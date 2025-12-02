require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const { rateLimit } = require('express-rate-limit');
const helmet = require('helmet');
const { z } = require('zod');
const { LRUCache } = require('lru-cache'); // REQUIERE: npm install lru-cache

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3002;

// Variables de entorno
const MASTER_URL = process.env.MASTER_SUPABASE_URL;
const MASTER_KEY = process.env.MASTER_SUPABASE_SERVICE_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || "https://tu-dominio-frontend.com";

if (!MASTER_URL || !MASTER_KEY) {
    console.error("❌ ERROR CRÍTICO: Faltan credenciales MASTER en .env");
    process.exit(1);
}

const masterClient = createClient(MASTER_URL, MASTER_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
});

// --- 1. SEGURIDAD: HEADERS & CORS ---
app.use(helmet());
// Evitar cacheo de respuestas sensibles (Fase 2 Fix)
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

app.use(cors({
    origin: [FRONTEND_URL, 'http://localhost:5173'],
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// DoS Protection: Límite estricto de body
app.use(express.json({ limit: '10kb' }));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    limit: 150, 
    message: { error: "Límite de peticiones excedido." }
});
app.use(limiter);

// --- 2. GESTIÓN DE MEMORIA SEGURA (Fase 2 Fix) ---
// Reemplazamos el Map nativo por LRU Cache para evitar fugas de memoria
const credentialCache = new LRUCache({
    max: 500, // Máximo 500 conexiones en memoria
    ttl: 1000 * 60 * 5, // 5 minutos de vida
    updateAgeOnGet: false,
});

// --- 3. SANITIZACIÓN (CSV/Formula Injection Fix) ---
const sanitizeInput = (text) => {
    if (typeof text !== 'string') return text;
    // Si empieza con caracteres peligrosos para Excel/CSV, neutralizarlos
    if (/^[=+\-@]/.test(text)) {
        return `'${text}`; 
    }
    return text;
};

// --- 4. MIDDLEWARE MULTI-TENANT ---
const dynamicDbMiddleware = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token requerido' });

    try {
        const { data: { user }, error: authError } = await masterClient.auth.getUser(token);

        if (authError || !user) {
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }

        req.user = user;

        let clinicConfig = credentialCache.get(user.id);
        
        if (!clinicConfig) {
            const { data, error: dbError } = await masterClient
                .from('web_clinica')
                .select('SUPABASE_URL, SUPABASE_SERVICE_KEY')
                .eq('ID_USER', user.id)
                .single();

            if (dbError || !data) {
                return res.status(404).json({ error: 'Configuración de clínica no encontrada.' });
            }

            clinicConfig = {
                url: data.SUPABASE_URL,
                key: data.SUPABASE_SERVICE_KEY,
            };
            credentialCache.set(user.id, clinicConfig);
        }

        req.clinicClient = createClient(clinicConfig.url, clinicConfig.key, {
            auth: { autoRefreshToken: false, persistSession: false }
        });

        next();

    } catch (err) {
        console.error("🔥 Error Middleware:", err);
        res.status(500).json({ error: 'Error de conexión.' });
    }
};

// --- 5. ESQUEMAS ZOD ---
const citaSchema = z.object({
    doctor_id: z.number(),
    cliente_id: z.number().optional().nullable(),
    fecha_hora: z.string().datetime(), 
    duracion_minutos: z.number().min(5).max(240),
    estado: z.string(),
    descripcion: z.string().optional().nullable(),
    timezone: z.string().optional(),
    new_client_name: z.string().min(2).optional(),
    new_client_dni: z.string().optional(),
    new_client_telefono: z.string().optional()
});

const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
    }
};

// --- RUTAS ---

app.get('/api/initial-data', dynamicDbMiddleware, async (req, res) => {
    try {
        const [docs, clients] = await Promise.all([
            req.clinicClient.from('doctores').select('*').eq('activo', true),
            req.clinicClient.from('clientes').select('*').eq('activo', true)
        ]);
        res.json({ doctores: docs.data, clientes: clients.data });
    } catch (e) { 
        res.status(500).json({ error: 'Error obteniendo datos.' }); 
    }
});

app.get('/api/citas', dynamicDbMiddleware, async (req, res) => {
    const { start, end } = req.query;
    try {
        let query = req.clinicClient.from('citas')
            .select(`*, cliente:clientes(id, nombre, telefono, dni), doctor:doctores(id, nombre, color)`)
            .order('fecha_hora', { ascending: true });

        if (start && end) query = query.gte('fecha_hora', start).lte('fecha_hora', end);
        
        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (e) { 
        res.status(500).json({ error: 'Error cargando citas.' }); 
    }
});

// POST Citas: Con Race Condition Check + Sanitización
app.post('/api/citas', dynamicDbMiddleware, validate(citaSchema), async (req, res) => {
    try {
        const body = req.body;
        
        // 1. Race Condition Fix (Verificación preventiva en Backend)
        const { data: existing } = await req.clinicClient.from('citas')
            .select('id')
            .eq('doctor_id', body.doctor_id)
            .eq('fecha_hora', body.fecha_hora)
            .neq('estado', 'cancelada') 
            .single();

        if (existing) {
            return res.status(409).json({ error: "El horario ya está ocupado." });
        }

        let clienteId = body.cliente_id;

        if (!clienteId && body.new_client_name) {
            // CSV Injection Fix: Sanitizar nombre
            const safeName = sanitizeInput(body.new_client_name);
            
            const { data: newClient, error: cErr } = await req.clinicClient.from('clientes')
                .insert({
                    nombre: safeName,
                    dni: sanitizeInput(body.new_client_dni || ''),
                    telefono: sanitizeInput(body.new_client_telefono || ''),
                    activo: true,
                    solicitud_de_secretaría: false 
                }).select().single();
            
            if (cErr) throw cErr;
            clienteId = newClient.id;
        }

        const { data, error } = await req.clinicClient.from('citas').insert({
            doctor_id: body.doctor_id,
            cliente_id: clienteId,
            fecha_hora: body.fecha_hora,
            duracion_minutos: body.duracion_minutos,
            estado: body.estado,
            descripcion: sanitizeInput(body.descripcion), // Sanitizar descripción
            timezone: body.timezone
        }).select().single();

        if (error) {
            // Manejo de error si la DB rechaza por índice único (Doble seguridad)
            if (error.code === '23505') return res.status(409).json({ error: "Horario ocupado (DB)." });
            throw error;
        }
        res.status(201).json({ ...data, new_client_id: clienteId });
    } catch (e) { 
        console.error(e);
        res.status(400).json({ error: 'Error al crear la cita.' }); 
    }
});

// PATCH Citas: Mass Assignment Fix (Whitelist)
app.patch('/api/citas/:id', dynamicDbMiddleware, async (req, res) => {
    try {
        // Definir qué campos se pueden actualizar
        const allowedSchema = z.object({
            estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']).optional(),
            descripcion: z.string().optional(),
            duracion_minutos: z.number().min(5).max(240).optional(),
            fecha_hora: z.string().datetime().optional()
        });

        // Filtrar y validar el body (Mass Assignment Fix)
        const safeData = allowedSchema.parse(req.body);

        if (safeData.descripcion) {
            safeData.descripcion = sanitizeInput(safeData.descripcion);
        }

        const { data, error } = await req.clinicClient.from('citas')
            .update(safeData) // Usamos safeData, NO req.body directo
            .eq('id', req.params.id).select().single();
            
        if (error) throw error;
        res.json(data);
    } catch (e) { 
        if (e instanceof z.ZodError) return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
        res.status(500).json({ error: 'Error actualizando cita.' }); 
    }
});

app.delete('/api/citas/:id', dynamicDbMiddleware, async (req, res) => {
    try {
        const { error } = await req.clinicClient.from('citas').delete().eq('id', req.params.id);
        if (error) throw error;
        res.status(204).send();
    } catch (e) { res.status(500).json({ error: 'Error eliminando cita.' }); }
});

// PATCH Clientes: Mass Assignment Fix + CSV Fix
app.patch('/api/clientes/:id', dynamicDbMiddleware, async (req, res) => {
    try {
        const clientUpdateSchema = z.object({
            activo: z.boolean().optional(),
            solicitud_de_secretaria: z.boolean().optional(),
            nombre: z.string().min(2).optional(),
            telefono: z.string().optional(),
            dni: z.string().optional()
        });

        const safeData = clientUpdateSchema.parse(req.body);
        
        // Sanitizar strings si existen
        ['nombre', 'telefono', 'dni'].forEach(field => {
            if (safeData[field]) safeData[field] = sanitizeInput(safeData[field]);
        });

        const { data, error } = await req.clinicClient.from('clientes')
            .update(safeData)
            .eq('id', req.params.id).select().single();
        
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error actualizando cliente.' }); }
});

// FILES: Path Traversal Fix (De Fase 1)
app.post('/api/files/generate-upload-url', dynamicDbMiddleware, async (req, res) => {
    try {
        const { fileName, clienteId } = req.body;
        
        if(!fileName || !clienteId || typeof fileName !== 'string') {
            return res.status(400).json({error: "Datos inválidos"});
        }

        // Sanitización estricta de Path Traversal
        const safeFileName = fileName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const safeClientId = String(clienteId).replace(/[^0-9]/g, '');

        const filePath = `${safeClientId}/${Date.now()}_${safeFileName}`;
        
        const { data, error } = await req.clinicClient.storage
            .from('adjuntos') 
            .createSignedUploadUrl(filePath, 60 * 10);

        if (error) throw error;
        res.json({ signedUrl: data.signedUrl, path: data.path });
    } catch (e) { 
        res.status(500).json({ error: 'Error generando URL.' }); 
    }
});

// El resto de rutas de archivos y chat se mantienen igual que en Fase 1, 
// ya que son lecturas simples y están protegidas por el middleware.
app.post('/api/files/confirm-upload', dynamicDbMiddleware, async (req, res) => {
    try {
        const { clienteId, storagePath, fileName, fileType, fileSizeKB } = req.body;
        const { data, error } = await req.clinicClient.from('archivos_adjuntos').insert({
            cliente_id: clienteId,
            storage_path: storagePath,
            file_name: fileName,
            file_type: fileType,
            file_size_kb: fileSizeKB
        }).select().single();
        if (error) throw error;
        res.status(201).json(data);
    } catch (e) { res.status(500).json({ error: 'Error registrando archivo.' }); }
});

app.get('/api/files/:clienteId', dynamicDbMiddleware, async (req, res) => {
    try {
        const { data, error } = await req.clinicClient.from('archivos_adjuntos')
            .select('*').eq('cliente_id', req.params.clienteId).order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error obteniendo archivos.' }); }
});

app.get('/api/chat-history/:telefono', dynamicDbMiddleware, async (req, res) => {
    try {
        const phone = req.params.telefono.replace(/\D/g, ''); 
        if (!phone) return res.json([]);
        const { data, error } = await req.clinicClient.from('n8n_chat_histories')
            .select('*').ilike('session_id', `%${phone}%`).order('id', { ascending: true });
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error cargando chat.' }); }
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Satélite SECURE+ Operativo en puerto ${PORT}`));