require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const { rateLimit } = require('express-rate-limit');
const helmet = require('helmet');
const { z } = require('zod');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3002;

// Variables de entorno
const MASTER_URL = process.env.MASTER_SUPABASE_URL;
const MASTER_KEY = process.env.MASTER_SUPABASE_SERVICE_KEY;
// URL DEL FRONTEND (Asegúrate de poner la URL real)
const FRONTEND_URL = process.env.FRONTEND_URL || "https://tu-dominio-frontend.com";

if (!MASTER_URL || !MASTER_KEY) {
    console.error("❌ ERROR CRÍTICO: Faltan credenciales MASTER en .env");
    process.exit(1);
}

const masterClient = createClient(MASTER_URL, MASTER_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
});

// --- 1. SEGURIDAD ---
app.use(helmet());
app.use(cors({
    origin: [FRONTEND_URL, 'http://localhost:5173'],
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10kb' }));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    limit: 150, // Un poco más alto para el satélite que tiene tráfico de uso intenso
    message: { error: "Límite de peticiones excedido." }
});
app.use(limiter);

// --- 2. CACHÉ CREDENCIALES ---
const credentialCache = new Map(); 
const CACHE_TTL = 1000 * 60 * 5; 

// --- 3. MIDDLEWARE MULTI-TENANT ---
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
        
        if (!clinicConfig || (Date.now() - clinicConfig.timestamp > CACHE_TTL)) {
            // console.log(`🔄 Resolviendo conexión para: ${user.id}`); // Debug seguro
            
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
                timestamp: Date.now()
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

// --- 4. ESQUEMAS ZOD ---
const citaSchema = z.object({
    doctor_id: z.number(),
    cliente_id: z.number().optional().nullable(),
    fecha_hora: z.string().datetime(), // Valida formato ISO
    duracion_minutos: z.number().min(5).max(240),
    estado: z.string(),
    descripcion: z.string().optional().nullable(),
    timezone: z.string().optional(),
    // Para paciente nuevo
    new_client_name: z.string().min(2).optional(),
    new_client_dni: z.string().optional(),
    new_client_telefono: z.string().optional()
});

const clienteUpdateSchema = z.object({
    activo: z.boolean().optional(),
    solicitud_de_secretaria: z.boolean().optional()
});

// Middleware Validación
const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
    }
};

// --- RUTAS ---

// DATA INICIAL
app.get('/api/initial-data', dynamicDbMiddleware, async (req, res) => {
    try {
        const [docs, clients] = await Promise.all([
            req.clinicClient.from('doctores').select('*').eq('activo', true),
            req.clinicClient.from('clientes').select('*').eq('activo', true)
        ]);
        res.json({ doctores: docs.data, clientes: clients.data });
    } catch (e) { 
        console.error(e);
        res.status(500).json({ error: 'Error obteniendo datos iniciales.' }); 
    }
});

// CITAS
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
        console.error(e);
        res.status(500).json({ error: 'Error cargando citas.' }); 
    }
});

app.post('/api/citas', dynamicDbMiddleware, validate(citaSchema), async (req, res) => {
    try {
        const body = req.body;
        let clienteId = body.cliente_id;

        if (!clienteId && body.new_client_name) {
            // Crear cliente con validación básica implícita por el backend anterior
            const { data: newClient, error: cErr } = await req.clinicClient.from('clientes')
                .insert({
                    nombre: body.new_client_name,
                    dni: body.new_client_dni || '',
                    telefono: body.new_client_telefono || '',
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
            descripcion: body.descripcion,
            timezone: body.timezone
        }).select().single();

        if (error) throw error;
        res.status(201).json({ ...data, new_client_id: clienteId });
    } catch (e) { 
        console.error(e);
        res.status(400).json({ error: 'Error al crear la cita.' }); 
    }
});

app.patch('/api/citas/:id', dynamicDbMiddleware, async (req, res) => {
    // Nota: Deberías hacer un schema para updatePartial si quieres ser estricto
    try {
        const { data, error } = await req.clinicClient.from('citas')
            .update(req.body).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error actualizando cita.' }); }
});

app.delete('/api/citas/:id', dynamicDbMiddleware, async (req, res) => {
    try {
        const { error } = await req.clinicClient.from('citas').delete().eq('id', req.params.id);
        if (error) throw error;
        res.status(204).send();
    } catch (e) { res.status(500).json({ error: 'Error eliminando cita.' }); }
});

// CLIENTES
app.patch('/api/clientes/:id', dynamicDbMiddleware, validate(clienteUpdateSchema), async (req, res) => {
    try {
        const { activo, solicitud_de_secretaria } = req.body;
        const updates = {};
        if (typeof activo === 'boolean') updates.activo = activo;
        if (typeof solicitud_de_secretaria === 'boolean') updates.solicitud_de_secretaría = solicitud_de_secretaria;

        const { data, error } = await req.clinicClient.from('clientes')
            .update(updates).eq('id', req.params.id).select().single();
        
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error actualizando cliente.' }); }
});

// FILES & CHAT (Sin cambios mayores de lógica, solo protegidos por middleware)
app.post('/api/files/generate-upload-url', dynamicDbMiddleware, async (req, res) => {
    try {
        const { fileName, clienteId } = req.body;
        // Validación básica manual (Zod sería mejor)
        if(!fileName || !clienteId) return res.status(400).json({error: "Faltan datos"});

        const filePath = `${clienteId}/${Date.now()}_${fileName.replace(/\s+/g, '_')}`;
        const { data, error } = await req.clinicClient.storage
            .from('adjuntos') 
            .createSignedUploadUrl(filePath, 60 * 10);

        if (error) throw error;
        res.json({ signedUrl: data.signedUrl, path: data.path });
    } catch (e) { res.status(500).json({ error: 'Error de almacenamiento.' }); }
});

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
            .select('*')
            .ilike('session_id', `%${phone}%`)
            .order('id', { ascending: true });
            
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error cargando chat.' }); }
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Satélite SECURE Operativo en puerto ${PORT}`));