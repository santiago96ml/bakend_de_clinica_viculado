require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const { rateLimit } = require('express-rate-limit');
const helmet = require('helmet');
const { z } = require('zod');
const { LRUCache } = require('lru-cache'); 

const app = express();
app.set('trust proxy', 1); // Necesario si estás detrás de un proxy (Nginx/EasyPanel)
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

// --- 1. CAPA DE SEGURIDAD: HEADERS & CORS ---
app.use(helmet());
app.use((req, res, next) => {
    // Evita caché en respuestas API para proteger datos médicos
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

app.use(cors({
    origin: [FRONTEND_URL, 'http://localhost:5173'],
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-owner-id'],
    credentials: true
}));

// Protección contra DoS (Payload grande)
app.use(express.json({ limit: '10kb' }));

// Rate Limiting (150 peticiones cada 15 min por IP)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    limit: 150, 
    message: { error: "Límite de peticiones excedido." }
});
app.use(limiter);

// --- 2. LOGGER SIEM-READY (Logs Inteligentes) ---
// Genera logs en JSON estructurado para herramientas de auditoría (Wazuh, Datadog)
const structuredLogger = (req, res, next) => {
    const start = Date.now();
    
    // Interceptamos el final de la respuesta para medir tiempo y capturar estado
    const oldSend = res.send;
    res.send = function(data) {
        const duration = Date.now() - start;
        res.send = oldSend; // Restauramos función original
        
        // Objeto de Log Estructurado
        const logEvent = {
            timestamp: new Date().toISOString(),
            level: res.statusCode >= 400 ? 'error' : 'info',
            event_type: 'http_request',
            environment: process.env.NODE_ENV || 'development',
            req: {
                method: req.method,
                url: req.originalUrl,
                ip: req.ip,
                user_agent: req.headers['user-agent'],
                user_id: req.user ? req.user.id : 'anonymous',
                role: req.userRole || 'unknown' // Capturado del middleware RBAC
            },
            res: {
                status_code: res.statusCode,
                duration_ms: duration
            }
        };

        // En producción, esto se enviaría a un colector de logs.
        console.log(JSON.stringify(logEvent));
        
        return res.send(data);
    };
    next();
};

app.use(structuredLogger);

// --- 3. GESTIÓN DE MEMORIA SEGURA (Caché LRU) ---
const credentialCache = new LRUCache({
    max: 500, // Máximo 500 conexiones en memoria RAM
    ttl: 1000 * 60 * 5, // 5 minutos de vida
    updateAgeOnGet: false,
});

// --- 5. MIDDLEWARE MULTI-TENANT (Conexión Dinámica) ---
const dynamicDbMiddleware = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    // Header especial para cuando el Staff accede a la clínica del Dueño
    const targetOwnerId = req.headers['x-owner-id']; 

    if (!token) return res.status(401).json({ error: 'Token requerido' });

    try {
        const { data: { user }, error: authError } = await masterClient.auth.getUser(token);

        // CORRECCIÓN: Bypass de Autenticación por Email No Verificado
        if (authError || !user || !user.email_confirmed_at) {
            return res.status(403).json({ error: 'Token inválido o email no verificado.' });
        }

        req.user = user;
        
        // Determinar a qué clínica conectar:
        // Si hay targetOwnerId, es un Staff entrando a la clínica de un jefe.
        // Si no, es el propio dueño entrando a su clínica.
        const clinicOwnerId = targetOwnerId || user.id;

        let clinicConfig = credentialCache.get(clinicOwnerId);
        
        if (!clinicConfig) {
            const { data, error: dbError } = await masterClient
                .from('web_clinica')
                .select('SUPABASE_URL, SUPABASE_SERVICE_KEY')
                .eq('ID_USER', clinicOwnerId)
                .single();

            if (dbError || !data) {
                return res.status(404).json({ error: 'Clínica no encontrada.' });
            }

            clinicConfig = {
                url: data.SUPABASE_URL,
                key: data.SUPABASE_SERVICE_KEY,
            };
            credentialCache.set(clinicOwnerId, clinicConfig);
        }

        req.clinicClient = createClient(clinicConfig.url, clinicConfig.key, {
            auth: { autoRefreshToken: false, persistSession: false }
        });

        // Verificación de Pertenencia (Seguridad Staff)
        if (user.id !== clinicOwnerId) {
            const { data: staffMember, error: staffError } = await req.clinicClient
                .from('perfil_staff')
                .select('id, rol')
                .eq('email', user.email)
                .single();

            if (staffError || !staffMember) {
                // El logger capturará este 403 alertando posible intrusión
                return res.status(403).json({ error: 'No tienes permisos de Staff en esta clínica.' });
            }
            req.userRole = staffMember.rol; 
        } else {
            req.userRole = 'admin'; // El dueño es Admin Supremo
        }

        next();

    } catch (err) {
        console.error("🔥 Error Middleware:", err.message);
        res.status(500).json({ error: 'Error de conexión.' });
    }
};

// --- MIDDLEWARE RBAC (Control de Roles) ---
const requireRole = (allowedRoles) => async (req, res, next) => {
    try {
        let rol = req.userRole;
        // Si no se resolvió antes (ej. caché de conexión), verificamos de nuevo
        if (!rol) {
             const { data: staff } = await req.clinicClient
                .from('perfil_staff')
                .select('rol')
                .eq('email', req.user.email)
                .single();
             rol = staff ? staff.rol : 'admin'; 
             req.userRole = rol; // Actualizamos para el logger
        }

        if (!allowedRoles.includes(rol)) {
            return res.status(403).json({ error: 'Permisos insuficientes.' });
        }
        next();
    } catch (e) {
        res.status(500).json({ error: 'Error verificando permisos.' });
    }
};

// --- ESQUEMAS ZOD (Validación Estricta) ---
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

const queryCitasSchema = z.object({
    start: z.string().datetime().optional(),
    end: z.string().datetime().optional()
});

const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
    }
};

// --- RUTAS DE API ---
const STAFF_ROLES = ['admin', 'secretaria', 'doctor'];
const ADMIN_ROLES = ['admin', 'secretaria']; // Doctores excluidos de acciones destructivas

// GET Data Inicial
app.get('/api/initial-data', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        const [docs, clients] = await Promise.all([
            req.clinicClient.from('doctores').select('*').eq('activo', true),
            req.clinicClient.from('clientes').select('*').eq('activo', true)
        ]);
        res.json({ doctores: docs.data, clientes: clients.data });
    } catch (e) { res.status(500).json({ error: 'Error obteniendo datos.' }); }
});

// GET Citas (Validado + Protegido)
app.get('/api/citas', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        const { start, end } = queryCitasSchema.parse(req.query);
        let query = req.clinicClient.from('citas')
            .select(`*, cliente:clientes(id, nombre, telefono, dni), doctor:doctores(id, nombre, color)`)
            .order('fecha_hora', { ascending: true });

        if (start && end) query = query.gte('fecha_hora', start).lte('fecha_hora', end);
        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (e) { 
        if (e instanceof z.ZodError) return res.status(400).json({ error: 'Fechas inválidas' });
        res.status(500).json({ error: 'Error cargando citas.' }); 
    }
});

// POST Citas (Race Condition Fix + Sanitización eliminada en entrada)
app.post('/api/citas', dynamicDbMiddleware, requireRole(STAFF_ROLES), validate(citaSchema), async (req, res) => {
    try {
        const body = req.body;
        // Chequeo de Concurrencia (Doble reserva)
        const { data: existing } = await req.clinicClient.from('citas')
            .select('id').eq('doctor_id', body.doctor_id).eq('fecha_hora', body.fecha_hora).neq('estado', 'cancelada').single();

        if (existing) return res.status(409).json({ error: "Horario ocupado." });

        let clienteId = body.cliente_id;
        if (!clienteId && body.new_client_name) {
            // CORRECCIÓN: Se eliminó sanitizeInput para no corromper datos
            const safeName = body.new_client_name;
            const { data: newClient, error: cErr } = await req.clinicClient.from('clientes')
                .insert({
                    nombre: safeName,
                    dni: body.new_client_dni || '', 
                    telefono: body.new_client_telefono || '',
                    activo: true, solicitud_de_secretaría: false 
                }).select().single();
            if (cErr) throw cErr;
            clienteId = newClient.id;
        }

        const { data, error } = await req.clinicClient.from('citas').insert({
            doctor_id: body.doctor_id, cliente_id: clienteId, fecha_hora: body.fecha_hora,
            duracion_minutos: body.duracion_minutos, estado: body.estado,
            descripcion: body.descripcion, timezone: body.timezone
        }).select().single();

        if (error) {
            if (error.code === '23505') return res.status(409).json({ error: "Horario ocupado (DB)." });
            throw error;
        }
        res.status(201).json({ ...data, new_client_id: clienteId });
    } catch (e) { res.status(400).json({ error: 'Error al crear la cita.' }); }
});

// PATCH Citas (Mass Assignment Fix)
app.patch('/api/citas/:id', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        const allowedSchema = z.object({
            estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']).optional(),
            descripcion: z.string().optional(),
            duracion_minutos: z.number().min(5).max(240).optional(),
            fecha_hora: z.string().datetime().optional()
        });
        const safeData = allowedSchema.parse(req.body);
        // CORRECCIÓN: Se eliminó sanitización redundante que corrompía datos

        const { data, error } = await req.clinicClient.from('citas').update(safeData).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json(data);
    } catch (e) { 
        if (e instanceof z.ZodError) return res.status(400).json({ error: 'Datos inválidos' });
        res.status(500).json({ error: 'Error actualizando.' }); 
    }
});

// DELETE Citas (Solo Admin)
app.delete('/api/citas/:id', dynamicDbMiddleware, requireRole(ADMIN_ROLES), async (req, res) => {
    try {
        const { error } = await req.clinicClient.from('citas').delete().eq('id', req.params.id);
        if (error) throw error;
        res.status(204).send();
    } catch (e) { res.status(500).json({ error: 'Error eliminando.' }); }
});

// PATCH Clientes
app.patch('/api/clientes/:id', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        const clientUpdateSchema = z.object({
            activo: z.boolean().optional(), solicitud_de_secretaria: z.boolean().optional(),
            nombre: z.string().min(2).optional(), telefono: z.string().optional(), dni: z.string().optional()
        });
        const safeData = clientUpdateSchema.parse(req.body);
        // CORRECCIÓN: Se eliminó el bucle de sanitización que agregaba comillas

        const { data, error } = await req.clinicClient.from('clientes').update(safeData).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error actualizando cliente.' }); }
});

// FILES: Generar URL (CORRECCIÓN CRÍTICA: Anti-Spoofing en Descarga)
app.post('/api/files/generate-upload-url', dynamicDbMiddleware, async (req, res) => {
    try {
        const { fileName, clienteId } = req.body;
        if(!fileName || !clienteId) return res.status(400).json({error: "Datos inválidos"});

        const safeFileName = fileName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const safeClientId = String(clienteId).replace(/[^0-9]/g, '');
        const filePath = `${safeClientId}/${Date.now()}_${safeFileName}`;
        
        // 🔥 CRÍTICO: download: true fuerza 'Content-Disposition: attachment'.
        // Impide que un HTML/SVG malicioso se ejecute en el navegador.
        const { data, error } = await req.clinicClient.storage.from('adjuntos') 
            .createSignedUploadUrl(filePath, 60 * 10, { download: true });

        if (error) throw error;
        res.json({ signedUrl: data.signedUrl, path: data.path });
    } catch (e) { res.status(500).json({ error: 'Error generando URL.' }); }
});

// FILES: Confirmar Subida (Validación de Integridad)
app.post('/api/files/confirm-upload', dynamicDbMiddleware, async (req, res) => {
    try {
        const { clienteId, storagePath, fileName, fileType, fileSizeKB } = req.body;
        
        // CORRECCIÓN: Evasión de Filtro (Double Extension Attack)
        const dangerousExtensions = ['.php', '.exe', '.sh', '.js', '.bat'];
        if (dangerousExtensions.some(ext => fileName.toLowerCase().includes(ext + '.'))) {
             return res.status(400).json({ error: 'Nombre de archivo sospechoso.' });
        }

        // Verificación de extensión vs MIME Type
        const extension = fileName.split('.').pop().toLowerCase();
        const mimeMap = {
            'pdf': ['application/pdf'], 'png': ['image/png'],
            'jpg': ['image/jpeg', 'image/jpg'], 'jpeg': ['image/jpeg', 'image/jpg'],
            'doc': ['application/msword'], 'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            'txt': ['text/plain']
        };

        if (mimeMap[extension]) {
            if (!mimeMap[extension].some(mime => fileType.includes(mime))) {
                 return res.status(400).json({ error: 'Discrepancia de tipo de archivo (Posible Spoofing).' });
            }
        }
        
        const { data, error } = await req.clinicClient.from('archivos_adjuntos').insert({
            cliente_id: clienteId, storage_path: storagePath, file_name: fileName,
            file_type: fileType, file_size_kb: fileSizeKB
        }).select().single();

        if (error) throw error;
        res.status(201).json(data);
    } catch (e) { res.status(500).json({ error: 'Error registrando archivo.' }); }
});

// GET Archivos (Protegido)
app.get('/api/files/:clienteId', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        const { data, error } = await req.clinicClient.from('archivos_adjuntos')
            .select('*').eq('cliente_id', req.params.clienteId).order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error obteniendo archivos.' }); }
});

app.get('/api/chat-history/:telefono', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        const phone = req.params.telefono.replace(/\D/g, ''); 
        if (!phone) return res.json([]);
        const { data, error } = await req.clinicClient.from('n8n_chat_histories')
            .select('*').ilike('session_id', `%${phone}%`).order('id', { ascending: true });
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error cargando chat.' }); }
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Satélite SECURE V5 (SIEM-Ready) Operativo en puerto ${PORT}`));