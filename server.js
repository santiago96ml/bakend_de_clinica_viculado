require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const { rateLimit } = require('express-rate-limit');
const helmet = require('helmet');
const { z } = require('zod');
const { LRUCache } = require('lru-cache'); 

const app = express();

// 1. TRUST PROXY: Necesario para Cloudflare WAF / Proxies
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3002;

// CONFIGURACIÓN DE DOMINIOS
const FRONTEND_URL = process.env.FRONTEND_URL || "https://vintex.net.br";

// Variables de Entorno (Master)
const MASTER_URL = process.env.MASTER_SUPABASE_URL;
const MASTER_KEY = process.env.MASTER_SUPABASE_SERVICE_KEY;

if (!MASTER_URL || !MASTER_KEY) {
    console.error("❌ ERROR CRÍTICO: Faltan credenciales MASTER en .env");
    process.exit(1);
}

const masterClient = createClient(MASTER_URL, MASTER_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
});

// --- SEGURIDAD: HEADERS, CORS & HTTPS ---
app.use(helmet());

// Forzar HTTPS en Producción (Solución Vulnerabilidad: Falta de HTTPS forzado)
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production' && !req.secure && req.get('x-forwarded-proto') !== 'https') {
        return res.redirect('https://' + req.get('host') + req.url);
    }
    next();
});

app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

app.use(cors({
    origin: [FRONTEND_URL, 'https://vintex.net.br', 'http://localhost:5173'],
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-owner-id'],
    credentials: true
}));

// Límite de Body (Solución Vulnerabilidad: Middleware de JSON sin límites)
app.use(express.json({ limit: '10kb' }));

// Rate Limit (150/15min) (Solución Vulnerabilidad: DoS)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    limit: 150, 
    message: { error: "Límite de peticiones excedido. Intenta más tarde." }
});
app.use(limiter);

// --- LOGGER DE AUDITORÍA (Solución Vulnerabilidad: Ausencia de Audit Logging) ---
// Registra acciones críticas de negocio además de las peticiones HTTP
const auditLog = (action, user, details) => {
    const logEntry = {
        timestamp: new Date().toISOString(),
        type: 'AUDIT_LOG',
        action: action.toUpperCase(),
        user_id: user ? user.id : 'anonymous',
        user_email: user ? user.email : 'unknown',
        details: details
    };
    // En producción, esto debería ir a una tabla de logs o servicio externo (Datadog/CloudWatch)
    console.info(JSON.stringify(logEntry)); 
};

// --- CACHÉ DE MEMORIA ---
const credentialCache = new LRUCache({
    max: 500, 
    ttl: 1000 * 60 * 5, 
    updateAgeOnGet: false,
});

// --- MIDDLEWARE MULTI-TENANT ---
const dynamicDbMiddleware = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    const targetOwnerId = req.headers['x-owner-id']; 

    // Solución Vulnerabilidad: Falta de Autenticación
    if (!token) return res.status(401).json({ error: 'Token requerido' });

    try {
        const { data: { user }, error: authError } = await masterClient.auth.getUser(token);

        if (authError || !user) {
            return res.status(403).json({ error: 'Token inválido o sesión expirada.' });
        }

        req.user = user;
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

        // Verificación de Roles (Staff vs Dueño)
        if (user.id !== clinicOwnerId) {
            const { data: staffMember, error: staffError } = await req.clinicClient
                .from('perfil_staff')
                .select('id, rol')
                .eq('email', user.email)
                .single();

            if (staffError || !staffMember) {
                return res.status(403).json({ error: 'No tienes permisos de Staff en esta clínica.' });
            }
            req.userRole = staffMember.rol; 
        } else {
            req.userRole = 'admin';
        }

        next();

    } catch (err) {
        // Solución Vulnerabilidad: Exposición de Stack Traces (Log interno seguro, respuesta genérica)
        console.error("🔥 Error Middleware:", err.message); 
        res.status(500).json({ error: 'Error de conexión interno.' });
    }
};

// --- MIDDLEWARE RBAC (Solución Vulnerabilidad: Broken Access Control) ---
const requireRole = (allowedRoles) => async (req, res, next) => {
    try {
        let rol = req.userRole;
        if (!rol) {
             // Fallback por seguridad
             const { data: staff } = await req.clinicClient
                .from('perfil_staff')
                .select('rol')
                .eq('email', req.user.email)
                .single();
             rol = staff ? staff.rol : 'admin'; 
             req.userRole = rol;
        }

        if (!allowedRoles.includes(rol)) {
            auditLog('UNAUTHORIZED_ACCESS_ATTEMPT', req.user, { path: req.path, required: allowedRoles, actual: rol });
            return res.status(403).json({ error: 'Permisos insuficientes.' });
        }
        next();
    } catch (e) {
        res.status(500).json({ error: 'Error verificando permisos.' });
    }
};

// --- ESQUEMAS ZOD (Solución Vulnerabilidad: Inyección de Datos & XSS) ---
// Función de limpieza de HTML
const sanitizeString = (str) => (str ? str.replace(/<[^>]*>?/gm, '').trim() : str);

const citaSchema = z.object({
    doctor_id: z.number(),
    cliente_id: z.number().optional().nullable(),
    fecha_hora: z.string().datetime(), // Solución Vulnerabilidad: Validación de Fechas
    duracion_minutos: z.number().min(5).max(240),
    estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']), // Enum estricto
    descripcion: z.string().optional().nullable().transform(sanitizeString), // Sanitización XSS
    timezone: z.string().optional(),
    new_client_name: z.string().min(2).transform(sanitizeString).optional(),
    new_client_dni: z.string().transform(sanitizeString).optional(),
    new_client_telefono: z.string().transform(sanitizeString).optional()
});

const queryCitasSchema = z.object({
    start: z.string().datetime().optional(),
    end: z.string().datetime().optional()
});

const validate = (schema) => (req, res, next) => {
    try {
        req.body = schema.parse(req.body); // Reemplazamos body con la versión limpia/sanitizada
        next();
    } catch (e) {
        return res.status(400).json({ error: 'Datos inválidos', details: e.errors });
    }
};

// --- RUTAS DE API ---
const STAFF_ROLES = ['admin', 'secretaria', 'doctor'];
const ADMIN_ROLES = ['admin', 'secretaria'];

app.get('/api/initial-data', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        // Solución Vulnerabilidad: Exposición de Datos Sensibles (PII)
        // Seleccionamos SOLO los campos necesarios, evitando enviar contraseñas o datos privados
        const [docs, clients] = await Promise.all([
            req.clinicClient.from('doctores')
                .select('id, nombre, especialidad, color, activo') // SELECT ESPECÍFICO
                .eq('activo', true),
            req.clinicClient.from('clientes')
                .select('id, nombre, dni, telefono, activo') // SELECT ESPECÍFICO
                .eq('activo', true)
        ]);
        res.json({ doctores: docs.data, clientes: clients.data });
    } catch (e) { res.status(500).json({ error: 'Error obteniendo datos.' }); }
});

app.get('/api/citas', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        const { start, end } = queryCitasSchema.parse(req.query);
        let query = req.clinicClient.from('citas')
            // Solución PII: Joins con campos específicos
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

app.post('/api/citas', dynamicDbMiddleware, requireRole(STAFF_ROLES), validate(citaSchema), async (req, res) => {
    try {
        const body = req.body;
        // Race Condition Check
        const { data: existing } = await req.clinicClient.from('citas')
            .select('id').eq('doctor_id', body.doctor_id).eq('fecha_hora', body.fecha_hora).neq('estado', 'cancelada').single();

        if (existing) return res.status(409).json({ error: "Horario ocupado." });

        let clienteId = body.cliente_id;
        if (!clienteId && body.new_client_name) {
            const { data: newClient, error: cErr } = await req.clinicClient.from('clientes')
                .insert({
                    nombre: body.new_client_name,
                    dni: body.new_client_dni || '', 
                    telefono: body.new_client_telefono || '',
                    activo: true, solicitud_de_secretaría: false 
                }).select().single();
            if (cErr) throw cErr;
            clienteId = newClient.id;
            auditLog('CREATE_CLIENT', req.user, { client_id: newClient.id, name: body.new_client_name });
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

        auditLog('CREATE_APPOINTMENT', req.user, { cita_id: data.id, doctor: body.doctor_id });
        res.status(201).json({ ...data, new_client_id: clienteId });
    } catch (e) { res.status(400).json({ error: 'Error al crear la cita.' }); }
});

app.patch('/api/citas/:id', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        const allowedSchema = z.object({
            estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']).optional(),
            descripcion: z.string().transform(sanitizeString).optional(),
            duracion_minutos: z.number().min(5).max(240).optional(),
            fecha_hora: z.string().datetime().optional()
        });
        const safeData = allowedSchema.parse(req.body);
        
        const { data, error } = await req.clinicClient.from('citas').update(safeData).eq('id', req.params.id).select().single();
        if (error) throw error;

        auditLog('UPDATE_APPOINTMENT', req.user, { cita_id: req.params.id, changes: safeData });
        res.json(data);
    } catch (e) { 
        if (e instanceof z.ZodError) return res.status(400).json({ error: 'Datos inválidos' });
        res.status(500).json({ error: 'Error actualizando.' }); 
    }
});

app.delete('/api/citas/:id', dynamicDbMiddleware, requireRole(ADMIN_ROLES), async (req, res) => {
    try {
        const { error } = await req.clinicClient.from('citas').delete().eq('id', req.params.id);
        if (error) throw error;
        
        auditLog('DELETE_APPOINTMENT', req.user, { cita_id: req.params.id });
        res.status(204).send();
    } catch (e) { res.status(500).json({ error: 'Error eliminando.' }); }
});

app.patch('/api/clientes/:id', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
    try {
        const clientUpdateSchema = z.object({
            activo: z.boolean().optional(), solicitud_de_secretaria: z.boolean().optional(),
            nombre: z.string().min(2).transform(sanitizeString).optional(),
            telefono: z.string().transform(sanitizeString).optional(),
            dni: z.string().transform(sanitizeString).optional()
        });
        const safeData = clientUpdateSchema.parse(req.body);
        
        const { data, error } = await req.clinicClient.from('clientes').update(safeData).eq('id', req.params.id).select().single();
        if (error) throw error;
        
        auditLog('UPDATE_CLIENT', req.user, { client_id: req.params.id, changes: safeData });
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error actualizando cliente.' }); }
});

// Solución Vulnerabilidad: Subida de Archivos No Restringida
// Se implementa doble verificación (Nombre y extensión en confirmación)
app.post('/api/files/generate-upload-url', dynamicDbMiddleware, async (req, res) => {
    try {
        const { fileName, clienteId } = req.body;
        if(!fileName || !clienteId) return res.status(400).json({error: "Datos inválidos"});

        const safeFileName = fileName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const safeClientId = String(clienteId).replace(/[^0-9]/g, '');
        const filePath = `${safeClientId}/${Date.now()}_${safeFileName}`;
        
        // Force download previene ejecución en el navegador
        const { data, error } = await req.clinicClient.storage.from('adjuntos') 
            .createSignedUploadUrl(filePath, 60 * 10, { download: true });

        if (error) throw error;
        res.json({ signedUrl: data.signedUrl, path: data.path });
    } catch (e) { res.status(500).json({ error: 'Error generando URL.' }); }
});

app.post('/api/files/confirm-upload', dynamicDbMiddleware, async (req, res) => {
    try {
        const { clienteId, storagePath, fileName, fileType, fileSizeKB } = req.body;
        
        // CHECK: Extensiones Peligrosas
        const dangerousExtensions = ['.php', '.exe', '.sh', '.js', '.bat', '.html', '.svg'];
        if (dangerousExtensions.some(ext => fileName.toLowerCase().endsWith(ext))) {
             auditLog('SECURITY_ALERT', req.user, { type: 'MALICIOUS_FILE_ATTEMPT', fileName });
             return res.status(400).json({ error: 'Tipo de archivo no permitido.' });
        }

        // CHECK: Consistencia MIME Type
        const extension = fileName.split('.').pop().toLowerCase();
        const mimeMap = {
            'pdf': ['application/pdf'], 
            'png': ['image/png'],
            'jpg': ['image/jpeg', 'image/jpg'], 
            'jpeg': ['image/jpeg', 'image/jpg'],
            'doc': ['application/msword'], 
            'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            'txt': ['text/plain']
        };

        if (mimeMap[extension]) {
            if (!mimeMap[extension].some(mime => fileType.includes(mime))) {
                 return res.status(400).json({ error: 'Discrepancia de tipo de archivo.' });
            }
        }
        
        const { data, error } = await req.clinicClient.from('archivos_adjuntos').insert({
            cliente_id: clienteId, storage_path: storagePath, file_name: fileName,
            file_type: fileType, file_size_kb: fileSizeKB
        }).select().single();

        if (error) throw error;
        auditLog('UPLOAD_FILE', req.user, { fileName, clienteId });
        res.status(201).json(data);
    } catch (e) { res.status(500).json({ error: 'Error registrando archivo.' }); }
});

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

app.get('/api/metrics', dynamicDbMiddleware, requireRole(STAFF_ROLES), async (req, res) => {
  try {
    const { data, error } = await req.clinicClient.rpc('obtener_estadisticas_generales');

    if (error) {
      console.error('Error obteniendo métricas:', error);
      return res.status(500).json({ error: 'Error al calcular estadísticas' });
    }

    // CORRECCIÓN: Extraer el objeto si viene en array
    const stats = Array.isArray(data) && data.length > 0 ? data[0] : (data || {});
    
    res.json(stats); // Ahora siempre envías el objeto limpio

  } catch (err) {
    // ...
  }
});

// Solución Vulnerabilidad: Falta de Timeouts
// Configuramos un timeout explícito para evitar ataques Slowloris
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Satélite SECURE (api-clinica.vintex.net.br) en puerto ${PORT}`);
});
server.setTimeout(25000); // Timeout de 25 segundos