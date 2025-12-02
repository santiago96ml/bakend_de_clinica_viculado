require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const { rateLimit } = require('express-rate-limit');
const helmet = require('helmet');
const { z } = require('zod');
const { LRUCache } = require('lru-cache'); 

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
    allowedHeaders: ['Content-Type', 'Authorization', 'x-owner-id'], // Agregamos x-owner-id para staff
    credentials: true
}));

app.use(express.json({ limit: '10kb' })); // Previene DoS por payload grande

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    limit: 150, 
    message: { error: "Límite de peticiones excedido." }
});
app.use(limiter);

// --- 2. GESTIÓN DE MEMORIA SEGURA ---
const credentialCache = new LRUCache({
    max: 500, 
    ttl: 1000 * 60 * 5, 
    updateAgeOnGet: false,
});

// --- 3. SANITIZACIÓN (CSV Injection) ---
const sanitizeInput = (text) => {
    if (typeof text !== 'string') return text;
    if (/^[=+\-@]/.test(text)) {
        return `'${text}`; 
    }
    return text;
};

// --- 4. MIDDLEWARE MULTI-TENANT (CORREGIDO Lógica Staff) ---
const dynamicDbMiddleware = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    // Header opcional para cuando un Staff accede a la clínica de un Dueño
    const targetOwnerId = req.headers['x-owner-id']; 

    if (!token) return res.status(401).json({ error: 'Token requerido' });

    try {
        // 1. Validar Token en Master
        const { data: { user }, error: authError } = await masterClient.auth.getUser(token);

        if (authError || !user) {
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }

        req.user = user;

        // 2. Determinar el ID del Dueño de la Clínica a conectar
        // Si mandan x-owner-id, intentamos conectar a esa clínica (Caso Staff).
        // Si no, asumimos que el usuario logueado es el dueño (Caso Admin).
        const clinicOwnerId = targetOwnerId || user.id;

        // 3. Buscar Credenciales (con Caché)
        let clinicConfig = credentialCache.get(clinicOwnerId);
        
        if (!clinicConfig) {
            const { data, error: dbError } = await masterClient
                .from('web_clinica')
                .select('SUPABASE_URL, SUPABASE_SERVICE_KEY')
                .eq('ID_USER', clinicOwnerId) // Buscamos por el ID del dueño
                .single();

            if (dbError || !data) {
                return res.status(404).json({ error: 'Clínica no encontrada o no configurada.' });
            }

            clinicConfig = {
                url: data.SUPABASE_URL,
                key: data.SUPABASE_SERVICE_KEY,
            };
            credentialCache.set(clinicOwnerId, clinicConfig);
        }

        // 4. Conectar a la BD Satélite
        req.clinicClient = createClient(clinicConfig.url, clinicConfig.key, {
            auth: { autoRefreshToken: false, persistSession: false }
        });

        // 5. VERIFICACIÓN DE PERTENENCIA (Crucial para seguridad Staff)
        // Si el usuario logueado NO es el dueño, debemos verificar que sea Staff en esa BD
        if (user.id !== clinicOwnerId) {
            const { data: staffMember, error: staffError } = await req.clinicClient
                .from('perfil_staff')
                .select('id, rol')
                .eq('email', user.email) // Validamos por email
                .single();

            if (staffError || !staffMember) {
                console.warn(`[ACCESO ILEGAL] Usuario ${user.email} intentó acceder a clínica de ${clinicOwnerId}`);
                return res.status(403).json({ error: 'No tienes permisos de Staff en esta clínica.' });
            }
            // Opcional: inyectar el rol detectado para usarlo después
            req.userRole = staffMember.rol; 
        } else {
            req.userRole = 'admin'; // El dueño es admin supremo
        }

        next();

    } catch (err) {
        console.error("🔥 Error Middleware:", err);
        res.status(500).json({ error: 'Error de conexión.' });
    }
};

// --- MIDDLEWARE RBAC (Control de Roles) ---
const requireRole = (allowedRoles) => async (req, res, next) => {
    try {
        // Usamos el rol ya resuelto en dynamicDbMiddleware para ahorrar una consulta
        // Si no se resolvió (ej. es el dueño), volvemos a consultar o asumimos admin.
        let rol = req.userRole;

        if (!rol) {
             const { data: staff } = await req.clinicClient
                .from('perfil_staff')
                .select('rol')
                .eq('email', req.user.email)
                .single();
             rol = staff ? staff.rol : 'admin'; // Fallback a admin si es dueño
        }

        if (!allowedRoles.includes(rol)) {
            return res.status(403).json({ error: 'Permisos insuficientes.' });
        }
        next();
    } catch (e) {
        res.status(500).json({ error: 'Error verificando permisos.' });
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

// Validación para Query Params (GET /citas)
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

// --- RUTAS ---

const STAFF_ROLES = ['admin', 'secretaria', 'doctor'];
const ADMIN_ROLES = ['admin', 'secretaria'];

// GET Data Inicial - Protegido con RBAC
app.get('/api/initial-data', 
    dynamicDbMiddleware, 
    requireRole(STAFF_ROLES), 
    async (req, res) => {
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

// GET Citas - Protegido con RBAC + Validación Query Params
app.get('/api/citas', 
    dynamicDbMiddleware, 
    requireRole(STAFF_ROLES), 
    async (req, res) => {
    try {
        // Validación de inputs GET
        const { start, end } = queryCitasSchema.parse(req.query);
        
        let query = req.clinicClient.from('citas')
            .select(`*, cliente:clientes(id, nombre, telefono, dni), doctor:doctores(id, nombre, color)`)
            .order('fecha_hora', { ascending: true });

        if (start && end) query = query.gte('fecha_hora', start).lte('fecha_hora', end);
        
        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (e) { 
        if (e instanceof z.ZodError) return res.status(400).json({ error: 'Parámetros de fecha inválidos' });
        res.status(500).json({ error: 'Error cargando citas.' }); 
    }
});

// POST Citas
app.post('/api/citas', 
    dynamicDbMiddleware, 
    requireRole(STAFF_ROLES), 
    validate(citaSchema), 
    async (req, res) => {
    try {
        const body = req.body;
        // Race Condition Check
        const { data: existing } = await req.clinicClient.from('citas')
            .select('id')
            .eq('doctor_id', body.doctor_id)
            .eq('fecha_hora', body.fecha_hora)
            .neq('estado', 'cancelada') 
            .single();

        if (existing) return res.status(409).json({ error: "Horario ocupado." });

        let clienteId = body.cliente_id;

        if (!clienteId && body.new_client_name) {
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
            descripcion: sanitizeInput(body.descripcion),
            timezone: body.timezone
        }).select().single();

        if (error) {
            if (error.code === '23505') return res.status(409).json({ error: "Horario ocupado (DB)." });
            throw error;
        }
        res.status(201).json({ ...data, new_client_id: clienteId });
    } catch (e) { 
        res.status(400).json({ error: 'Error al crear la cita.' }); 
    }
});

// PATCH Citas
app.patch('/api/citas/:id', 
    dynamicDbMiddleware, 
    requireRole(STAFF_ROLES), 
    async (req, res) => {
    try {
        const allowedSchema = z.object({
            estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']).optional(),
            descripcion: z.string().optional(),
            duracion_minutos: z.number().min(5).max(240).optional(),
            fecha_hora: z.string().datetime().optional()
        });

        const safeData = allowedSchema.parse(req.body);
        if (safeData.descripcion) safeData.descripcion = sanitizeInput(safeData.descripcion);

        const { data, error } = await req.clinicClient.from('citas')
            .update(safeData).eq('id', req.params.id).select().single();
            
        if (error) throw error;
        res.json(data);
    } catch (e) { 
        if (e instanceof z.ZodError) return res.status(400).json({ error: 'Datos inválidos' });
        res.status(500).json({ error: 'Error actualizando.' }); 
    }
});

// DELETE Citas - Solo Admin/Secretaria
app.delete('/api/citas/:id', 
    dynamicDbMiddleware, 
    requireRole(ADMIN_ROLES), 
    async (req, res) => {
    try {
        const { error } = await req.clinicClient.from('citas').delete().eq('id', req.params.id);
        if (error) throw error;
        res.status(204).send();
    } catch (e) { res.status(500).json({ error: 'Error eliminando.' }); }
});

// PATCH Clientes
app.patch('/api/clientes/:id', 
    dynamicDbMiddleware, 
    requireRole(STAFF_ROLES), 
    async (req, res) => {
    try {
        const clientUpdateSchema = z.object({
            activo: z.boolean().optional(),
            solicitud_de_secretaria: z.boolean().optional(),
            nombre: z.string().min(2).optional(),
            telefono: z.string().optional(),
            dni: z.string().optional()
        });
        const safeData = clientUpdateSchema.parse(req.body);
        ['nombre', 'telefono', 'dni'].forEach(k => { if(safeData[k]) safeData[k] = sanitizeInput(safeData[k]); });

        const { data, error } = await req.clinicClient.from('clientes')
            .update(safeData).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: 'Error actualizando cliente.' }); }
});

// FILES: Generar URL (CORRECCIÓN CRÍTICA: Anti-Spoofing en Descarga)
app.post('/api/files/generate-upload-url', dynamicDbMiddleware, async (req, res) => {
    try {
        const { fileName, clienteId } = req.body;
        if(!fileName || !clienteId) return res.status(400).json({error: "Datos inválidos"});

        // Path Traversal Mitigation
        const safeFileName = fileName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const safeClientId = String(clienteId).replace(/[^0-9]/g, '');
        const filePath = `${safeClientId}/${Date.now()}_${safeFileName}`;
        
        // 🔥 SOLUCIÓN CRÍTICA: download: true
        // Esto agrega 'Content-Disposition: attachment' obligando al navegador a descargar el archivo.
        // Impide que un HTML/SVG malicioso se ejecute en el contexto de la aplicación.
        const { data, error } = await req.clinicClient.storage
            .from('adjuntos') 
            .createSignedUploadUrl(filePath, 60 * 10, {
                download: true 
            });

        if (error) throw error;
        res.json({ signedUrl: data.signedUrl, path: data.path });
    } catch (e) { 
        res.status(500).json({ error: 'Error generando URL.' }); 
    }
});

// FILES: Confirmar Subida (Validación de Integridad)
app.post('/api/files/confirm-upload', dynamicDbMiddleware, async (req, res) => {
    try {
        const { clienteId, storagePath, fileName, fileType, fileSizeKB } = req.body;

        // Validación de extensión vs MIME (Defensa en Profundidad)
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
                 return res.status(400).json({ error: 'Discrepancia detectada entre extensión y tipo de archivo.' });
            }
        } else {
             // Opcional: Rechazar extensiones no permitidas
             // return res.status(400).json({ error: 'Tipo de archivo no soportado.' });
        }

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

// GET Archivos - Protegido con RBAC
app.get('/api/files/:clienteId', 
    dynamicDbMiddleware, 
    requireRole(STAFF_ROLES), 
    async (req, res) => {
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

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Satélite SECURE V3 Operativo en puerto ${PORT}`));