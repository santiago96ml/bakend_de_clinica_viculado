// =======================================================================================
// FUSIÓN VINTEX: ORQUESTADOR (Logic Creds) + CLINIC BACKEND (Business Logic)
// =======================================================================================

// 1. IMPORTACIÓN DE MÓDULOS
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');

// 2. CONFIGURACIÓN INICIAL DEL APP
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' }));
app.use(express.json());

// Variables globales para el cliente de la clínica (se llenarán dinámicamente)
let supabase; 
let JWT_SECRET;

// =======================================================================================
// PARTE 1: LÓGICA DE CREDENCIALES (Inspirado en Código 1)
// =======================================================================================

const MASTER_URL = process.env.MASTER_SUPABASE_URL;
const MASTER_KEY = process.env.MASTER_SUPABASE_SERVICE_KEY;
const CLINIC_USER_ID = process.env.CLINIC_USER_ID;

if (!MASTER_URL || !MASTER_KEY || !CLINIC_USER_ID) {
    console.error("❌ ERROR FATAL: Faltan credenciales MAESTRAS o CLINIC_USER_ID en .env");
    process.exit(1);
}

// Cliente Maestro (Solo para arrancar)
const masterSupabase = createClient(MASTER_URL, MASTER_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
});

async function bootServer() {
    console.log("⏳ Iniciando secuencia de arranque (Orquestador)...");
    
    try {
        // A. Verificar servicio activo en la Master
        const { data: servicio, error: servError } = await masterSupabase
            .from('servisi')
            .select('web_clinica')
            .eq('ID_User', CLINIC_USER_ID)
            .single();

        if (servError || !servicio || !servicio.web_clinica) {
            throw new Error('Servicio Web Clínica no activo o no autorizado en la Master DB.');
        }

        // B. Obtener secretos de la tabla 'web_clinica'
        const { data: config, error: configError } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_SERVICE_KEY, JWT_SECRET')
            .eq('ID_USER', CLINIC_USER_ID)
            .single();

        if (configError || !config) {
            throw new Error('Configuración no encontrada en web_clinica para este usuario.');
        }

        // C. Asignar credenciales a las variables globales
        console.log(`🔐 Credenciales obtenidas para Clinic ID: ${CLINIC_USER_ID}`);
        
        JWT_SECRET = config.JWT_SECRET;
        supabase = createClient(config.SUPABASE_URL, config.SUPABASE_SERVICE_KEY);
        
        console.log("✅ Cliente Supabase de la CLÍNICA inicializado correctamente.");
        
        // D. Iniciar el servidor Express (solo después de tener la config)
        startExpressServer();

    } catch (error) {
        console.error('❌ Error crítico en el arranque:', error.message);
        process.exit(1);
    }
}

// =======================================================================================
// PARTE 2: LÓGICA DE NEGOCIO (100% Código 2)
// =======================================================================================

// Middlewares de Rate Limit
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10,
    message: 'Demasiados intentos de inicio de sesión.',
    standardHeaders: true, legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, 
    max: 100,
    message: 'Demasiadas peticiones a la API.',
    standardHeaders: true, legacyHeaders: false,
});

app.use('/api/', apiLimiter);

// Middleware de Autenticación
function authenticateToken(req, res, next) {
    // Verificación de seguridad por si el servidor arrancó mal
    if (!JWT_SECRET) return res.status(500).json({ error: 'Servidor no inicializado correctamente.' });

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ error: 'Acceso denegado.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido.' });
        req.user = user;
        next();
    });
}

// --- ESQUEMAS ZOD (Tal cual Código 2) ---
const idSchema = z.number().int().positive();
const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
}).strict();

const citasRangeSchema = z.object({
    start: z.string().datetime(),
    end: z.string().datetime(),
}).strict();

const citaBaseSchema = z.object({
    doctor_id: idSchema,
    fecha_hora: z.string().datetime(),
    timezone: z.string(),
    descripcion: z.string().optional(),
    duracion_minutos: z.number().int().positive(),
    estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']),
});

const nuevaCitaSchema = citaBaseSchema.extend({
    cliente_id: idSchema.optional(),
    new_client_name: z.string().optional(),
    new_client_dni: z.string().optional(),
    new_client_telefono: z.string().optional(),
}).strict();

const updateCitaSchema = citaBaseSchema.partial();
const clienteSchema = z.object({ activo: z.boolean().optional(), solicitud_de_secretaría: z.boolean().optional() }).partial().strict();
const doctorSchema = z.object({ nombre: z.string().min(3).optional(), especialidad: z.string().optional().nullable(), activo: z.boolean().optional(), horario_inicio: z.string().regex(/^\d{2}:\d{2}(:\d{2})?$/).optional().nullable(), horario_fin: z.string().regex(/^\d{2}:\d{2}(:\d{2})?$/).optional().nullable() }).strict();
const updateDoctorSchema = doctorSchema.partial();

// --- DEFINICIÓN DE ENDPOINTS (Envueltos en función de inicio) ---
function startExpressServer() {

    // --- HEALTH CHECK ---
    app.get('/', (req, res) => res.status(200).send('Vintex Clinic Backend (Fusión) - Operativo'));

    // --- LOGIN ---
    app.post('/api/login', loginLimiter, async (req, res) => {
        try {
            const { email, password } = loginSchema.parse(req.body);
            const { data: user, error } = await supabase
                .from('usuarios')
                .select('id, email, password_hash, rol')
                .eq('email', email)
                .single();

            if (error || !user) return res.status(401).json({ error: 'Credenciales inválidas.' });

            const isValid = await bcrypt.compare(password, user.password_hash);
            if (!isValid) return res.status(401).json({ error: 'Credenciales inválidas.' });

            const token = jwt.sign({ id: user.id, email: user.email, rol: user.rol }, JWT_SECRET, { expiresIn: '8h' });
            res.status(200).json({ token, user: { id: user.id, email: user.email, rol: user.rol } });
        } catch (error) {
            if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos inválidos', details: error.errors });
            res.status(500).json({ error: 'Error interno.' });
        }
    });

    // --- DATOS INICIALES ---
    app.get('/api/initial-data', authenticateToken, async (req, res) => {
        try {
            const [doctores, clientes, chatHistory] = await Promise.all([
                supabase.from('doctores').select('*').order('nombre', { ascending: true }),
                supabase.from('clientes').select('*').order('nombre', { ascending: true }),
                supabase.from('n8n_chat_histories').select('*').order('id', { ascending: false }).limit(500)
            ]);
            if (doctores.error) throw doctores.error;
            res.status(200).json({ doctors: doctores.data, clients: clientes.data, chatHistory: chatHistory.data });
        } catch (error) {
            res.status(500).json({ error: 'Error cargando datos.', details: error.message });
        }
    });

    // --- CITAS (GET UNIFICADO) ---
    app.get('/api/citas', authenticateToken, async (req, res) => {
        const { start, end } = req.query;
        try {
            let query = supabase.from('citas').select(`
                id, fecha_hora, descripcion, estado, duracion_minutos, timezone,
                cliente:clientes (id, nombre, dni),
                doctor:doctores (id, nombre, especialidad, activo, horario_inicio, horario_fin)
            `).order('fecha_hora', { ascending: true });

            if (start && end) {
                const validatedQuery = citasRangeSchema.parse({ start, end });
                query = query.gte('fecha_hora', validatedQuery.start).lte('fecha_hora', validatedQuery.end);
            }
            const { data, error } = await query;
            if (error) throw error;
            res.status(200).json(data);
        } catch (error) {
            if (error instanceof z.ZodError) return res.status(400).json({ error: 'Rango inválido', details: error.errors });
            res.status(500).json({ error: 'Error obteniendo citas', details: error.message });
        }
    });

    // --- CITAS (POST) ---
    app.post('/api/citas', authenticateToken, async (req, res) => {
        try {
            const citaData = nuevaCitaSchema.parse(req.body);
            let clienteId = citaData.cliente_id;

            if (citaData.new_client_name && citaData.new_client_dni) {
                const { data: newClient, error: clientError } = await supabase
                    .from('clientes')
                    .insert({ nombre: citaData.new_client_name, dni: citaData.new_client_dni, telefono: citaData.new_client_telefono, activo: true, solicitud_de_secretaría: false })
                    .select('id').single();
                if (clientError) throw clientError;
                clienteId = newClient.id;
            } else if (!clienteId) return res.status(400).json({ error: 'Falta cliente_id.' });

            const { data: nuevaCita, error: citaError } = await supabase
                .from('citas')
                .insert({
                    cliente_id: clienteId, doctor_id: citaData.doctor_id, fecha_hora: citaData.fecha_hora, timezone: citaData.timezone,
                    descripcion: citaData.descripcion, duracion_minutos: citaData.duracion_minutos, estado: citaData.estado
                })
                .select('*, cliente:clientes(*), doctor:doctores(*)').single(); // Select simplificado para el ejemplo
            if (citaError) throw citaError;
            res.status(201).json(nuevaCita);
        } catch (error) {
            if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos inválidos', details: error.errors });
            res.status(500).json({ error: 'Error creando cita', details: error.message });
        }
    });

    // --- CITAS (PATCH) ---
    app.patch('/api/citas/:id', authenticateToken, async (req, res) => {
        try {
            const validatedId = idSchema.parse(Number(req.params.id));
            const dataToUpdate = updateCitaSchema.parse(req.body);
            const { data, error } = await supabase.from('citas').update(dataToUpdate).eq('id', validatedId).select().single();
            if (error) throw error;
            if (!data) return res.status(404).json({ error: 'No encontrada' });
            res.status(200).json(data);
        } catch (error) {
            res.status(500).json({ error: 'Error actualizando', details: error.message });
        }
    });

    // --- CITAS (DELETE) ---
    app.delete('/api/citas/:id', authenticateToken, async (req, res) => {
        try {
            const validatedId = idSchema.parse(Number(req.params.id));
            const { error } = await supabase.from('citas').delete().eq('id', validatedId);
            if (error) throw error;
            res.status(204).send();
        } catch (error) {
            res.status(500).json({ error: 'Error eliminando', details: error.message });
        }
    });

    // --- CLIENTES & DOCTORES (PATCH/POST) - Resumido manteniendo lógica ---
    app.patch('/api/clientes/:id', authenticateToken, async (req, res) => {
        try {
            const validatedId = idSchema.parse(Number(req.params.id));
            const dataToUpdate = clienteSchema.parse(req.body);
            const { data, error } = await supabase.from('clientes').update(dataToUpdate).eq('id', validatedId).select().single();
            if (error) throw error;
            res.status(200).json(data);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    app.post('/api/doctores', authenticateToken, async (req, res) => {
        try {
            const dataToInsert = doctorSchema.parse(req.body);
            const { data, error } = await supabase.from('doctores').insert(dataToInsert).select().single();
            if (error) throw error;
            res.status(201).json(data);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    app.patch('/api/doctores/:id', authenticateToken, async (req, res) => {
        try {
            const validatedId = idSchema.parse(Number(req.params.id));
            const dataToUpdate = updateDoctorSchema.parse(req.body);
            const { data, error } = await supabase.from('doctores').update(dataToUpdate).eq('id', validatedId).select().single();
            if (error) throw error;
            res.status(200).json(data);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // --- INICIO DEL SERVIDOR EXPRESS ---
    app.listen(PORT, () => {
        console.log(`\n🚀 SERVIDOR VINTEX (FUSIÓN) ACTIVO EN PUERTO ${PORT}`);
        console.log(`   - Modo: Satélite (Configuración dinámica desde Master)`);
        console.log(`   - ID Clínica: ${CLINIC_USER_ID}`);
    });
}

// 3. EJECUTAR ARRANQUE
bootServer();