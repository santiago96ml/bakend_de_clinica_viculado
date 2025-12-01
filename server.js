// =======================================================================================
// SERVIDOR SATÉLITE VINTEX - CORREGIDO Y SEGURO
// =======================================================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');

// 1. CONFIGURACIÓN INICIAL
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// SEGURIDAD: Configurar CORS para aceptar solo tu frontend (o * en desarrollo)
app.use(cors({ 
    origin: process.env.FRONTEND_URL || '*', 
    methods: ['GET', 'POST', 'PATCH', 'DELETE']
}));
app.use(express.json());

// Variables globales dinámicas (se llenan al arrancar)
let clinicSupabase = null; 
let clinicJwtSecret = null;
let isReady = false; 

// --- VARIABLES DE ENTORNO CRÍTICAS (Deben estar en el panel del hosting) ---
const MASTER_URL = process.env.MASTER_SUPABASE_URL;
const MASTER_KEY = process.env.MASTER_SUPABASE_SERVICE_KEY;
const CLINIC_USER_ID = process.env.CLINIC_USER_ID;

// Verificación de seguridad al inicio
if (!MASTER_URL || !MASTER_KEY || !CLINIC_USER_ID) {
    console.error("❌ ERROR FATAL: Faltan variables de entorno (MASTER_... o CLINIC_USER_ID).");
    process.exit(1);
}

// Cliente Maestro (Solo para leer configuración inicial)
const masterSupabase = createClient(MASTER_URL, MASTER_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
});

// 2. SECUENCIA DE ARRANQUE (BOOTSTRAP)
async function bootServer() {
    console.log(`⏳ Iniciando Satélite para ID Clínica: ${CLINIC_USER_ID}...`);
    
    try {
        // A. Verificar si el servicio 'web_clinica' está activo en la Master DB
        const { data: servicio, error: servError } = await masterSupabase
            .from('servisi')
            .select('web_clinica')
            .eq('ID_User', CLINIC_USER_ID)
            .single();

        if (servError || !servicio?.web_clinica) {
            throw new Error('Servicio Web Clínica inactivo o no autorizado en Master.');
        }

        // B. Descargar secretos desde la tabla 'web_clinica'
        const { data: config, error: configError } = await masterSupabase
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_SERVICE_KEY, JWT_SECRET')
            .eq('ID_USER', CLINIC_USER_ID)
            .single();

        if (configError || !config) {
            throw new Error('No se encontró configuración técnica en web_clinica.');
        }

        // C. Inicializar el Cliente Local de la Clínica
        clinicJwtSecret = config.JWT_SECRET;
        clinicSupabase = createClient(config.SUPABASE_URL, config.SUPABASE_SERVICE_KEY);
        
        isReady = true;
        console.log("✅ SISTEMA ONLINE: Conectado a la Base de Datos de la Clínica.");

    } catch (error) {
        console.error('❌ Fallo crítico de arranque:', error.message);
        // No cerramos el proceso para permitir reintentos o diagnósticos, pero el estado queda isReady=false
    }
}

// 3. MIDDLEWARES

// Bloqueo hasta que el servidor esté listo
const checkReady = (req, res, next) => {
    if (!isReady) return res.status(503).json({ error: 'Servidor iniciándose, por favor espere...' });
    next();
};

// Autenticación JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token requerido.' });

    jwt.verify(token, clinicJwtSecret, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido o expirado.' });
        req.user = user;
        next();
    });
};

// Rate Limiter
const apiLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 200 }); // 200 req/min
app.use('/api/', apiLimiter);

// 4. SCHEMAS DE VALIDACIÓN (ZOD)
const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
});

const nuevaCitaSchema = z.object({
    doctor_id: z.number(),
    fecha_hora: z.string().datetime(), // ISO 8601
    duracion_minutos: z.number().int().positive(),
    estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']),
    descripcion: z.string().optional(),
    timezone: z.string().optional(),
    // Datos opcionales para cliente
    cliente_id: z.number().optional(),
    new_client_name: z.string().optional(),
    new_client_dni: z.string().optional(),
    new_client_telefono: z.string().optional(),
});

// 5. RUTAS DE LA API

// Health Check
app.get('/', (req, res) => res.status(200).send(isReady ? 'Vintex Satellite: ONLINE' : 'Vintex Satellite: BOOTING...'));

// LOGIN DEL PERSONAL (Contra tabla 'usuarios' local)
app.post('/api/login', checkReady, async (req, res) => {
    try {
        const { email, password } = loginSchema.parse(req.body);
        
        // Buscar en DB Local
        const { data: user, error } = await clinicSupabase
            .from('usuarios')
            .select('id, email, password_hash, rol, nombre')
            .eq('email', email)
            .single();

        if (error || !user) return res.status(401).json({ error: 'Usuario no encontrado.' });

        // Verificar contraseña
        const validPass = await bcrypt.compare(password, user.password_hash);
        if (!validPass) return res.status(401).json({ error: 'Contraseña incorrecta.' });

        // Generar Token
        const token = jwt.sign(
            { id: user.id, email: user.email, rol: user.rol, nombre: user.nombre }, 
            clinicJwtSecret, 
            { expiresIn: '12h' }
        );

        res.json({ token, user: { id: user.id, email: user.email, rol: user.rol, nombre: user.nombre } });

    } catch (e) {
        if (e instanceof z.ZodError) return res.status(400).json({ error: 'Datos inválidos' });
        res.status(500).json({ error: e.message || 'Error interno' });
    }
});

// OBTENER CITAS (Rango de fechas)
app.get('/api/citas', checkReady, authenticateToken, async (req, res) => {
    const { start, end } = req.query;
    try {
        let query = clinicSupabase
            .from('citas')
            .select(`
                *,
                cliente:clientes(id, nombre, dni, telefono),
                doctor:doctores(id, nombre, especialidad, color)
            `)
            .order('fecha_hora', { ascending: true });

        if (start && end) {
            query = query.gte('fecha_hora', start).lte('fecha_hora', end);
        }

        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// CREAR CITA (Con lógica de Paciente Nuevo)
app.post('/api/citas', checkReady, authenticateToken, async (req, res) => {
    try {
        const body = nuevaCitaSchema.parse(req.body);
        let clienteId = body.cliente_id;

        // Si es paciente nuevo, crearlo primero
        if (!clienteId && body.new_client_name) {
            // Verificar duplicados por DNI primero
            const { data: existing } = await clinicSupabase
                .from('clientes')
                .select('id')
                .eq('dni', body.new_client_dni)
                .single();

            if (existing) {
                clienteId = existing.id; // Usar existente si el DNI coincide
            } else {
                const { data: newClient, error: clientError } = await clinicSupabase
                    .from('clientes')
                    .insert({
                        nombre: body.new_client_name,
                        dni: body.new_client_dni,
                        telefono: body.new_client_telefono || '',
                        activo: true,
                        solicitud_de_secretaria: false // Corrección de tilde
                    })
                    .select()
                    .single();
                
                if (clientError) throw new Error(`Error creando paciente: ${clientError.message}`);
                clienteId = newClient.id;
            }
        }

        if (!clienteId) throw new Error("Debe seleccionar un paciente o ingresar datos válidos.");

        // Crear la Cita
        const { data: cita, error: citaError } = await clinicSupabase
            .from('citas')
            .insert({
                doctor_id: body.doctor_id,
                cliente_id: clienteId,
                fecha_hora: body.fecha_hora,
                duracion_minutos: body.duracion_minutos,
                estado: body.estado,
                descripcion: body.descripcion,
                timezone: body.timezone
            })
            .select()
            .single();

        if (citaError) throw citaError;
        res.status(201).json(cita);

    } catch (e) {
        const msg = e instanceof z.ZodError ? 'Datos inválidos' : e.message;
        res.status(400).json({ error: msg, details: e });
    }
});

// DATOS INICIALES (Doctores y Pacientes para selects)
app.get('/api/initial-data', checkReady, authenticateToken, async (req, res) => {
    try {
        const [doctores, clientes] = await Promise.all([
            clinicSupabase.from('doctores').select('*').eq('activo', true),
            clinicSupabase.from('clientes').select('*').eq('activo', true).limit(500) // Limitar para rendimiento
        ]);
        
        res.json({ 
            doctors: doctores.data || [], 
            clients: clientes.data || [] 
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- INICIAR SERVIDOR ---
app.listen(PORT, () => {
    console.log(`🚀 Servidor Satélite escuchando en puerto ${PORT}`);
    bootServer(); // Arrancar lógica de conexión
});