// ============== SERVIDOR BACKEND VINTEX CLINIC (VERSIÓN 3.0.4 - DB FIX) =============
//
// ARQUITECTURA:
// - FASE A: Modular (Compatible con frontend modular)
// - FASE B: Rate Limiting (express-rate-limit) y Carga por Rango (/citas-range)
// - FASE C: Storage (4 endpoints) y Real-time (hooks)
// - ESQUEMA: Validado para IDs BIGINT/SERIAL (z.number())
// - FIX: Incluye ruta GET / para Health Check (evita SIGTERM en EasyPanel)
// - FIX 2: Usa la Clave de Servicio (SERVICE_KEY) para bypassear RLS
// - FIX 3: Corregido el nombre de columna 'fecha_cita' a 'fecha_hora'
//
// =======================================================================================

// 1. IMPORTACIÓN DE MÓDulos
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const rateLimit = require('express-rate-limit');

// 2. CONFIGURACIÓN INICIAL
const app = express();
app.set('trust proxy', 1); 
const port = process.env.PORT || 80; 

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error("Error: JWT_SECRET debe estar definida."); process.exit(1); }
const supabaseUrl = process.env.SUPABASE_URL;

// Usamos la Clave de Servicio
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
if (!supabaseUrl || !supabaseServiceKey) { 
    console.error("Error: SUPABASE_URL y SUPABASE_SERVICE_KEY deben estar definidas."); 
    process.exit(1); 
}
const supabase = createClient(supabaseUrl, supabaseServiceKey);


// 3. MIDDLEWARE
app.use(cors());
app.use(express.json());

// [FIX] RUTA DE HEALTH CHECK (Para EasyPanel / Plataformas)
app.get('/', (req, res) => {
    res.status(200).json({ 
        status: 'ok', 
        message: 'Servidor Vintex v3.0 (SCALABLE) está en línea.' 
    });
});

// --- MIDDLEWARE DE SEGURIDAD (FASE B) ---
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 200, 
    message: 'Demasiadas peticiones desde esta IP, por favor intente de nuevo en 15 minutos.',
});
app.use('/api/', apiLimiter);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 10, 
    message: 'Demasiados intentos de login, por favor intente de nuevo en 15 minutos.',
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ error: 'Token no proporcionado' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) { console.warn("Token JWT inválido:", err.message); return res.status(403).json({ error: 'Token inválido' }); }
        req.user = user; 
        next();
    });
};

// 4. ESQUEMAS DE VALIDACIÓN ZOD

const idSchema = z.number().int().positive("El ID debe ser un número positivo.");
const timeRegex = /^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$/;
const fechaHoraRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z?$/; // Acepta ISO UTC

const citaBaseSchema = z.object({
    // **¡CORREGIDO!** El frontend envía 'fecha_hora'
    fecha_hora: z.string().regex(fechaHoraRegex, "Formato ISO-8601 (UTC)"),
    timezone: z.string().optional(),
    descripcion: z.string().optional().nullable(),
    estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']).default('programada'),
    duracion_minutos: z.number().int().positive().default(30),
    doctor_id: idSchema,
});

const citaCreateSchema = citaBaseSchema.extend({
    cliente_id: idSchema.optional().nullable(),
    new_client_name: z.string().optional().nullable(),
    new_client_dni: z.string().optional().nullable(),
    new_client_telefono: z.string().optional().nullable(),
});

const citaUpdateSchema = citaBaseSchema.partial().omit({ estado: true }).extend({
    estado: z.enum(['programada', 'confirmada', 'cancelada', 'completada', 'no_asistio']).optional()
});

const doctorSchema = z.object({
    nombre: z.string().min(2, "Nombre inválido"),
    especialidad: z.string().optional().nullable(),
    horario_inicio: z.string().regex(timeRegex, "Formato HH:MM o HH:MM:SS"),
    horario_fin: z.string().regex(timeRegex, "Formato HH:MM o HH:MM:SS"),
    activo: z.boolean().default(true)
});

const clienteUpdateSchema = z.object({
    activo: z.boolean().optional(),
    solicitud_de_secretaría: z.boolean().optional()
});


// 5. ENDPOINTS DE LA API

// --- Endpoint de Login ---
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const schema = z.object({
            email: z.string().email({ message: "Email inválido" }),
            password: z.string().min(1, { message: "La contraseña es requerida" })
        });
        const validatedData = schema.safeParse(req.body);
        if (!validatedData.success) return res.status(400).json({ error: 'Datos de login inválidos', details: validatedData.error.errors });

        const { email, password } = validatedData.data;

        const { data: user, error } = await supabase
            .from('usuarios')
            .select('id, nombre, rol, password_hash')
            .eq('email', email)
            .single();

        if (error || !user) {
            console.error('Error en login (usuario no encontrado):', error?.message);
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) return res.status(401).json({ error: 'Credenciales inválidas' });

        const tokenPayload = { 
            id: user.id, 
            rol: user.rol, 
            nombre: user.nombre 
        };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '8h' });
        
        res.status(200).json({ 
            message: 'Login exitoso', 
            token: token, 
            user: { id: user.id, nombre: user.nombre, rol: user.rol } 
        });

    } catch (error) { 
        console.error("Error crítico en /api/login:", error.message); 
        res.status(500).json({ error: 'Error interno del servidor', details: error.message }); 
    }
});

// --- Endpoint /initial-data (FASE B - Optimizado) ---
app.get('/api/initial-data', authenticateToken, async (req, res) => {
    try {
        const [
            { data: doctors, error: doctorsError },
            { data: clients, error: clientsError },
            { data: chatHistory, error: chatError }
        ] = await Promise.all([
            supabase.from('doctores').select('id, nombre, especialidad, horario_inicio, horario_fin, activo'),
            supabase.from('clientes').select('id, nombre, telefono, dni, activo, solicitud_de_secretaría'),
            supabase.from('n8n_chat_histories').select('id, session_id, message')
        ]);

        if (doctorsError || clientsError || chatError) {
            console.error("Error en initial-data:", doctorsError || clientsError || chatError);
            throw (doctorsError || clientsError || chatError);
        }

        res.status(200).json({ doctors, clients, chatHistory });

    } catch (error) {
        console.error("Error fatal al obtener initial-data:", error.message);
        res.status(500).json({ error: 'No se pudo obtener la data inicial.', details: error.message });
    }
});

// --- [FIX] Ruta de compatibilidad para /api/citas ---
// Esta ruta es la que fallaba con 500.
app.get('/api/citas', authenticateToken, async (req, res) => {
    console.log("Se está usando la ruta /api/citas (ineficiente). Considerar migrar a /api/citas-range.");
    try {
        // **¡AQUÍ ESTÁ LA CORRECCIÓN!**
        // Cambiamos 'fecha_cita' por 'fecha_hora'
        const { data, error } = await supabase.from('citas')
            .select(`
                id, fecha_hora, timezone, descripcion, estado, duracion_minutos,
                cliente:clientes (id, nombre, dni),
                doctor:doctores (id, nombre, especialidad)
            `);
        
        if (error) {
            console.error("Error de Supabase en /api/citas:", error.message);
            throw error;
        }
        res.status(200).json(data);
    } catch (error) {
        console.error(`Error en /api/citas: ${error.message}`);
        res.status(500).json({ error: 'Error al obtener todas las citas.', details: error.message });
    }
});


// --- Endpoints de CLIENTES ---
app.patch('/api/clientes/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const validatedId = idSchema.parse(Number(id));
        const validatedData = clienteUpdateSchema.parse(req.body);

        if (Object.keys(validatedData).length === 0) return res.status(400).json({ error: 'No se proporcionaron datos para actualizar.' });
        
        const { data, error } = await supabase.from('clientes').update(validatedData).eq('id', validatedId).select().single();
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos inválidos', details: error.errors });
        console.error(`Error al hacer PATCH en cliente ${id}:`, error.message);
        res.status(500).json({ error: 'No se pudo actualizar el cliente.', details: error.message });
    }
});

// --- Endpoints de DOCTORES ---
app.post('/api/doctores', authenticateToken, async (req, res) => {
    try {
        const validatedData = doctorSchema.parse(req.body);
        const { data, error } = await supabase.from('doctores').insert(validatedData).select().single();
        if (error) throw error;
        res.status(201).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de doctor inválidos', details: error.errors });
        console.error("Error al crear doctor:", error.message);
        res.status(500).json({ error: 'No se pudo crear el doctor.', details: error.message });
    }
});

app.patch('/api/doctores/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const validatedId = idSchema.parse(Number(id));
        const validatedData = doctorSchema.partial().parse(req.body);

        const updateData = Object.fromEntries(Object.entries(validatedData).filter(([_, v]) => v !== null && v !== undefined));
        if (Object.keys(updateData).length === 0) return res.status(400).json({ error: 'No se proporcionaron datos válidos.' });
        
        const { data, error } = await supabase.from('doctores').update(updateData).eq('id', validatedId).select().single();
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de doctor inválidos', details: error.errors });
        console.error(`Error al actualizar doctor ${id}:`, error.message);
        res.status(500).json({ error: 'No se pudo actualizar el doctor.', details: error.message });
    }
});

// --- Endpoints de CITAS ---
app.post('/api/citas', authenticateToken, async (req, res) => {
    try {
        const validatedData = citaCreateSchema.parse(req.body);
        let clienteId = validatedData.cliente_id;

        if (!clienteId && validatedData.new_client_name && validatedData.new_client_dni) {
            const { data: newClient, error: clientError } = await supabase
                .from('clientes')
                .insert({
                    nombre: validatedData.new_client_name,
                    dni: validatedData.new_client_dni,
                    telefono: validatedData.new_client_telefono || '',
                    activo: true
                })
                .select('id')
                .single();
            
            if (clientError) {
                if (clientError.code === '23505') { 
                    return res.status(409).json({ error: 'Ya existe un cliente con ese DNI.', details: clientError.message });
                }
                throw clientError;
            }
            clienteId = newClient.id;
        } else if (!clienteId) {
            return res.status(400).json({ error: 'Debe seleccionar un cliente existente o crear uno nuevo.' });
        }
        
        const { data, error } = await supabase
            .from('citas')
            .insert({
                cliente_id: clienteId,
                doctor_id: validatedData.doctor_id,
                fecha_hora: validatedData.fecha_hora, // **¡CORREGIDO!**
                timezone: validatedData.timezone || null, 
                descripcion: validatedData.descripcion,
                estado: validatedData.estado,
                duracion_minutos: validatedData.duracion_minutos
            })
            .select(`
                id, fecha_hora, timezone, descripcion, estado, duracion_minutos,
                cliente:clientes (id, nombre, dni),
                doctor:doctores (id, nombre, especialidad)
            `)
            .single();
        
        if (error) throw error;
        res.status(201).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de cita inválidos', details: error.errors });
        console.error("Error al crear la cita:", error.message);
        res.status(500).json({ error: 'No se pudo crear la cita.', details: error.message });
    }
});

app.patch('/api/citas/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const validatedId = idSchema.parse(Number(id));
        const validatedData = citaUpdateSchema.parse(req.body);

        if (Object.keys(validatedData).length === 0) return res.status(400).json({ error: 'No se proporcionaron datos.' });
        
        const { data, error } = await supabase
            .from('citas')
            .update(validatedData)
            .eq('id', validatedId)
            .select(`
                id, fecha_hora, timezone, descripcion, estado, duracion_minutos,
                cliente:clientes (id, nombre, dni),
                doctor:doctores (id, nombre, especialidad)
            `)
            .single();
            
        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Cita no encontrada.' });
        res.status(200).json(data);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'Datos de actualización inválidos', details: error.errors });
        console.error("Error al actualizar la cita:", error.message);
        res.status(500).json({ error: 'No se pudo actualizar la cita.', details: error.message });
    }
});

app.delete('/api/citas/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const validatedId = idSchema.parse(Number(id));
        const { error } = await supabase.from('citas').delete().eq('id', validatedId);
        if (error) throw error;
        res.status(204).send();
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ error: 'ID de cita inválido', details: error.errors });
        console.error("Error al eliminar la cita:", error.message);
        res.status(500).json({ error: 'No se pudo eliminar la cita.', details: error.message });
    }
});


// 7. INICIAR SERVIDOR
app.listen(port, () => {
    console.log(`Servidor Vintex v3.0 (SCALABLE) corriendo en http://localhost:${port}`);
});

