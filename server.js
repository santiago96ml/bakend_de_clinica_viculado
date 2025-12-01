require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const { z } = require('zod');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// Variables de entorno (Configurar en Easypanel del Satélite)
const MASTER_URL = process.env.MASTER_SUPABASE_URL;
const MASTER_KEY = process.env.MASTER_SUPABASE_SERVICE_KEY;
const CLINIC_USER_ID = process.env.CLINIC_USER_ID; 

app.use(cors({ origin: '*' }));
app.use(express.json());

// Estado del servidor
let supabase; 
let JWT_SECRET;
let isReady = false;

// --- BOOTSTRAP: Cargar configuración desde Master ---
async function bootServer() {
    if (!MASTER_URL || !MASTER_KEY || !CLINIC_USER_ID) {
        console.error("❌ ERROR: Faltan variables de entorno MASTER o CLINIC_USER_ID");
        return;
    }

    console.log(`⏳ Iniciando Satélite para ID: ${CLINIC_USER_ID}...`);
    try {
        const masterClient = createClient(MASTER_URL, MASTER_KEY);
        
        // Obtener credenciales de la tabla web_clinica
        const { data, error } = await masterClient
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_SERVICE_KEY, JWT_SECRET')
            .eq('ID_USER', CLINIC_USER_ID)
            .single();

        if (error || !data) throw new Error("No se encontró configuración en Master DB.");

        // Inicializar cliente local
        supabase = createClient(data.SUPABASE_URL, data.SUPABASE_SERVICE_KEY);
        JWT_SECRET = data.JWT_SECRET;
        isReady = true;
        
        console.log("✅ Satélite CONECTADO a DB Clínica.");
    } catch (err) {
        console.error("❌ Fallo de arranque:", err.message);
        setTimeout(bootServer, 10000); // Reintentar
    }
}
bootServer();

// --- MIDDLEWARES ---
const checkReady = (req, res, next) => {
    if (!isReady) return res.status(503).json({ error: 'Servidor iniciando...' });
    next();
};

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token requerido' });

    // Validamos el token. Si viene del Master (Admin) o Login Local (Staff)
    // Asumimos que ambos comparten el JWT_SECRET si se configuró así en Supabase
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// --- ROUTES ---

// Health Check
app.get('/', (req, res) => res.send(isReady ? 'Vintex Clinic API: ONLINE' : 'Booting...'));

// 1. DATA INICIAL (Dashboard)
app.get('/api/initial-data', checkReady, authenticateToken, async (req, res) => {
    try {
        const [docs, clients] = await Promise.all([
            supabase.from('doctores').select('*').eq('activo', true),
            supabase.from('clientes').select('*').eq('activo', true)
        ]);
        res.json({ doctores: docs.data, clientes: clients.data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. OBTENER CITAS
app.get('/api/citas', checkReady, authenticateToken, async (req, res) => {
    const { start, end } = req.query;
    try {
        let query = supabase.from('citas')
            .select(`*, cliente:clientes(id, nombre, telefono), doctor:doctores(id, nombre, color)`)
            .order('fecha_hora', { ascending: true });

        if (start && end) query = query.gte('fecha_hora', start).lte('fecha_hora', end);
        
        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. CREAR/EDITAR CITAS
app.post('/api/citas', checkReady, authenticateToken, async (req, res) => {
    try {
        const body = req.body;
        let clienteId = body.cliente_id;

        // Crear cliente nuevo si aplica
        if (!clienteId && body.new_client_name) {
            const { data: newClient, error: cErr } = await supabase.from('clientes')
                .insert({
                    nombre: body.new_client_name,
                    dni: body.new_client_dni || '',
                    telefono: body.new_client_telefono || '',
                    activo: true
                }).select().single();
            
            if (cErr) throw cErr;
            clienteId = newClient.id;
        }

        const { data, error } = await supabase.from('citas').insert({
            doctor_id: body.doctor_id,
            cliente_id: clienteId,
            fecha_hora: body.fecha_hora,
            duracion_minutos: body.duracion_minutos,
            estado: body.estado,
            descripcion: body.descripcion,
            timezone: body.timezone
        }).select().single();

        if (error) throw error;
        res.status(201).json(data);
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.patch('/api/citas/:id', checkReady, authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase.from('citas')
            .update(req.body)
            .eq('id', req.params.id)
            .select().single();
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/citas/:id', checkReady, authenticateToken, async (req, res) => {
    try {
        const { error } = await supabase.from('citas').delete().eq('id', req.params.id);
        if (error) throw error;
        res.status(204).send();
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`🚀 Satélite (Clínica) en puerto ${PORT}`));