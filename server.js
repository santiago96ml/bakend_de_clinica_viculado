require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// Variables de entorno
const MASTER_URL = process.env.MASTER_SUPABASE_URL;
const MASTER_KEY = process.env.MASTER_SUPABASE_SERVICE_KEY;
const CLINIC_USER_ID = process.env.CLINIC_USER_ID; 

app.use(cors({ origin: '*' }));
app.use(express.json());

// Estado del servidor
let supabase; 
let JWT_SECRET;
let isReady = false;

// --- BOOTSTRAP: Conexión con Master ---
async function bootServer() {
    if (!MASTER_URL || !MASTER_KEY || !CLINIC_USER_ID) {
        console.error("❌ ERROR: Faltan variables de entorno MASTER o CLINIC_USER_ID");
        return;
    }

    console.log(`⏳ Iniciando Satélite para ID: ${CLINIC_USER_ID}...`);
    try {
        const masterClient = createClient(MASTER_URL, MASTER_KEY);
        
        // Obtener credenciales
        const { data, error } = await masterClient
            .from('web_clinica')
            .select('SUPABASE_URL, SUPABASE_SERVICE_KEY, JWT_SECRET')
            .eq('ID_USER', CLINIC_USER_ID)
            .single();

        if (error || !data) throw new Error("No se encontró configuración en Master DB.");

        // Inicializar cliente local con permisos de servicio (Admin)
        supabase = createClient(data.SUPABASE_URL, data.SUPABASE_SERVICE_KEY);
        JWT_SECRET = data.JWT_SECRET;
        isReady = true;
        
        console.log("✅ Satélite CONECTADO a DB Clínica.");
    } catch (err) {
        console.error("❌ Fallo de arranque:", err.message);
        setTimeout(bootServer, 10000); 
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

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// --- RUTAS API (CRM COMPLETO) ---

// 1. DATA INICIAL
app.get('/api/initial-data', checkReady, authenticateToken, async (req, res) => {
    try {
        const [docs, clients] = await Promise.all([
            supabase.from('doctores').select('*').eq('activo', true),
            supabase.from('clientes').select('*').eq('activo', true) // Solo activos por defecto
        ]);
        res.json({ doctores: docs.data, clientes: clients.data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. CITAS (Lectura/Escritura)
app.get('/api/citas', checkReady, authenticateToken, async (req, res) => {
    const { start, end } = req.query;
    try {
        let query = supabase.from('citas')
            .select(`*, cliente:clientes(id, nombre, telefono, dni), doctor:doctores(id, nombre, color)`)
            .order('fecha_hora', { ascending: true });

        if (start && end) query = query.gte('fecha_hora', start).lte('fecha_hora', end);
        
        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/citas', checkReady, authenticateToken, async (req, res) => {
    try {
        const body = req.body;
        let clienteId = body.cliente_id;

        // Lógica de "Paciente Nuevo" (Transaccional)
        if (!clienteId && body.new_client_name) {
            const { data: newClient, error: cErr } = await supabase.from('clientes')
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
        res.status(201).json({ ...data, new_client_id: clienteId });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.patch('/api/citas/:id', checkReady, authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase.from('citas').update(req.body).eq('id', req.params.id).select().single();
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

// 3. GESTIÓN DE PACIENTES (Toggle Bot / Secretaría)
app.patch('/api/clientes/:id', checkReady, authenticateToken, async (req, res) => {
    try {
        const { activo, solicitud_de_secretaria } = req.body;
        const updates = {};
        // Solo actualizamos lo que viene en el body
        if (typeof activo === 'boolean') updates.activo = activo;
        if (typeof solicitud_de_secretaria === 'boolean') updates.solicitud_de_secretaria = solicitud_de_secretaria;

        const { data, error } = await supabase.from('clientes')
            .update(updates).eq('id', req.params.id).select().single();
        
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4. STORAGE (Archivos Adjuntos)
app.post('/api/files/generate-upload-url', checkReady, authenticateToken, async (req, res) => {
    try {
        const { fileName, fileType, clienteId } = req.body;
        // Estructura: ID_CLIENTE / TIMESTAMP_NOMBRE
        const filePath = `${clienteId}/${Date.now()}_${fileName.replace(/\s+/g, '_')}`;
        
        const { data, error } = await supabase.storage
            .from('adjuntos') // IMPORTANTE: Crear este bucket en Supabase como público o privado autenticado
            .createSignedUploadUrl(filePath, 60 * 10); // 10 minutos de validez

        if (error) throw error;
        res.json({ signedUrl: data.signedUrl, path: data.path });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/confirm-upload', checkReady, authenticateToken, async (req, res) => {
    try {
        const { clienteId, storagePath, fileName, fileType, fileSizeKB } = req.body;
        const { data, error } = await supabase.from('archivos_adjuntos').insert({
            cliente_id: clienteId,
            storage_path: storagePath,
            file_name: fileName,
            file_type: fileType,
            file_size_kb: fileSizeKB,
            // Asumimos que podemos obtener el ID del usuario del token si está en la tabla users
            // subido_por_admin_id: req.user.sub 
        }).select().single();

        if (error) throw error;
        res.status(201).json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/files/:clienteId', checkReady, authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase.from('archivos_adjuntos')
            .select('*').eq('cliente_id', req.params.clienteId).order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. HISTORIAL DE CHAT
app.get('/api/chat-history/:telefono', checkReady, authenticateToken, async (req, res) => {
    try {
        // Normalizamos el teléfono (quitamos símbolos)
        const phone = req.params.telefono.replace(/\D/g, ''); 
        if (!phone) return res.json([]);

        const { data, error } = await supabase.from('n8n_chat_histories')
            .select('*')
            .ilike('session_id', `%${phone}%`) // Búsqueda flexible
            .order('id', { ascending: true });
            
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`🚀 Satélite Operativo en puerto ${PORT}`));