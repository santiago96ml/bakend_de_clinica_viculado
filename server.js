require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3002;

// --- CONFIGURACIÓN MASTER (CEREBRO) ---
// Estas variables deben estar en tu .env del Satélite
const MASTER_URL = process.env.MASTER_SUPABASE_URL;
const MASTER_KEY = process.env.MASTER_SUPABASE_SERVICE_KEY;

if (!MASTER_URL || !MASTER_KEY) {
    console.error("❌ ERROR CRÍTICO: Faltan credenciales MASTER en .env");
    process.exit(1);
}

// Cliente Maestro: Solo se usa para autenticar y buscar credenciales
const masterClient = createClient(MASTER_URL, MASTER_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
});

app.use(cors({ origin: '*' }));
app.use(express.json());

// --- SISTEMA DE CACHÉ DE CONEXIONES ---
// Para no consultar la DB Master en cada clic, guardamos las credenciales en memoria por 5 min
const credentialCache = new Map(); 
const CACHE_TTL = 1000 * 60 * 5; // 5 minutos

// --- MIDDLEWARE MULTI-TENANT (EL CORAZÓN DEL SISTEMA) ---
const dynamicDbMiddleware = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token requerido' });

    try {
        // 1. Validar quién es el usuario usando el Auth del Master
        const { data: { user }, error: authError } = await masterClient.auth.getUser(token);

        if (authError || !user) {
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }

        req.user = user; // Guardamos el usuario identificado

        // 2. Revisar si ya tenemos las credenciales de su clínica en caché
        let clinicConfig = credentialCache.get(user.id);
        
        // 3. Si no está en caché, buscamos en la tabla 'web_clinica' del Master
        if (!clinicConfig || (Date.now() - clinicConfig.timestamp > CACHE_TTL)) {
            console.log(`🔄 Resolviendo conexión para usuario: ${user.id}`);
            
            const { data, error: dbError } = await masterClient
                .from('web_clinica')
                .select('SUPABASE_URL, SUPABASE_SERVICE_KEY')
                .eq('ID_USER', user.id) // Relación definida en tu esquema [cite: 162]
                .single();

            if (dbError || !data) {
                return res.status(404).json({ error: 'No tienes una clínica configurada. Contacta a soporte.' });
            }

            clinicConfig = {
                url: data.SUPABASE_URL,
                key: data.SUPABASE_SERVICE_KEY,
                timestamp: Date.now()
            };
            // Guardar en caché
            credentialCache.set(user.id, clinicConfig);
        }

        // 4. Crear la conexión "AL VUELO" para esta clínica específica
        // Usamos la Service Key de la clínica para tener permisos de Admin sobre sus datos
        req.clinicClient = createClient(clinicConfig.url, clinicConfig.key, {
            auth: { autoRefreshToken: false, persistSession: false }
        });

        next(); // Continuar a la ruta solicitada

    } catch (err) {
        console.error("🔥 Error crítico en middleware:", err);
        res.status(500).json({ error: 'Error interno de enrutamiento de base de datos' });
    }
};

// --- RUTAS DE LA API (Ahora usan req.clinicClient) ---

// 1. DATA INICIAL (Doctores y Clientes)
app.get('/api/initial-data', dynamicDbMiddleware, async (req, res) => {
    try {
        const [docs, clients] = await Promise.all([
            req.clinicClient.from('doctores').select('*').eq('activo', true), // Tabla doctores [cite: 75]
            req.clinicClient.from('clientes').select('*').eq('activo', true)  // Tabla clientes [cite: 51]
        ]);
        
        if (docs.error) throw docs.error;
        if (clients.error) throw clients.error;

        res.json({ doctores: docs.data, clientes: clients.data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. CITAS (Lectura)
app.get('/api/citas', dynamicDbMiddleware, async (req, res) => {
    const { start, end } = req.query;
    try {
        let query = req.clinicClient.from('citas') // Tabla citas [cite: 16]
            .select(`*, cliente:clientes(id, nombre, telefono, dni), doctor:doctores(id, nombre, color)`)
            .order('fecha_hora', { ascending: true });

        if (start && end) query = query.gte('fecha_hora', start).lte('fecha_hora', end);
        
        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. CREAR CITA (Escritura)
app.post('/api/citas', dynamicDbMiddleware, async (req, res) => {
    try {
        const body = req.body;
        let clienteId = body.cliente_id;

        // Si es paciente nuevo, lo creamos primero en la DB de la clínica
        if (!clienteId && body.new_client_name) {
            const { data: newClient, error: cErr } = await req.clinicClient.from('clientes')
                .insert({
                    nombre: body.new_client_name,
                    dni: body.new_client_dni || '',
                    telefono: body.new_client_telefono || '',
                    activo: true,
                    solicitud_de_secretaría: false // [cite: 59] Ojo con el acento en tu schema
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
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 4. ACTUALIZAR CITA
app.patch('/api/citas/:id', dynamicDbMiddleware, async (req, res) => {
    try {
        const { data, error } = await req.clinicClient.from('citas')
            .update(req.body).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. BORRAR CITA
app.delete('/api/citas/:id', dynamicDbMiddleware, async (req, res) => {
    try {
        const { error } = await req.clinicClient.from('citas').delete().eq('id', req.params.id);
        if (error) throw error;
        res.status(204).send();
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 6. GESTIÓN DE PACIENTES
app.patch('/api/clientes/:id', dynamicDbMiddleware, async (req, res) => {
    try {
        const { activo, solicitud_de_secretaria } = req.body;
        const updates = {};
        if (typeof activo === 'boolean') updates.activo = activo;
        
        // Mapeo el nombre del campo según tu schema [cite: 59]
        if (typeof solicitud_de_secretaria === 'boolean') updates.solicitud_de_secretaría = solicitud_de_secretaria;

        const { data, error } = await req.clinicClient.from('clientes')
            .update(updates).eq('id', req.params.id).select().single();
        
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 7. ARCHIVOS ADJUNTOS (Storage)
app.post('/api/files/generate-upload-url', dynamicDbMiddleware, async (req, res) => {
    try {
        const { fileName, clienteId } = req.body;
        const filePath = `${clienteId}/${Date.now()}_${fileName.replace(/\s+/g, '_')}`;
        
        // Subimos al bucket 'adjuntos' de la clínica
        const { data, error } = await req.clinicClient.storage
            .from('adjuntos') 
            .createSignedUploadUrl(filePath, 60 * 10);

        if (error) throw error;
        res.json({ signedUrl: data.signedUrl, path: data.path });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/confirm-upload', dynamicDbMiddleware, async (req, res) => {
    try {
        // Guardamos metadata en tabla archivos_adjuntos [cite: 1]
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
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/files/:clienteId', dynamicDbMiddleware, async (req, res) => {
    try {
        const { data, error } = await req.clinicClient.from('archivos_adjuntos')
            .select('*').eq('cliente_id', req.params.clienteId).order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 8. HISTORIAL DE CHAT
app.get('/api/chat-history/:telefono', dynamicDbMiddleware, async (req, res) => {
    try {
        const phone = req.params.telefono.replace(/\D/g, ''); 
        if (!phone) return res.json([]);

        // Tabla n8n_chat_histories [cite: 104]
        const { data, error } = await req.clinicClient.from('n8n_chat_histories')
            .select('*')
            .ilike('session_id', `%${phone}%`)
            .order('id', { ascending: true });
            
        if (error) throw error;
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Satélite SaaS (Multi-Tenant) Corriendo en puerto ${PORT}`));