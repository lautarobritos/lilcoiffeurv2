// app.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
// --- MANTENER: SDK Cliente de Firebase para operaciones en Firestore ---
const { initializeApp: initializeClientApp } = require('firebase/app');
const { getFirestore, collection, getDocs, addDoc, updateDoc, deleteDoc, doc, query, where, orderBy, setDoc } = require('firebase/firestore');

const app = express();

// --- AGREGAR: Importar Firebase Admin SDK ---
const admin = require('firebase-admin');

// --- AGREGAR: Inicializar Firebase Admin SDK ---
// Asegúrate de tener el archivo serviceAccountKey.json en tu proyecto
let serviceAccount;
try {
    serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log("Firebase Admin SDK inicializado correctamente.");
} catch (error) {
    console.error("Error al inicializar Firebase Admin SDK. Asegúrate de tener el archivo serviceAccountKey.json:", error.message);
    // Puedes optar por detener el servidor aquí si es crítico
    // process.exit(1);
}

// Configuración de Firebase Cliente (para operaciones que no requieren autenticación de admin)
const firebaseClientConfig = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID
};

// Inicializar Firebase Cliente
const firebaseClientApp = initializeClientApp(firebaseClientConfig);
const db = getFirestore(firebaseClientApp); // Usar Firestore del cliente

// Configuración de EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuración de CORS
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://127.0.0.1:3000',
            'http://127.0.0.1:5500',
            'http://localhost:5500',
            'http://127.0.0.1:5501',
            'http://localhost:5501',
            'http://localhost:3000',
            'https://lilcoiffeurv2-production.up.railway.app', // Asegúrate de que no haya espacios
            // Agrega aquí el dominio de tu frontend en cPanel cuando lo tengas
            // 'https://tu-dominio-de-cpanel.com'
        ];
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('No permitido por CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// --- AGREGAR: Middleware para verificar token de Firebase ---
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Acceso denegado. Token no proporcionado o formato incorrecto (Bearer <token>).', code: 'missing_token' });
    }

    const idToken = authHeader.split('Bearer ')[1];

    try {
        // Verificar el token ID de Firebase
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        // Agregar información del usuario al objeto req para usarla en las rutas
        req.user = decodedToken;
        console.log(`Usuario autenticado: ${decodedToken.email || decodedToken.uid}`);
        next();
    } catch (error) {
        console.error('Error al verificar token de Firebase:', error);
        if (error.code === 'auth/argument-error' || error.code === 'auth/id-token-expired' || error.code === 'auth/invalid-id-token') {
            return res.status(401).json({ error: 'Token inválido o expirado.', code: 'invalid_token' });
        }
        return res.status(500).json({ error: 'Error interno al verificar autenticación.', code: 'auth_error' });
    }
};

// Rutas

// Página principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Panel de administración (Sirve el EJS, la autenticación se maneja en el frontend)
app.get('/admin', async (req, res) => {
    try {
        res.render('admin', {
            FIREBASE_API_KEY: process.env.FIREBASE_API_KEY,
            FIREBASE_AUTH_DOMAIN: process.env.FIREBASE_AUTH_DOMAIN,
            FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID,
            FIREBASE_STORAGE_BUCKET: process.env.FIREBASE_STORAGE_BUCKET,
            FIREBASE_MESSAGING_SENDER_ID: process.env.FIREBASE_MESSAGING_SENDER_ID,
            FIREBASE_APP_ID: process.env.FIREBASE_APP_ID
        });
    } catch (error) {
        console.error('Error al cargar panel admin:', error);
        res.status(500).send('Error al cargar el panel de administración');
    }
});

// --- MODIFICAR: Aplicar middleware verifyToken a las rutas que requieran autenticación ---

// API: Obtener barberos (Puede ser pública si se usa en el frontend)
app.get('/api/barberos', async (req, res) => {
    try {
        const barberosSnapshot = await getDocs(collection(db, 'barberos'));
        const barberos = [];
        barberosSnapshot.forEach((doc) => {
            barberos.push({ id: doc.id, ...doc.data() });
        });
        res.json(barberos);
    } catch (error) {
        console.error('Error al obtener barberos:', error);
        res.status(500).json({ error: 'Error al obtener barberos: ' + error.message });
    }
});

// API: Crear barbero (Protegida)
app.post('/api/barberos', verifyToken, async (req, res) => {
    try {
        const barbero = req.body;
        const docRef = await addDoc(collection(db, 'barberos'), barbero);
        res.status(201).json({ id: docRef.id, ...barbero });
    } catch (error) {
        console.error('Error al crear barbero:', error);
        res.status(500).json({ error: 'Error al crear barbero: ' + error.message });
    }
});

// API: Actualizar barbero (Protegida)
app.put('/api/barberos/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        const data = req.body;
        await updateDoc(doc(db, 'barberos', id), data);
        res.json({ success: true });
    } catch (error) {
        console.error('Error al actualizar barbero:', error);
        res.status(500).json({ error: 'Error al actualizar barbero: ' + error.message });
    }
});

// API: Eliminar barbero (Protegida)
app.delete('/api/barberos/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        await deleteDoc(doc(db, 'barberos', id));
        res.json({ success: true });
    } catch (error) {
        console.error('Error al eliminar barbero:', error);
        res.status(500).json({ error: 'Error al eliminar barbero: ' + error.message });
    }
});

// API: Obtener servicios (Puede ser pública si se usa en el frontend)
app.get('/api/servicios', async (req, res) => {
    try {
        const serviciosSnapshot = await getDocs(collection(db, 'servicios'));
        const servicios = [];
        serviciosSnapshot.forEach((doc) => {
            servicios.push({ id: doc.id, ...doc.data() });
        });
        res.json(servicios);
    } catch (error) {
        console.error('Error al obtener servicios:', error);
        res.status(500).json({ error: 'Error al obtener servicios: ' + error.message });
    }
});

// API: Crear servicio (Protegida)
app.post('/api/servicios', verifyToken, async (req, res) => {
    try {
        const servicio = req.body;
        const docRef = await addDoc(collection(db, 'servicios'), servicio);
        res.status(201).json({ id: docRef.id, ...servicio });
    } catch (error) {
        console.error('Error al crear servicio:', error);
        res.status(500).json({ error: 'Error al crear servicio: ' + error.message });
    }
});

// API: Actualizar servicio (Protegida)
app.put('/api/servicios/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        const data = req.body;
        await updateDoc(doc(db, 'servicios', id), data);
        res.json({ success: true });
    } catch (error) {
        console.error('Error al actualizar servicio:', error);
        res.status(500).json({ error: 'Error al actualizar servicio: ' + error.message });
    }
});

// API: Eliminar servicio (Protegida)
app.delete('/api/servicios/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        await deleteDoc(doc(db, 'servicios', id));
        res.json({ success: true });
    } catch (error) {
        console.error('Error al eliminar servicio:', error);
        res.status(500).json({ error: 'Error al eliminar servicio: ' + error.message });
    }
});

// API: Obtener disponibilidad de un barbero (Puede ser pública)
app.get('/api/disponibilidad/:barberoId', async (req, res) => {
    try {
        const barberoId = req.params.barberoId;
        const q = query(
            collection(db, 'horarios'),
            where('barberoId', '==', barberoId),
            where('estado', '==', 'disponible'),
            orderBy('fechaHora')
        );

        const horariosSnapshot = await getDocs(q);
        const horarios = [];
        horariosSnapshot.forEach((doc) => {
            horarios.push({ id: doc.id, ...doc.data() });
        });

        res.json(horarios);
    } catch (error) {
        console.error('Error al obtener disponibilidad:', error);
        res.status(500).json({ error: 'Error al obtener disponibilidad: ' + error.message });
    }
});

// API: Crear reserva (Puede ser pública para clientes)
app.post('/api/reservas', async (req, res) => {
    try {
        const { nombre, celular, servicio, barberoId, horarioId } = req.body;

        if (!nombre || !celular || !servicio || !barberoId || !horarioId) {
            return res.status(400).json({ error: 'Faltan datos requeridos' });
        }

        const reserva = {
            nombre,
            celular,
            servicio,
            barberoId,
            horarioId,
            estado: 'pendiente',
            fechaCreacion: new Date()
        };

        const reservaRef = await addDoc(collection(db, 'reservas'), reserva);

        const horarioDocRef = doc(db, 'horarios', horarioId);
        try {
            await updateDoc(horarioDocRef, {
                estado: 'ocupado',
                reservaId: reservaRef.id
            });
        } catch (error) {
            if (error.code === 'not-found' || error.code === 13) {
                await setDoc(horarioDocRef, {
                    barberoId: barberoId,
                    fechaHora: horarioId,
                    estado: 'ocupado',
                    reservaId: reservaRef.id
                });
            } else {
                throw error;
            }
        }

        res.status(201).json({ id: reservaRef.id, ...reserva });
    } catch (error) {
        console.error('Error al crear reserva:', error);
        res.status(500).json({ error: 'Error al crear reserva: ' + error.message });
    }
});

// API: Obtener reservas para admin (Protegida)
// API: Obtener reservas para admin (Protegida) - Versión corregida
app.get('/api/reservas', verifyToken, async (req, res) => {
    try {
        console.log("Iniciando solicitud a /api/reservas"); // <-- Log para debugging
        const reservasSnapshot = await getDocs(collection(db, 'reservas'));
        console.log(`Obtenidos ${reservasSnapshot.size} documentos`); // <-- Log para debugging
        const reservas = [];
        reservasSnapshot.forEach((doc) => {
            console.log(`Procesando documento ID: ${doc.id}`); // <-- Log para debugging
            const data = doc.data();
            
            // Convertir campos de fecha a cadenas ISO para asegurar la serialización
            const processedData = {
                id: doc.id,
                ...data,
                // Asegúrate de convertir cualquier campo Date a string
                // Ajusta los nombres de los campos según tu estructura real
                ...(data.fechaCreacion && data.fechaCreacion.toDate ? 
                    { fechaCreacion: data.fechaCreacion.toDate().toISOString() } : 
                    {}),
                ...(data.horarioId && typeof data.horarioId === 'object' && data.horarioId.toDate ? 
                    { horarioId: data.horarioId.toDate().toISOString() } : 
                    {})
                // Agrega más conversiones si es necesario para otros campos de tipo Timestamp
            };
            
            reservas.push(processedData);
        });
        console.log("Documentos procesados, enviando respuesta"); // <-- Log para debugging
        res.json(reservas);
    } catch (error) {
        console.error('Error DETALLADO al obtener reservas en /api/reservas:', error); // <-- Log más detallado
        res.status(500).json({ 
            error: 'Error interno del servidor al obtener reservas.',
            message: error.message // Puedes quitar esto en producción si consideras que expone información sensible
        });
    }
});

// API: Actualizar estado de reserva (Protegida)
app.put('/api/reservas/:id', verifyToken, async (req, res) => {
    try {
        const reservaId = req.params.id;
        const { estado } = req.body;

        if (!['pendiente', 'confirmado', 'rechazado'].includes(estado)) {
            return res.status(400).json({ error: 'Estado inválido' });
        }

        await updateDoc(doc(db, 'reservas', reservaId), { estado });

        if (estado === 'rechazado') {
            try {
                const reservaDocSnap = await getDocs(doc(db, 'reservas', reservaId));
                if (reservaDocSnap.exists()) {
                    const reservaData = reservaDocSnap.data();
                    if (reservaData.horarioId) {
                        const horarioDocRef = doc(db, 'horarios', reservaData.horarioId);
                        try {
                            await updateDoc(horarioDocRef, {
                                estado: 'disponible',
                                reservaId: null
                            });
                        } catch (horarioError) {
                            if (horarioError.code === 'not-found' || horarioError.code === 13) {
                                await setDoc(horarioDocRef, {
                                    barberoId: reservaData.barberoId,
                                    fechaHora: reservaData.horarioId,
                                    estado: 'disponible',
                                    reservaId: null
                                });
                            } else {
                                throw horarioError;
                            }
                        }
                    }
                }
            } catch (horarioError) {
                console.error('Error al actualizar/liberar horario:', horarioError);
            }
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error al actualizar reserva:', error);
        res.status(500).json({ error: 'Error al actualizar reserva: ' + error.message });
    }
});

// API: Crear bloqueo de disponibilidad (Protegida)
app.post('/api/bloqueos', verifyToken, async (req, res) => {
    try {
        const { barberoId, fecha, motivo } = req.body;

        if (!barberoId || !fecha || !motivo) {
            return res.status(400).json({ error: 'Faltan datos requeridos' });
        }

        if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
            return res.status(400).json({ error: 'Formato de fecha inválido. Use YYYY-MM-DD' });
        }

        const bloqueo = {
            barberoId,
            fecha,
            motivo,
            tipo: 'bloqueo',
            createdAt: new Date()
        };

        const docRef = await addDoc(collection(db, 'bloqueos'), bloqueo);
        res.status(201).json({ id: docRef.id, ...bloqueo });
    } catch (error) {
        console.error('Error al crear bloqueo:', error);
        res.status(500).json({ error: 'Error al crear bloqueo: ' + error.message });
    }
});

// API: Eliminar bloqueo de disponibilidad (Protegida)
app.delete('/api/bloqueos/:id', verifyToken, async (req, res) => {
    try {
        const id = req.params.id;

        if (!id) {
            return res.status(400).json({ error: 'ID de bloqueo requerido' });
        }

        await deleteDoc(doc(db, 'bloqueos', id));
        res.json({ success: true });
    } catch (error) {
        console.error('Error al eliminar bloqueo:', error);
        res.status(500).json({ error: 'Error al eliminar bloqueo: ' + error.message });
    }
});

// API: Obtener bloqueos de un barbero en un rango de fechas (Puede ser pública o protegida)
app.get('/api/bloqueos/:barberoId', verifyToken, async (req, res) => {
    try {
        const barberoId = req.params.barberoId;
        const { fechaInicio, fechaFin } = req.query;

        if (!barberoId) {
            return res.status(400).json({ error: 'ID de barbero requerido' });
        }

        let q = query(
            collection(db, 'bloqueos'),
            where('barberoId', '==', barberoId)
        );

        if (fechaInicio && fechaFin) {
            if (!/^\d{4}-\d{2}-\d{2}$/.test(fechaInicio) || !/^\d{4}-\d{2}-\d{2}$/.test(fechaFin)) {
                return res.status(400).json({ error: 'Formato de fecha inválido. Use YYYY-MM-DD' });
            }

            q = query(
                q,
                where('fecha', '>=', fechaInicio),
                where('fecha', '<=', fechaFin)
            );
        }

        const bloqueosSnapshot = await getDocs(q);
        const bloqueos = [];
        bloqueosSnapshot.forEach((doc) => {
            bloqueos.push({ id: doc.id, ...doc.data() });
        });

        res.json(bloqueos);
    } catch (error) {
        console.error('Error al obtener bloqueos:', error);
        res.status(500).json({ error: 'Error al obtener bloqueos: ' + error.message });
    }
});

// API: Generar horarios automáticos para un barbero en una fecha (Puede ser pública)
app.get('/api/horarios/:barberoId/:fecha', async (req, res) => {
    try {
        const { barberoId, fecha } = req.params;

        if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
            return res.status(400).json({ error: 'Formato de fecha inválido' });
        }

        const fechaSeleccionada = new Date(fecha);
        const hoy = new Date();
        hoy.setHours(0, 0, 0, 0);

        if (fechaSeleccionada < hoy) {
            return res.json([]);
        }

        const diaSemana = fechaSeleccionada.getDay();
        if (diaSemana === 0 || diaSemana === 6) {
            return res.json([]);
        }

        const bloqueosQuery = query(
            collection(db, 'bloqueos'),
            where('barberoId', '==', barberoId),
            where('fecha', '==', fecha)
        );

        const bloqueosSnapshot = await getDocs(bloqueosQuery);
        if (!bloqueosSnapshot.empty) {
            return res.json([]);
        }

        const horarios = [];
        for (let hora = 10; hora <= 18; hora++) {
            const horaCompleta = `${hora.toString().padStart(2, '0')}:00`;
            const fechaHora = `${fecha}T${horaCompleta}:00`;

            const horariosQuery = query(
                collection(db, 'horarios'),
                where('barberoId', '==', barberoId),
                where('fechaHora', '==', fechaHora),
                where('estado', '==', 'ocupado')
            );

            const horariosSnapshot = await getDocs(horariosQuery);
            if (horariosSnapshot.empty) {
                horarios.push({
                    barberoId,
                    fechaHora,
                    estado: 'disponible'
                });
            }
        }

        res.json(horarios);
    } catch (error) {
        console.error('Error al generar horarios:', error);
        res.status(500).json({ error: 'Error al generar horarios: ' + error.message });
    }
});

// API: Obtener reservas por fecha (Puede ser pública)
app.get('/api/reservas-por-fecha/:barberoId/:fecha', async (req, res) => {
    try {
        const { barberoId, fecha } = req.params;

        if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
            return res.status(400).json({ error: 'Formato de fecha inválido' });
        }

        const fechaInicio = new Date(`${fecha}T00:00:00`);
        const fechaFin = new Date(`${fecha}T23:59:59`);

        const q = query(
            collection(db, 'reservas'),
            where('barberoId', '==', barberoId),
            where('horarioId', '>=', fechaInicio.toISOString()),
            where('horarioId', '<=', fechaFin.toISOString()),
            where('estado', 'in', ['pendiente', 'confirmado'])
        );

        const reservasSnapshot = await getDocs(q);
        const reservas = [];
        reservasSnapshot.forEach((doc) => {
            reservas.push({ id: doc.id, ...doc.data() });
        });

        res.json(reservas);
    } catch (error) {
        console.error('Error al obtener reservas por fecha:', error);
        res.status(500).json({ error: 'Error al obtener reservas por fecha: ' + error.message });
    }
});

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
