require('dotenv').config();
const express = require('express');
const path = require('path');
const { initializeApp } = require('firebase/app');
const { getFirestore, collection, getDocs, addDoc, updateDoc, deleteDoc, doc, query, where, orderBy, setDoc } = require('firebase/firestore');

const app = express();

// Configuración de Firebase
const firebaseConfig = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID
};

// Inicializar Firebase
const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);

// Configuración de EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rutas

// Página principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Panel de administración
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

// API: Obtener barberos
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

// API: Crear barbero
app.post('/api/barberos', async (req, res) => {
    try {
        const barbero = req.body;
        const docRef = await addDoc(collection(db, 'barberos'), barbero);
        res.status(201).json({ id: docRef.id, ...barbero });
    } catch (error) {
        console.error('Error al crear barbero:', error);
        res.status(500).json({ error: 'Error al crear barbero: ' + error.message });
    }
});

// API: Actualizar barbero
app.put('/api/barberos/:id', async (req, res) => {
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

// API: Eliminar barbero
app.delete('/api/barberos/:id', async (req, res) => {
    try {
        const id = req.params.id;
        await deleteDoc(doc(db, 'barberos', id));
        res.json({ success: true });
    } catch (error) {
        console.error('Error al eliminar barbero:', error);
        res.status(500).json({ error: 'Error al eliminar barbero: ' + error.message });
    }
});

// API: Obtener servicios
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

// API: Crear servicio
app.post('/api/servicios', async (req, res) => {
    try {
        const servicio = req.body;
        const docRef = await addDoc(collection(db, 'servicios'), servicio);
        res.status(201).json({ id: docRef.id, ...servicio });
    } catch (error) {
        console.error('Error al crear servicio:', error);
        res.status(500).json({ error: 'Error al crear servicio: ' + error.message });
    }
});

// API: Actualizar servicio
app.put('/api/servicios/:id', async (req, res) => {
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

// API: Eliminar servicio
app.delete('/api/servicios/:id', async (req, res) => {
    try {
        const id = req.params.id;
        await deleteDoc(doc(db, 'servicios', id));
        res.json({ success: true });
    } catch (error) {
        console.error('Error al eliminar servicio:', error);
        res.status(500).json({ error: 'Error al eliminar servicio: ' + error.message });
    }
});

// API: Obtener disponibilidad de un barbero
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

// API: Crear reserva
app.post('/api/reservas', async (req, res) => {
    try {
        const { nombre, celular, servicio, barberoId, horarioId } = req.body;
        
        // Validar datos requeridos
        if (!nombre || !celular || !servicio || !barberoId || !horarioId) {
            return res.status(400).json({ error: 'Faltan datos requeridos' });
        }
        
        // Crear reserva
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
        
        // Verificar si el documento de horario existe, si no, crearlo
        const horarioDocRef = doc(db, 'horarios', horarioId);
        try {
            // Intentar obtener el documento
            await getDocs(horarioDocRef);
            // Si existe, actualizarlo
            await updateDoc(horarioDocRef, {
                estado: 'ocupado',
                reservaId: reservaRef.id
            });
        } catch (error) {
            // Si no existe, crearlo
            await setDoc(horarioDocRef, {
                barberoId: barberoId,
                fechaHora: horarioId,
                estado: 'ocupado',
                reservaId: reservaRef.id
            });
        }
        
        res.status(201).json({ id: reservaRef.id, ...reserva });
    } catch (error) {
        console.error('Error al crear reserva:', error);
        res.status(500).json({ error: 'Error al crear reserva: ' + error.message });
    }
});

// API: Obtener reservas para admin
app.get('/api/reservas', async (req, res) => {
    try {
        const reservasSnapshot = await getDocs(collection(db, 'reservas'));
        const reservas = [];
        reservasSnapshot.forEach((doc) => {
            reservas.push({ id: doc.id, ...doc.data() });
        });
        res.json(reservas);
    } catch (error) {
        console.error('Error al obtener reservas:', error);
        res.status(500).json({ error: 'Error al obtener reservas: ' + error.message });
    }
});

// API: Actualizar estado de reserva
app.put('/api/reservas/:id', async (req, res) => {
    try {
        const reservaId = req.params.id;
        const { estado } = req.body;
        
        // Validar estado
        if (!['pendiente', 'confirmado', 'rechazado'].includes(estado)) {
            return res.status(400).json({ error: 'Estado inválido' });
        }
        
        // Actualizar estado de reserva
        await updateDoc(doc(db, 'reservas', reservaId), { estado });
        
        // Si se rechaza, liberar el horario
        if (estado === 'rechazado') {
            try {
                const reservaDocRef = doc(db, 'reservas', reservaId);
                const reservaDoc = await getDocs(reservaDocRef);
                if (reservaDoc.exists()) {
                    const reserva = reservaDoc.data();
                    if (reserva.horarioId) {
                        const horarioDocRef = doc(db, 'horarios', reserva.horarioId);
                        try {
                            // Verificar si el documento existe
                            await getDocs(horarioDocRef);
                            // Si existe, actualizarlo
                            await updateDoc(horarioDocRef, {
                                estado: 'disponible',
                                reservaId: null
                            });
                        } catch (horarioError) {
                            // Si no existe, crearlo como disponible
                            await setDoc(horarioDocRef, {
                                barberoId: reserva.barberoId,
                                fechaHora: reserva.horarioId,
                                estado: 'disponible',
                                reservaId: null
                            });
                        }
                    }
                }
            } catch (horarioError) {
                console.error('Error al actualizar horario:', horarioError);
                // No detener la operación principal por error en horario
            }
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error al actualizar reserva:', error);
        res.status(500).json({ error: 'Error al actualizar reserva: ' + error.message });
    }
});

// API: Crear bloqueo de disponibilidad
app.post('/api/bloqueos', async (req, res) => {
    try {
        const { barberoId, fecha, motivo } = req.body;
        
        // Validar datos requeridos
        if (!barberoId || !fecha || !motivo) {
            return res.status(400).json({ error: 'Faltan datos requeridos' });
        }
        
        // Validar formato de fecha (YYYY-MM-DD)
        if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
            return res.status(400).json({ error: 'Formato de fecha inválido. Use YYYY-MM-DD' });
        }
        
        // Crear bloqueo
        const bloqueo = {
            barberoId,
            fecha, // Mantener como string para evitar problemas de zona horaria
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

// API: Eliminar bloqueo de disponibilidad
app.delete('/api/bloqueos/:id', async (req, res) => {
    try {
        const id = req.params.id;
        
        // Validar ID
        if (!id) {
            return res.status(400).json({ error: 'ID de bloqueo requerido' });
        }
        
        // Eliminar bloqueo
        await deleteDoc(doc(db, 'bloqueos', id));
        res.json({ success: true });
    } catch (error) {
        console.error('Error al eliminar bloqueo:', error);
        res.status(500).json({ error: 'Error al eliminar bloqueo: ' + error.message });
    }
});

// API: Obtener bloqueos de un barbero en un rango de fechas
app.get('/api/bloqueos/:barberoId', async (req, res) => {
    try {
        const barberoId = req.params.barberoId;
        const { fechaInicio, fechaFin } = req.query;
        
        // Validar que barberoId sea válido
        if (!barberoId) {
            return res.status(400).json({ error: 'ID de barbero requerido' });
        }
        
        let q = query(
            collection(db, 'bloqueos'),
            where('barberoId', '==', barberoId)
        );
        
        // Solo aplicar filtros de fecha si se proporcionan y tienen formato válido
        if (fechaInicio && fechaFin) {
            // Validar formato de fechas
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

// API: Generar horarios automáticos para un barbero en una fecha
app.get('/api/horarios/:barberoId/:fecha', async (req, res) => {
    try {
        const { barberoId, fecha } = req.params;
        
        // Validar formato de fecha
        if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
            return res.status(400).json({ error: 'Formato de fecha inválido' });
        }
        
        // Verificar si la fecha ya pasó
        const fechaSeleccionada = new Date(fecha);
        const hoy = new Date();
        hoy.setHours(0, 0, 0, 0);
        
        if (fechaSeleccionada < hoy) {
            return res.json([]);
        }
        
        // Verificar si es fin de semana (sábado = 6, domingo = 0)
        const diaSemana = fechaSeleccionada.getDay();
        if (diaSemana === 0 || diaSemana === 6) {
            return res.json([]);
        }
        
        // Verificar si hay bloqueos para ese día
        const bloqueosQuery = query(
            collection(db, 'bloqueos'),
            where('barberoId', '==', barberoId),
            where('fecha', '==', fecha)
        );
        
        const bloqueosSnapshot = await getDocs(bloqueosQuery);
        if (!bloqueosSnapshot.empty) {
            // Hay bloqueo, no hay horarios disponibles
            return res.json([]);
        }
        
        // Generar horarios de 10:00 a 19:00 cada hora
        const horarios = [];
        for (let hora = 10; hora <= 18; hora++) {
            const horaCompleta = `${hora.toString().padStart(2, '0')}:00`;
            const fechaHora = `${fecha}T${horaCompleta}:00`;
            
            // Verificar si este horario ya está ocupado
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

// API: Obtener reservas por fecha (NUEVO ENDPOINT)
app.get('/api/reservas-por-fecha/:barberoId/:fecha', async (req, res) => {
    try {
        const { barberoId, fecha } = req.params;
        
        // Validar formato de fecha
        if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
            return res.status(400).json({ error: 'Formato de fecha inválido' });
        }
        
        // Crear rango de fechas para buscar reservas de ese día
        const fechaInicio = new Date(`${fecha}T00:00:00`);
        const fechaFin = new Date(`${fecha}T23:59:59`);
        
        // Buscar reservas confirmadas o pendientes para esa fecha
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