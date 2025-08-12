// app.js (migrado a Admin SDK y rutas limpias sin .html)
require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');

// SDK Cliente de Firebase (para endpoints públicos que respeten reglas)
const { initializeApp: initializeClientApp } = require('firebase/app');
const {
  getFirestore,
  collection,
  getDocs,
  addDoc,
  updateDoc,
  deleteDoc,
  doc,
  query,
  where,
  orderBy,
  setDoc,
  getDoc
} = require('firebase/firestore');

// SDK Admin de Firebase (para rutas protegidas - ignora reglas)
const admin = require('firebase-admin');

const app = express();

// --- Inicializar Firebase Admin SDK ---
let adminInitialized = false;
try {
  if (!admin.apps.length) {
    const serviceAccount = {
      type: 'service_account',
      project_id: process.env.FIREBASE_ADMIN_PROJECT_ID,
      private_key_id: process.env.FIREBASE_ADMIN_PRIVATE_KEY_ID,
      private_key: process.env.FIREBASE_ADMIN_PRIVATE_KEY?.replace(/\\n/g, '\n'),
      client_email: process.env.FIREBASE_ADMIN_CLIENT_EMAIL,
      client_id: process.env.FIREBASE_ADMIN_CLIENT_ID,
      auth_uri: 'https://accounts.google.com/o/oauth2/auth',
      token_uri: 'https://oauth2.googleapis.com/token',
      auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
      client_x509_cert_url: process.env.FIREBASE_ADMIN_CLIENT_CERT_URL
    };

    if (!serviceAccount.project_id || !serviceAccount.private_key || !serviceAccount.client_email) {
      throw new Error('Faltan variables de entorno críticas para Firebase Admin SDK');
    }

    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('Firebase Admin SDK inicializado correctamente.');
  }
  adminInitialized = true;
} catch (error) {
  console.error('Error CRÍTICO al inicializar Firebase Admin SDK:', error.message);
}

// Instancia de Firestore Admin (para rutas protegidas)
const adb = adminInitialized ? admin.firestore() : null;

// --- Inicializar Firebase Cliente ---
const firebaseClientConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID
};
const firebaseClientApp = initializeClientApp(firebaseClientConfig);
const db = getFirestore(firebaseClientApp); // Firestore (cliente) para endpoints públicos

// View engine (opcional)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5500',
      'http://localhost:5500',
      'http://127.0.0.1:5501',
      'http://localhost:5501',
      'http://localhost:3000',
      'https://lilcoiffeurv2-production.up.railway.app',
      'https://administrador.lilcoiffeur.uy',
      'https://prueba.lilcoiffeur.uy',
      'https://lilcoiffeur.uy/'
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

// --- Rutas "limpias" sin .html ---
// Index limpio
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
// Admin limpio
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
// Redirecciones opcionales desde .html a rutas limpias
app.get('/index.html', (req, res) => res.redirect('/'));
app.get('/admin.html', (req, res) => res.redirect('/admin'));

// --- Middleware de autenticación (Admin) ---
const verifyToken = async (req, res, next) => {
  if (!adminInitialized || !adb) {
    return res.status(500).json({ error: 'Firebase Admin no inicializado', code: 'admin_not_initialized' });
  }
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token faltante o mal formado', code: 'missing_token' });
  }
  const idToken = authHeader.slice(7);
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (e) {
    console.error('Error al verificar token de Firebase:', e);
    const authCodes = ['auth/argument-error', 'auth/id-token-expired', 'auth/invalid-id-token'];
    if (authCodes.includes(e.code)) {
      return res.status(401).json({ error: 'Token inválido o expirado', code: 'invalid_token' });
    }
    return res.status(500).json({ error: 'Error verificando token', code: 'auth_error' });
  }
};

// ======================
//  BARBEROS
// ======================
// GET (pública)
app.get('/api/barberos', async (req, res) => {
  try {
    const snap = await getDocs(collection(db, 'barberos'));
    const out = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(out);
  } catch (error) {
    console.error('Error al obtener barberos:', error);
    res.status(500).json({ error: 'Error al obtener barberos: ' + error.message });
  }
});

// POST (protegida - Admin)
app.post('/api/barberos', verifyToken, async (req, res) => {
  try {
    const data = req.body;
    const ref = await adb.collection('barberos').add(data);
    res.status(201).json({ id: ref.id, ...data });
  } catch (error) {
    console.error('Error al crear barbero:', error);
    res.status(500).json({ error: 'Error al crear barbero: ' + error.message });
  }
});

// PUT (protegida - Admin)
app.put('/api/barberos/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    await adb.collection('barberos').doc(id).update(req.body);
    res.json({ success: true });
  } catch (error) {
    console.error('Error al actualizar barbero:', error);
    res.status(500).json({ error: 'Error al actualizar barbero: ' + error.message });
  }
});

// DELETE (protegida - Admin)
app.delete('/api/barberos/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    await adb.collection('barberos').doc(id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Error al eliminar barbero:', error);
    res.status(500).json({ error: 'Error al eliminar barbero: ' + error.message });
  }
});

// ======================
//  SERVICIOS
// ======================
// GET (pública)
app.get('/api/servicios', async (req, res) => {
  try {
    const snap = await getDocs(collection(db, 'servicios'));
    const out = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(out);
  } catch (error) {
    console.error('Error al obtener servicios:', error);
    res.status(500).json({ error: 'Error al obtener servicios: ' + error.message });
  }
});

// POST (protegida - Admin)
app.post('/api/servicios', verifyToken, async (req, res) => {
  try {
    const data = req.body;
    const ref = await adb.collection('servicios').add(data);
    res.status(201).json({ id: ref.id, ...data });
  } catch (error) {
    console.error('Error al crear servicio:', error);
    res.status(500).json({ error: 'Error al crear servicio: ' + error.message });
  }
});

// PUT (protegida - Admin)
app.put('/api/servicios/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    await adb.collection('servicios').doc(id).update(req.body);
    res.json({ success: true });
  } catch (error) {
    console.error('Error al actualizar servicio:', error);
    res.status(500).json({ error: 'Error al actualizar servicio: ' + error.message });
  }
});

// DELETE (protegida - Admin)
app.delete('/api/servicios/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    await adb.collection('servicios').doc(id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Error al eliminar servicio:', error);
    res.status(500).json({ error: 'Error al eliminar servicio: ' + error.message });
  }
});

// ======================
//  DISPONIBILIDAD / HORARIOS (público)
// ======================
app.get('/api/disponibilidad/:barberoId', async (req, res) => {
  try {
    const barberoId = req.params.barberoId;
    const qy = query(
      collection(db, 'horarios'),
      where('barberoId', '==', barberoId),
      where('estado', '==', 'disponible'),
      orderBy('fechaHora')
    );
    const snap = await getDocs(qy);
    const out = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(out);
  } catch (error) {
    console.error('Error al obtener disponibilidad:', error);
    res.status(500).json({ error: 'Error al obtener disponibilidad: ' + error.message });
  }
});

app.get('/api/horarios/:barberoId/:fecha', async (req, res) => {
  try {
    const { barberoId, fecha } = req.params;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
      return res.status(400).json({ error: 'Formato de fecha inválido' });
    }

    const fechaSel = new Date(fecha);
    const hoy = new Date();
    hoy.setHours(0, 0, 0, 0);
    if (fechaSel < hoy) return res.json([]);

    const dia = fechaSel.getDay();
    if (dia === 0 || dia === 6) return res.json([]);

    const bloqueosQ = query(
      collection(db, 'bloqueos'),
      where('barberoId', '==', barberoId),
      where('fecha', '==', fecha)
    );
    const bloqueosSnap = await getDocs(bloqueosQ);
    if (!bloqueosSnap.empty) return res.json([]);

    const horarios = [];
    for (let h = 10; h <= 18; h++) {
      const hStr = `${h.toString().padStart(2, '0')}:00`;
      const fechaHora = `${fecha}T${hStr}:00`;
      const ocupadosQ = query(
        collection(db, 'horarios'),
        where('barberoId', '==', barberoId),
        where('fechaHora', '==', fechaHora),
        where('estado', '==', 'ocupado')
      );
      const ocSnap = await getDocs(ocupadosQ);
      if (ocSnap.empty) {
        horarios.push({ barberoId, fechaHora, estado: 'disponible' });
      }
    }
    res.json(horarios);
  } catch (error) {
    console.error('Error al generar horarios:', error);
    res.status(500).json({ error: 'Error al generar horarios: ' + error.message });
  }
});

// ======================
//  RESERVAS
// ======================
// Crear reserva (pública)
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

    // Guardar reserva (cliente, depende de reglas)
    const reservaRef = await addDoc(collection(db, 'reservas'), reserva);

    // Marcar horario como ocupado (si no existe, crearlo)
    const horarioDocRef = doc(db, 'horarios', horarioId);
    try {
      await updateDoc(horarioDocRef, { estado: 'ocupado', reservaId: reservaRef.id });
    } catch (err) {
      await setDoc(horarioDocRef, {
        barberoId,
        fechaHora: horarioId,
        estado: 'ocupado',
        reservaId: reservaRef.id
      }, { merge: true });
    }

    res.status(201).json({ id: reservaRef.id, ...reserva });
  } catch (error) {
    console.error('Error al crear reserva:', error);
    res.status(500).json({ error: 'Error al crear reserva: ' + error.message });
  }
});

// Obtener reservas (PROTEGIDA - Admin)
app.get('/api/reservas', verifyToken, async (req, res) => {
  try {
    const snap = await adb.collection('reservas').get();
    const reservas = snap.docs.map(d => {
      const data = d.data();
      return {
        id: d.id,
        ...data,
        fechaCreacion: data.fechaCreacion instanceof admin.firestore.Timestamp
          ? data.fechaCreacion.toDate().toISOString()
          : data.fechaCreacion,
        horarioId: data.horarioId instanceof admin.firestore.Timestamp
          ? data.horarioId.toDate().toISOString()
          : data.horarioId
      };
    });
    res.json(reservas);
  } catch (error) {
    console.error('Error DETALLADO al obtener reservas:', error);
    res.status(500).json({ error: 'Error interno del servidor al obtener reservas.', message: error.message });
  }
});

// Actualizar estado de reserva (PROTEGIDA - Admin)
app.put('/api/reservas/:id', verifyToken, async (req, res) => {
  try {
    const reservaId = req.params.id;
    const { estado } = req.body;
    if (!['pendiente', 'confirmado', 'rechazado'].includes(estado)) {
      return res.status(400).json({ error: 'Estado inválido' });
    }

    await adb.collection('reservas').doc(reservaId).update({ estado });

    if (estado === 'rechazado') {
      try {
        const reservaSnap = await adb.collection('reservas').doc(reservaId).get();
        if (reservaSnap.exists) {
          const r = reservaSnap.data();
          if (r.horarioId) {
            const hRef = adb.collection('horarios').doc(r.horarioId);
            await hRef.set({
              estado: 'disponible',
              reservaId: null,
              barberoId: r.barberoId,
              fechaHora: r.horarioId
            }, { merge: true });
          }
        }
      } catch (horarioError) {
        console.error('Error al liberar horario:', horarioError);
      }
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error al actualizar reserva:', error);
    res.status(500).json({ error: 'Error al actualizar reserva: ' + error.message });
  }
});

// Reservas por fecha (pública, lectura con SDK cliente)
app.get('/api/reservas-por-fecha/:barberoId/:fecha', async (req, res) => {
  try {
    const { barberoId, fecha } = req.params;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
      return res.status(400).json({ error: 'Formato de fecha inválido' });
    }
    const inicio = new Date(`${fecha}T00:00:00`).toISOString();
    const fin = new Date(`${fecha}T23:59:59`).toISOString();

    const qy = query(
      collection(db, 'reservas'),
      where('barberoId', '==', barberoId),
      where('horarioId', '>=', inicio),
      where('horarioId', '<=', fin),
      where('estado', 'in', ['pendiente', 'confirmado'])
    );
    const snap = await getDocs(qy);
    const out = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(out);
  } catch (error) {
    console.error('Error al obtener reservas por fecha:', error);
    res.status(500).json({ error: 'Error al obtener reservas por fecha: ' + error.message });
  }
});

// ======================
//  BLOQUEOS (Admin)
// ======================
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
    const ref = await adb.collection('bloqueos').add(bloqueo);
    res.status(201).json({ id: ref.id, ...bloqueo });
  } catch (error) {
    console.error('Error al crear bloqueo:', error);
    res.status(500).json({ error: 'Error al crear bloqueo: ' + error.message });
  }
});

app.delete('/api/bloqueos/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    await adb.collection('bloqueos').doc(id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Error al eliminar bloqueo:', error);
    res.status(500).json({ error: 'Error al eliminar bloqueo: ' + error.message });
  }
});

app.get('/api/bloqueos/:barberoId', verifyToken, async (req, res) => {
  try {
    const { barberoId } = req.params;
    const { fechaInicio, fechaFin } = req.query;
    if (!barberoId) return res.status(400).json({ error: 'ID de barbero requerido' });

    let qy = adb.collection('bloqueos').where('barberoId', '==', barberoId);
    if (fechaInicio && fechaFin) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(fechaInicio) || !/^\d{4}-\d{2}-\d{2}$/.test(fechaFin)) {
        return res.status(400).json({ error: 'Formato de fecha inválido. Use YYYY-MM-DD' });
      }
      qy = qy.where('fecha', '>=', fechaInicio).where('fecha', '<=', fechaFin);
    }

    const snap = await qy.get();
    const out = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(out);
  } catch (error) {
    console.error('Error al obtener bloqueos:', error);
    res.status(500).json({ error: 'Error al obtener bloqueos: ' + error.message });
  }
});

// Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
