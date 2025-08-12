// app.js (reserva con Admin SDK + rutas limpias)
require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');

// ---------------- SDK Cliente (para lecturas públicas que respetan reglas)
const { initializeApp: initClient } = require('firebase/app');
const {
  getFirestore,
  collection,
  getDocs,
  query,
  where,
  orderBy,
  doc
} = require('firebase/firestore');

// ---------------- SDK Admin (para escrituras/lecturas protegidas – ignora reglas)
const admin = require('firebase-admin');

const app = express();

// --------- Inicializar Firebase Admin
let adminInitialized = false;
try {
  if (!admin.apps.length) {
    const svc = {
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
    if (!svc.project_id || !svc.private_key || !svc.client_email) {
      throw new Error('Faltan variables de entorno del Admin SDK');
    }
    admin.initializeApp({ credential: admin.credential.cert(svc) });
    console.log('Admin SDK inicializado.');
  }
  adminInitialized = true;
} catch (e) {
  console.error('Error inicializando Admin SDK:', e.message);
}
const adb = adminInitialized ? admin.firestore() : null;

// --------- Inicializar Firebase Cliente (para lecturas públicas)
const clientConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID
};
const clientApp = initClient(clientConfig);
const db = getFirestore(clientApp);

// --------- App base
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS (ajustá tu dominio)
const corsOptions = {
  origin: (origin, cb) => {
    const ok = [
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
    if (!origin || ok.includes(origin)) return cb(null, true);
    cb(new Error('Origen no permitido por CORS'));
  },
  credentials: true
};
app.use(cors(corsOptions));

// Rutas limpias
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (_, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/index.html', (_, res) => res.redirect('/'));
app.get('/admin.html', (_, res) => res.redirect('/admin'));

// --------- Middleware auth (para endpoints de admin)
const verifyToken = async (req, res, next) => {
  if (!adb) return res.status(500).json({ error: 'Admin no inicializado' });
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token faltante o mal formado', code: 'missing_token' });
  }
  const idToken = authHeader.slice(7);
  try {
    req.user = await admin.auth().verifyIdToken(idToken);
    next();
  } catch (e) {
    console.error('verifyIdToken:', e);
    return res.status(401).json({ error: 'Token inválido o expirado', code: 'invalid_token' });
  }
};

// ====================== BARBEROS ======================
// Pública (lectura con SDK cliente – respeta reglas)
app.get('/api/barberos', async (_req, res) => {
  try {
    const snap = await getDocs(collection(db, 'barberos'));
    res.json(snap.docs.map(d => ({ id: d.id, ...d.data() })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error al obtener barberos: ' + e.message });
  }
});

// Admin
app.post('/api/barberos', verifyToken, async (req, res) => {
  try {
    const ref = await adb.collection('barberos').add(req.body);
    res.status(201).json({ id: ref.id, ...req.body });
  } catch (e) {
    res.status(500).json({ error: 'Error al crear barbero: ' + e.message });
  }
});
app.put('/api/barberos/:id', verifyToken, async (req, res) => {
  try {
    await adb.collection('barberos').doc(req.params.id).update(req.body);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al actualizar barbero: ' + e.message });
  }
});
app.delete('/api/barberos/:id', verifyToken, async (req, res) => {
  try {
    await adb.collection('barberos').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al eliminar barbero: ' + e.message });
  }
});

// ====================== SERVICIOS ======================
// Pública
app.get('/api/servicios', async (_req, res) => {
  try {
    const snap = await getDocs(collection(db, 'servicios'));
    res.json(snap.docs.map(d => ({ id: d.id, ...d.data() })));
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener servicios: ' + e.message });
  }
});

// Admin
app.post('/api/servicios', verifyToken, async (req, res) => {
  try {
    const ref = await adb.collection('servicios').add(req.body);
    res.status(201).json({ id: ref.id, ...req.body });
  } catch (e) {
    res.status(500).json({ error: 'Error al crear servicio: ' + e.message });
  }
});
app.put('/api/servicios/:id', verifyToken, async (req, res) => {
  try {
    await adb.collection('servicios').doc(req.params.id).update(req.body);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al actualizar servicio: ' + e.message });
  }
});
app.delete('/api/servicios/:id', verifyToken, async (req, res) => {
  try {
    await adb.collection('servicios').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al eliminar servicio: ' + e.message });
  }
});

// ================== HORARIOS / DISPONIBILIDAD (público) ==================
app.get('/api/disponibilidad/:barberoId', async (req, res) => {
  try {
    const qy = query(
      collection(db, 'horarios'),
      where('barberoId', '==', req.params.barberoId),
      where('estado', '==', 'disponible'),
      orderBy('fechaHora')
    );
    const snap = await getDocs(qy);
    res.json(snap.docs.map(d => ({ id: d.id, ...d.data() })));
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener disponibilidad: ' + e.message });
  }
});

// Generador simple de horarios filtrando los ocupados y bloqueos
app.get('/api/horarios/:barberoId/:fecha', async (req, res) => {
  try {
    const { barberoId, fecha } = req.params;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
      return res.status(400).json({ error: 'Fecha inválida (YYYY-MM-DD)' });
    }

    const fechaSel = new Date(fecha);
    const hoy = new Date(); hoy.setHours(0,0,0,0);
    if (fechaSel < hoy) return res.json([]);

    const dow = fechaSel.getDay();
    if (dow === 0 || dow === 6) return res.json([]); // domingo/sábado fuera

    // Bloqueos
    const bloqQ = query(
      collection(db, 'bloqueos'),
      where('barberoId', '==', barberoId),
      where('fecha', '==', fecha)
    );
    const bloqSnap = await getDocs(bloqQ);
    if (!bloqSnap.empty) return res.json([]);

    // Producir slots de 10:00 a 18:00
    const horarios = [];
    for (let h = 10; h <= 18; h++) {
      const hh = `${String(h).padStart(2,'0')}:00`;
      const fechaHora = `${fecha}T${hh}:00`;

      const ocQ = query(
        collection(db, 'horarios'),
        where('barberoId', '==', barberoId),
        where('fechaHora', '==', fechaHora),
        where('estado', '==', 'ocupado')
      );
      const ocSnap = await getDocs(ocQ);
      if (ocSnap.empty) {
        horarios.push({ barberoId, fechaHora, estado: 'disponible' });
      }
    }
    res.json(horarios);
  } catch (e) {
    res.status(500).json({ error: 'Error al generar horarios: ' + e.message });
  }
});

// ====================== RESERVAS ======================
// Crear reserva (PÚBLICO) usando ADMIN SDK + transacción atómica
app.post('/api/reservas', async (req, res) => {
  try {
    if (!adb) return res.status(500).json({ error: 'Admin no inicializado' });

    const { nombre, celular, servicio, barberoId, horarioId } = req.body;
    if (!nombre || !celular || !servicio || !barberoId || !horarioId) {
      return res.status(400).json({ error: 'Faltan datos requeridos' });
    }

    let nuevaReservaId = null;
    const hRef = adb.collection('horarios').doc(horarioId); // usamos ISO como id

    await adb.runTransaction(async (t) => {
      const hSnap = await t.get(hRef);
      if (hSnap.exists && hSnap.data()?.estado === 'ocupado') {
        throw new Error('CONFLICT_SLOT');
      }

      const rRef = adb.collection('reservas').doc();
      const reserva = {
        nombre, celular, servicio, barberoId, horarioId,
        estado: 'pendiente',
        fechaCreacion: admin.firestore.FieldValue.serverTimestamp()
      };
      t.set(rRef, reserva);

      t.set(hRef, {
        barberoId,
        fechaHora: horarioId,
        estado: 'ocupado',
        reservaId: rRef.id
      }, { merge: true });

      nuevaReservaId = rRef.id;
    });

    return res.status(201).json({
      id: nuevaReservaId,
      nombre, celular, servicio, barberoId, horarioId, estado: 'pendiente'
    });
  } catch (e) {
    if (e.message === 'CONFLICT_SLOT') {
      return res.status(409).json({ error: 'Ese horario ya fue reservado' });
    }
    console.error('POST /api/reservas', e);
    res.status(500).json({ error: 'Error al crear reserva: ' + e.message });
  }
});

// Listar reservas (ADMIN)
app.get('/api/reservas', verifyToken, async (_req, res) => {
  try {
    const snap = await adb.collection('reservas').get();
    const out = snap.docs.map(d => {
      const data = d.data();
      return {
        id: d.id,
        ...data,
        fechaCreacion: data.fechaCreacion instanceof admin.firestore.Timestamp
          ? data.fechaCreacion.toDate().toISOString() : data.fechaCreacion
      };
    });
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener reservas: ' + e.message });
  }
});

// Actualizar estado (ADMIN) y liberar horario si se rechaza
app.put('/api/reservas/:id', verifyToken, async (req, res) => {
  try {
    const { estado } = req.body;
    if (!['pendiente','confirmado','rechazado'].includes(estado)) {
      return res.status(400).json({ error: 'Estado inválido' });
    }

    const rRef = adb.collection('reservas').doc(req.params.id);
    await rRef.update({ estado });

    if (estado === 'rechazado') {
      const rSnap = await rRef.get();
      if (rSnap.exists) {
        const r = rSnap.data();
        if (r.horarioId) {
          const hRef = adb.collection('horarios').doc(r.horarioId);
          await hRef.set({
            estado: 'disponible',
            reservaId: admin.firestore.FieldValue.delete(),
            barberoId: r.barberoId,
            fechaHora: r.horarioId
          }, { merge: true });
        }
      }
    }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al actualizar reserva: ' + e.message });
  }
});

// Reservas por fecha (PÚBLICO) usando ADMIN pero devolviendo SOLO horarioId
app.get('/api/reservas-por-fecha/:barberoId/:fecha', async (req, res) => {
  try {
    if (!adb) return res.status(500).json({ error: 'Admin no inicializado' });
    const { barberoId, fecha } = req.params;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) {
      return res.status(400).json({ error: 'Fecha inválida (YYYY-MM-DD)' });
    }
    const inicio = new Date(`${fecha}T00:00:00.000Z`).toISOString();
    const fin    = new Date(`${fecha}T23:59:59.999Z`).toISOString();

    const snap = await adb.collection('reservas')
      .where('barberoId', '==', barberoId)
      .where('horarioId', '>=', inicio)
      .where('horarioId', '<=', fin)
      .where('estado', 'in', ['pendiente', 'confirmado'])
      .get();

    const ocupados = snap.docs.map(d => d.data().horarioId).filter(Boolean);
    res.json(ocupados);
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener reservas por fecha: ' + e.message });
  }
});

// ====================== BLOQUEOS (ADMIN para escribir, leer protegido en panel) ======================
app.post('/api/bloqueos', verifyToken, async (req, res) => {
  try {
    const { barberoId, fecha, motivo } = req.body;
    if (!barberoId || !fecha || !motivo) return res.status(400).json({ error: 'Faltan datos' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) return res.status(400).json({ error: 'Fecha inválida' });

    const payload = { barberoId, fecha, motivo, tipo: 'bloqueo', createdAt: new Date() };
    const ref = await adb.collection('bloqueos').add(payload);
    res.status(201).json({ id: ref.id, ...payload });
  } catch (e) {
    res.status(500).json({ error: 'Error al crear bloqueo: ' + e.message });
  }
});

app.delete('/api/bloqueos/:id', verifyToken, async (req, res) => {
  try {
    await adb.collection('bloqueos').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al eliminar bloqueo: ' + e.message });
  }
});

// Lectura de bloqueos para el panel (ADMIN)
app.get('/api/bloqueos/:barberoId', verifyToken, async (req, res) => {
  try {
    let q = adb.collection('bloqueos').where('barberoId', '==', req.params.barberoId);
    const { fechaInicio, fechaFin } = req.query;
    if (fechaInicio && fechaFin) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(fechaInicio) || !/^\d{4}-\d{2}-\d{2}$/.test(fechaFin)) {
        return res.status(400).json({ error: 'Rango de fecha inválido' });
      }
      q = q.where('fecha', '>=', fechaInicio).where('fecha', '<=', fechaFin);
    }
    const snap = await q.get();
    res.json(snap.docs.map(d => ({ id: d.id, ...d.data() })));
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener bloqueos: ' + e.message });
  }
});

// --------- Puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));
