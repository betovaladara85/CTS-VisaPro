const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const XLSX = require('xlsx');
const db = require('./db');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'visapro-secret-key-change-in-production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'visapro-session-secret-change-in-production';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'))
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });
app.use('/uploads', express.static(uploadsDir));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

// ---------- Session + Passport ----------
const pgPool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;

const PgSession = require('connect-pg-simple')(session);
const pgPool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;

app.use(session({
  store: pgPool ? new PgSession({ pool: pgPool, tableName: 'session', createTableIfMissing: true }) : new session.MemoryStore(),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  touch: true,
  cookie: {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax',
    secure: true,
    path: '/'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.findUserById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

if (process.env.GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
  }, async (accessToken, refreshToken, profile, done) => {
    console.log('=== PASSPORT GOOGLE STRATEGY ===', { 
      hasAccessToken: !!accessToken, 
      hasRefreshToken: !!refreshToken,
      profileId: profile.id,
      emails: profile.emails?.map(e => e.value),
      displayName: profile.displayName
    });
    try {
      const email = profile.emails?.[0]?.value;
      if (!email) {
        console.log('No email in profile');
        return done(null, false, { message: 'No email from Google' });
      }
      console.log('Looking up user by email:', email);
      let user = await db.findUserByEmail(email);
      console.log('Existing user:', user ? 'found' : 'not found');
      if (!user) {
        const nombre = profile.displayName || profile.name?.givenName || email.split('@')[0];
        const apellido = profile.name?.familyName || '';
        console.log('Creating new user:', { email, nombre, apellido });
        try {
          user = await db.createUser(email, 'google-oauth-' + Date.now(), nombre, apellido, 'client');
          console.log('Created user:', user.id);
        } catch (e) {
          console.log('Create user failed, finding existing:', e.message);
          user = await db.findUserByEmail(email);
        }
      }
      if (!user) {
        console.log('No user after create/find');
        return done(null, false, { message: 'No se pudo crear la cuenta.' });
      }
      console.log('Returning user:', user.id);
      return done(null, user);
    } catch (err) {
      console.error('Strategy error:', err);
      return done(err, null);
    }
  }));
}

// ---------- Auth Middleware ----------
function authMiddleware(role) {
  return (req, res, next) => {
    // Check JWT cookie first (for API calls)
    const token = req.cookies.token;
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        if (role && decoded.role !== role) {
          if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Forbidden' });
          return res.redirect('/login');
        }
        return next();
      } catch {}
    }
    // Fallback to session (for browser navigation)
    if (req.isAuthenticated && req.isAuthenticated()) {
      req.user = { id: req.user.id, email: req.user.email, role: req.user.role, nombre: req.user.nombre };
      if (role && req.user.role !== role) {
        if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Forbidden' });
        return res.redirect('/login');
      }
      return next();
    }
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'No autenticado' });
    return res.redirect('/login');
  };
}

// ---------- Routes ----------

// Login page
app.get('/login', (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role === 'admin') return res.redirect('/admin');
      return res.redirect('/cliente');
    } catch {}
  }
  res.render('login', { error: null });
});

// Login action
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.findUserByEmail(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  }
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, nombre: user.nombre }, JWT_SECRET, { expiresIn: '24h' });
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax', path: '/', secure: isSecure });
  // Also establish session
  req.login(user, (err) => {
    if (err) console.error('Session login error:', err);
  });
  res.json({ success: true, role: user.role });
});

app.get('/logout', (req, res) => { 
  res.clearCookie('token', { path: '/' }); 
  req.logout(() => {});
  res.redirect('/login'); 
});

// Google OAuth routes (Passport)
app.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.redirect('/login?error=google_not_configured');
  }
  passport.authenticate('google', { scope: ['profile', 'email'], prompt: 'select_account' })(req, res, next);
});

app.get('/auth/google/callback', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.redirect('/login?error=google_not_configured');
  }
  console.log('=== GOOGLE CALLBACK ROUTE START ===', { query: req.query, sessionID: req.sessionID });
  passport.authenticate('google', { failureRedirect: '/login?error=no_account' }, (err, user, info) => {
    console.log('=== PASSPORT CALLBACK ===', { err: err?.message, user: user?.id, info });
    if (err || !user) {
      console.log('Passport auth failed:', err?.message, info?.message);
      return res.redirect('/login?error=' + encodeURIComponent(info?.message || 'no_account'));
    }
    req.logIn(user, (err) => {
      console.log('req.logIn result:', { err: err?.message, userId: user.id });
      if (err) return next(err);
      // Force session save with explicit user
      req.session.user = { id: user.id, email: user.email, role: user.role, nombre: user.nombre };
      req.session.save((err) => {
        if (err) return next(err);
        // Also issue JWT cookie for API compatibility
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role, nombre: user.nombre }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax', path: '/', secure: true });
        console.log('Redirecting to:', user.role === 'admin' ? '/admin' : '/cliente');
        if (user.role === 'admin') return res.redirect('/admin');
        return res.redirect('/cliente');
      });
    });
  })(req, res, next);
});

// Debug endpoint
app.get('/auth/debug', (req, res) => {
  res.json({
    cookies: req.cookies,
    session: req.session ? 'present' : 'missing',
    sessionID: req.sessionID || 'none',
    sessionData: req.session ? { ...req.session, cookie: req.session.cookie } : null,
    user: req.user || null,
    isAuthenticated: req.isAuthenticated ? req.isAuthenticated() : false,
    headers: { proto: req.headers['x-forwarded-proto'], host: req.headers.host },
    secure: req.secure,
    env_client_id: !!process.env.GOOGLE_CLIENT_ID,
    env_client_secret: !!process.env.GOOGLE_CLIENT_SECRET,
    env_callback: process.env.GOOGLE_CALLBACK_URL,
    jwt_secret_set: JWT_SECRET !== 'visapro-secret-key-change-in-production'
  });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.json({ user: null });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ user: decoded });
  } catch { res.json({ user: null }); }
});

// ========== ADMIN ==========
app.get('/admin', authMiddleware('admin'), (req, res) => {
  res.render('admin', { user: req.user });
});

app.get('/api/admin/stats', authMiddleware('admin'), async (req, res) => {
  res.json(await db.getStats());
});

app.get('/api/admin/stats/mensual', authMiddleware('admin'), async (req, res) => {
  res.json(await db.getMonthlyStats());
});

app.get('/api/admin/clientes', authMiddleware('admin'), async (req, res) => {
  const { q, estado } = req.query;
  const clients = await db.getClients(q, estado);
  res.json(clients);
});

app.get('/api/admin/clientes/:id', authMiddleware('admin'), async (req, res) => {
  const client = await db.getClient(req.params.id);
  if (!client) return res.status(404).json({ error: 'Cliente no encontrado' });
  res.json(client);
});

app.post('/api/admin/clientes', authMiddleware('admin'), async (req, res) => {
  const client = await db.createClient(req.body);
  res.json(client);
});

app.put('/api/admin/clientes/:id', authMiddleware('admin'), async (req, res) => {
  await db.updateClient(req.params.id, req.body);
  res.json({ success: true });
});

app.put('/api/admin/clientes/:id/estado', authMiddleware('admin'), async (req, res) => {
  await db.updateClientStatus(req.params.id, req.body.estado);
  res.json({ success: true });
});

app.delete('/api/admin/clientes/:id', authMiddleware('admin'), async (req, res) => {
  await db.deleteClient(req.params.id);
  res.json({ success: true });
});

app.post('/api/admin/clientes/:id/reset-password', authMiddleware('admin'), async (req, res) => {
  const client = await db.getClient(req.params.id);
  if (!client) return res.status(404).json({ error: 'Cliente no encontrado' });
  if (!client.user_id) return res.status(400).json({ error: 'Cliente no tiene usuario' });
  const tempPass = Math.random().toString(36).slice(2, 8);
  await db.updateUserPassword(client.user_id, bcrypt.hashSync(tempPass, 10));
  res.json({ temp_password: tempPass });
});

// EXPORT Excel
app.get('/api/admin/exportar/excel', authMiddleware('admin'), async (req, res) => {
  const clients = await db.getClients('', 'all');
  const fields = ['nombre','apellido','email','telefono','pasaporte','fecha_nacimiento','lugar_nacimiento','nacionalidad','genero','estado_civil','ocupacion','pais_emision','fecha_expedicion','fecha_vencimiento','direccion','ciudad','codigo_postal','proposito_viaje','fecha_viaje','duracion','alojamiento','gastos_pagados_por','viaje_previo','visa_previa','negacion','familiares_usa','notas','estado','fecha_registro'];
  const labels = ['Nombre','Apellido','Email','Teléfono','Pasaporte','Fecha Nacimiento','Lugar Nacimiento','Nacionalidad','Género','Estado Civil','Ocupación','País Emisión','Fecha Expedición','Vencimiento Pasaporte','Dirección','Ciudad','Código Postal','Propósito Viaje','Fecha Viaje','Duración (días)','Alojamiento','Gastos Pagados Por','Viaje Previo USA','Visa Previa','Negación Visa','Familiares USA','Notas','Estado','Fecha Registro'];
  const data = clients.map(c => {
    const row = {};
    fields.forEach((f, i) => { row[labels[i]] = c[f] || ''; });
    return row;
  });
  const ws = XLSX.utils.json_to_sheet(data);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Clientes');
  ws['!cols'] = labels.map(l => ({ wch: Math.max(l.length, 15) }));
  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Disposition', 'attachment; filename=visapro_clientes.xlsx');
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});

app.get('/api/admin/exportar/csv', authMiddleware('admin'), async (req, res) => {
  const clients = await db.getClients('', 'all');
  const fields = ['nombre','apellido','email','telefono','pasaporte','fecha_nacimiento','lugar_nacimiento','nacionalidad','genero','estado_civil','ocupacion','pais_emision','fecha_expedicion','fecha_vencimiento','direccion','ciudad','codigo_postal','proposito_viaje','fecha_viaje','duracion','alojamiento','gastos_pagados_por','viaje_previo','visa_previa','negacion','familiares_usa','notas','estado','fecha_registro'];
  const labels = ['Nombre','Apellido','Email','Teléfono','Pasaporte','Fecha Nacimiento','Lugar Nacimiento','Nacionalidad','Género','Estado Civil','Ocupación','País Emisión','Fecha Expedición','Vencimiento Pasaporte','Dirección','Ciudad','Código Postal','Propósito Viaje','Fecha Viaje','Duración (días)','Alojamiento','Gastos Pagados Por','Viaje Previo USA','Visa Previa','Negación Visa','Familiares USA','Notas','Estado','Fecha Registro'];
  const rows = [labels];
  clients.forEach(c => {
    rows.push(fields.map(f => {
      const val = c[f] || '';
      return val.includes(',') || val.includes('"') || val.includes('\n') ? `"${val.replace(/"/g, '""')}"` : val;
    }));
  });
  const csv = '\uFEFF' + rows.map(r => r.join(',')).join('\n');
  res.setHeader('Content-Disposition', 'attachment; filename=visapro_clientes.csv');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send(csv);
});

// CHECKLIST
app.post('/api/admin/checklist', authMiddleware('admin'), async (req, res) => {
  await db.saveChecklist(req.body.checklist || []);
  res.json({ success: true });
});

app.get('/api/admin/checklist', authMiddleware('admin'), async (req, res) => {
  res.json(await db.getChecklist());
});

// WHATSAPP LOG
app.post('/api/admin/whatsapp/log', authMiddleware('admin'), async (req, res) => {
  const { client_id, template_id, message } = req.body;
  const entry = await db.logWhatsApp(client_id, template_id, message);
  res.json(entry);
});

app.get('/api/admin/whatsapp/logs', authMiddleware('admin'), async (req, res) => {
  const logs = await db.getWhatsAppLogs(null);
  res.json(logs);
});

app.get('/api/admin/whatsapp/logs/:clientId', authMiddleware('admin'), async (req, res) => {
  const logs = await db.getWhatsAppLogs(parseInt(req.params.clientId));
  res.json(logs);
});

// DOCUMENTOS
app.post('/api/admin/clientes/:id/documentos', authMiddleware('admin'), upload.single('file'), async (req, res) => {
  const client = await db.getClient(req.params.id);
  if (!client) return res.status(404).json({ error: 'Cliente no encontrado' });
  if (!req.file) return res.status(400).json({ error: 'No se subió ningún archivo' });
  const doc = {
    id: Date.now(),
    nombre: req.file.originalname,
    archivo: req.file.filename,
    tipo: req.body.tipo || 'documento',
    fecha: new Date().toISOString().split('T')[0]
  };
  const docs = client.documentos || [];
  docs.push(doc);
  await db.updateClient(req.params.id, { documentos: docs });
  res.json(doc);
});

app.delete('/api/admin/clientes/:id/documentos/:docId', authMiddleware('admin'), async (req, res) => {
  const client = await db.getClient(req.params.id);
  if (!client) return res.status(404).json({ error: 'Cliente no encontrado' });
  let docs = client.documentos || [];
  const doc = docs.find(d => d.id == req.params.docId);
  if (doc) {
    const filePath = path.join(__dirname, 'uploads', doc.archivo);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
  docs = docs.filter(d => d.id != req.params.docId);
  await db.updateClient(req.params.id, { documentos: docs });
  res.json({ success: true });
});

// TEMPLATES
app.get('/api/admin/templates', authMiddleware('admin'), async (req, res) => {
  res.json(await db.getTemplates());
});

app.post('/api/admin/templates', authMiddleware('admin'), async (req, res) => {
  const t = await db.createTemplate(req.body);
  res.json(t);
});

app.put('/api/admin/templates/:id', authMiddleware('admin'), async (req, res) => {
  const t = await db.saveTemplate(req.params.id, req.body);
  res.json(t);
});

app.delete('/api/admin/templates/:id', authMiddleware('admin'), async (req, res) => {
  await db.deleteTemplate(req.params.id);
  res.json({ success: true });
});

// ========== CLIENT ==========
app.get('/cliente', authMiddleware('client'), (req, res) => {
  res.render('client', { user: req.user });
});

app.get('/api/client/mi-caso', authMiddleware('client'), async (req, res) => {
  const client = await db.getClientByUserId(req.user.id);
  if (!client) return res.status(404).json({ error: 'No tienes un caso registrado' });
  res.json({ client, checklist: [] });
});

app.post('/api/client/mi-caso/visto', authMiddleware('client'), async (req, res) => {
  const client = await db.getClientByUserId(req.user.id);
  if (client) await db.updateClientLastView(client.id);
  res.json({ success: true });
});

// ========== ROOT → VISA APP ==========
app.get('/', (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role === 'admin') return res.redirect('/admin');
      return res.redirect('/cliente');
    } catch {}
  }
  res.redirect('/login');
});

// ========== SERVE (visa app) ==========
app.get('/recorrido', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'escuela3d.html'));
});

app.get('/visapro', (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role === 'admin') return res.redirect('/admin');
      return res.redirect('/cliente');
    } catch {}
  }
  res.redirect('/login');
});

db.init().then(() => {
  app.listen(PORT, () => console.log(`VisaPro corriendo en http://localhost:${PORT}`));
}).catch(err => {
  console.error('Error al iniciar:', err);
  process.exit(1);
});
