const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const https = require('https');
const http = require('http');
const XLSX = require('xlsx');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'visapro-secret-key-change-in-production';

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

// ---------- Google OAuth Config ----------
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback';
function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    mod.get(url, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => resolve(JSON.parse(d))); }).on('error', reject);
  });
}
function httpsPost(url, body, headers) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'POST', headers }, res => {
      let d = ''; res.on('data', c => d += c); res.on('end', () => resolve(JSON.parse(d)));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ---------- Auth Middleware ----------
function authMiddleware(role) {
  return (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      if (role && decoded.role !== role) return res.redirect('/login');
      next();
    } catch {
      res.clearCookie('token', { path: '/' });
      res.redirect('/login');
    }
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
  res.json({ success: true, role: user.role });
});

app.get('/logout', (req, res) => { res.clearCookie('token', { path: '/' }); res.redirect('/login'); });

// Google OAuth routes (manual, no passport)
app.get('/auth/debug', (req, res) => {
  res.json({
    cookies: req.cookies,
    headers: { proto: req.headers['x-forwarded-proto'], host: req.headers.host },
    secure: req.secure,
    env_client_id: !!GOOGLE_CLIENT_ID,
    env_client_secret: !!GOOGLE_CLIENT_SECRET,
    env_callback: GOOGLE_CALLBACK_URL,
    jwt_secret_set: JWT_SECRET !== 'visapro-secret-key-change-in-production'
  });
});
app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.redirect('/login?error=google_not_configured');
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_CALLBACK_URL,
    response_type: 'code',
    scope: 'openid email profile',
    prompt: 'select_account'
  });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString());
});

app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, error } = req.query;
    if (error || !code) return res.redirect('/login?error=' + encodeURIComponent(error || 'no_code'));

    const tokenRes = await httpsPost('https://oauth2.googleapis.com/token', new URLSearchParams({
      code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_CALLBACK_URL, grant_type: 'authorization_code'
    }).toString(), { 'Content-Type': 'application/x-www-form-urlencoded' });

    if (tokenRes.error) {
      console.error('Google token error:', tokenRes);
      return res.redirect('/login?error=' + encodeURIComponent(tokenRes.error_description || tokenRes.error));
    }

    const profileRes = await httpsGet('https://www.googleapis.com/oauth2/v3/userinfo?access_token=' + tokenRes.access_token);
    const email = profileRes.email;
    if (!email) return res.redirect('/login?error=no_email');

    let user = await db.findUserByEmail(email);
    if (!user) {
      const nombre = profileRes.name || email.split('@')[0];
      const apellido = profileRes.family_name || '';
      try {
        user = await db.createUser(email, 'google-oauth-' + Date.now(), nombre, apellido, 'client');
      } catch (e) {
        user = await db.findUserByEmail(email);
      }
      if (!user) return res.redirect('/login?error=no_account');
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, nombre: user.nombre }, JWT_SECRET, { expiresIn: '24h' });
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000, sameSite: 'lax', path: '/', secure: isSecure });
    if (user.role === 'admin') return res.redirect('/admin');
    return res.redirect('/cliente');
  } catch (err) {
    console.error('Google OAuth callback error:', err);
    return res.redirect('/login?error=' + encodeURIComponent(err.message));
  }
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
