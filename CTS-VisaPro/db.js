const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'database.json');
const DATABASE_URL = process.env.DATABASE_URL;
const UPLOADS_DIR = path.join(__dirname, 'uploads');

let pool = null;
let usePostgres = false;

// ---- Init ----
async function init() {
  if (DATABASE_URL) {
    usePostgres = true;
    pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await migratePostgres();
    console.log('Usando PostgreSQL');
  } else {
    usePostgres = false;
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], clients: [], checklist: [], templates: DEFAULT_TEMPLATES.map((t, i) => ({ id: i + 1, ...t })), whatsapp_log: [] }));
    }
    migrateJSON();
    console.log('Usando JSON file (local)');
  }
}

async function migratePostgres() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      nombre TEXT NOT NULL,
      apellido TEXT DEFAULT '',
      role TEXT NOT NULL DEFAULT 'client',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
  DROP TABLE IF EXISTS clients CASCADE;
    CREATE TABLE IF NOT EXISTS clients (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      nombre TEXT NOT NULL,
      apellido TEXT NOT NULL,
      fecha_nacimiento TEXT DEFAULT '',
      lugar_nacimiento TEXT DEFAULT '',
      nacionalidad TEXT DEFAULT '',
      genero TEXT DEFAULT '',
      estado_civil TEXT DEFAULT '',
      ocupacion TEXT DEFAULT '',
      pasaporte TEXT DEFAULT '',
      pais_emision TEXT DEFAULT '',
      fecha_expedicion TEXT DEFAULT '',
      fecha_vencimiento TEXT DEFAULT '',
      email TEXT DEFAULT '',
      telefono TEXT DEFAULT '',
      direccion TEXT DEFAULT '',
      ciudad TEXT DEFAULT '',
      codigo_postal TEXT DEFAULT '',
      proposito_viaje TEXT DEFAULT '',
      fecha_viaje TEXT DEFAULT '',
      duracion TEXT DEFAULT '',
      alojamiento TEXT DEFAULT '',
      gastos_pagados_por TEXT DEFAULT '',
      viaje_previo TEXT DEFAULT '',
      visa_previa TEXT DEFAULT '',
      negacion TEXT DEFAULT '',
      familiares_usa TEXT DEFAULT '',
      notas TEXT DEFAULT '',
	  estado TEXT DEFAULT 'proceso',
      fecha_registro TEXT DEFAULT '',
      ultima_vista TIMESTAMP DEFAULT NULL,
      documentos JSONB DEFAULT '[]',
      whatsapp_log JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS checklist (
      id SERIAL PRIMARY KEY,
      client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
      seccion_id INTEGER NOT NULL,
      completado BOOLEAN DEFAULT false,
      UNIQUE(client_id, seccion_id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS templates (
      id SERIAL PRIMARY KEY,
      icon TEXT DEFAULT 'fa-comment',
      title TEXT NOT NULL,
      text TEXT NOT NULL
    )
  `);
  const { rows: tmplCount } = await pool.query('SELECT COUNT(*) FROM templates');
  if (parseInt(tmplCount[0].count) === 0) {
    for (const t of DEFAULT_TEMPLATES) {
      await pool.query('INSERT INTO templates (icon, title, text) VALUES ($1, $2, $3)', [t.icon, t.title, t.text]);
    }
  }
  // Create admin if not exists
  const { rows } = await pool.query('SELECT id FROM users WHERE role = $1', ['admin']);
  if (rows.length === 0) {
    const hashed = bcrypt.hashSync('admin123', 10);
    await pool.query(
      'INSERT INTO users (email, password, nombre, apellido, role) VALUES ($1, $2, $3, $4, $5)',
      ['admin@visapro.com', hashed, 'Administrador', '', 'admin']
    );
    console.log('Admin creado: admin@visapro.com / admin123');
  }
}

function migrateJSON() {
  const db = loadJSON();
  const admin = db.users.find(u => u.role === 'admin');
  if (!admin) {
    const hashed = bcrypt.hashSync('admin123', 10);
    db.users.push({ id: 1, email: 'admin@visapro.com', password: hashed, nombre: 'Administrador', apellido: '', role: 'admin', created_at: new Date().toISOString() });
    saveJSON(db);
    console.log('Admin creado: admin@visapro.com / admin123');
  }
}

// ---- JSON helpers ----
function loadJSON() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return { users: [], clients: [], checklist: [] }; }
}
function saveJSON(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

// ---- Users ----
async function findUserByEmail(email) {
  if (usePostgres) {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return rows[0] || null;
  }
  return loadJSON().users.find(u => u.email === email) || null;
}

async function createUser(email, password, nombre, apellido, role) {
  if (usePostgres) {
    const { rows } = await pool.query(
      'INSERT INTO users (email, password, nombre, apellido, role) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [email, password, nombre, apellido, role]
    );
    return rows[0];
  }
  const db = loadJSON();
  const id = db.users.length > 0 ? Math.max(...db.users.map(u => u.id)) + 1 : 1;
  const user = { id, email, password, nombre, apellido, role, created_at: new Date().toISOString() };
  db.users.push(user);
  saveJSON(db);
  return user;
}

async function updateUserPassword(id, password) {
  if (usePostgres) {
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [password, id]);
  } else {
    const db = loadJSON();
    const user = db.users.find(u => u.id === id);
    if (user) { user.password = password; saveJSON(db); }
  }
}

// ---- Clients ----
async function getClients(q, estado) {
  if (usePostgres) {
    let sql = 'SELECT c.*, u.email as email_cliente FROM clients c LEFT JOIN users u ON c.user_id = u.id';
    const params = [];
    const conditions = [];
    if (q) { conditions.push(`(LOWER(c.nombre) LIKE $${params.length+1} OR LOWER(c.apellido) LIKE $${params.length+1} OR LOWER(c.pasaporte) LIKE $${params.length+1} OR LOWER(c.email) LIKE $${params.length+1})`); params.push(`%${q.toLowerCase()}%`); }
    if (estado && estado !== 'all') { conditions.push(`c.estado = $${params.length+1}`); params.push(estado); }
    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ' ORDER BY c.id DESC';
    const { rows } = await pool.query(sql, params);
    return rows;
  }
  let clients = [...loadJSON().clients];
  if (q) { const lq = q.toLowerCase(); clients = clients.filter(c => c.nombre.toLowerCase().includes(lq) || c.apellido.toLowerCase().includes(lq) || c.pasaporte.toLowerCase().includes(lq) || c.email.toLowerCase().includes(lq)); }
  if (estado && estado !== 'all') clients = clients.filter(c => c.estado === estado);
  return clients.reverse();
}

async function getClient(id) {
  if (usePostgres) {
    const { rows } = await pool.query('SELECT * FROM clients WHERE id = $1', [id]);
    if (!rows[0]) return null;
    const { rows: userRows } = await pool.query('SELECT email FROM users WHERE id = $1', [rows[0].user_id]);
    rows[0].login_creado = userRows.length > 0;
    rows[0].email_login = userRows[0]?.email || null;
    const { rows: chk } = await pool.query('SELECT * FROM checklist WHERE client_id = $1', [id]);
    rows[0].checklist = chk;
    return rows[0];
  }
  const db = loadJSON();
  const client = db.clients.find(c => c.id == id);
  if (!client) return null;
  const user = db.users.find(u => u.id === client.user_id);
  client.login_creado = !!user;
  client.email_login = user?.email || null;
  client.checklist = db.checklist.filter(ch => ch.client_id == id);
  if (!client.documentos) client.documentos = [];
  if (!client.whatsapp_log) client.whatsapp_log = [];
  return client;
}

async function createClient(data) {
  if (usePostgres) {
    const fields = ['nombre','apellido','fecha_nacimiento','lugar_nacimiento','nacionalidad','genero','estado_civil','ocupacion','pasaporte','pais_emision','fecha_expedicion','fecha_vencimiento','email','telefono','direccion','ciudad','estado','codigo_postal','proposito_viaje','fecha_viaje','duracion','alojamiento','gastos_pagados_por','viaje_previo','visa_previa','negacion','familiares_usa','notas','fecha_registro'];
    const vals = fields.map(f => data[f] || '');
    vals[vals.length - 1] = new Date().toLocaleDateString('es-MX');
    const placeholders = fields.map((_, i) => `$${i+1}`).join(',');
    const { rows } = await pool.query(`INSERT INTO clients (${fields.join(',')}) VALUES (${placeholders}) RETURNING *`, vals);
    const client = rows[0];

    if (data.email) {
      const tempPass = Math.random().toString(36).slice(2, 8);
      const hashed = bcrypt.hashSync(tempPass, 10);
      const user = await createUser(data.email, hashed, data.nombre, data.apellido, 'client');
      await pool.query('UPDATE clients SET user_id = $1 WHERE id = $2', [user.id, client.id]);
      client.user_id = user.id;
      client.temp_password = tempPass;
    }
    return client;
  }
  const db = loadJSON();
  const newId = db.clients.length > 0 ? Math.max(...db.clients.map(c => c.id)) + 1 : 1;
  const client = { id: newId, user_id: null, ...data, estado: 'proceso', fecha_registro: new Date().toLocaleDateString('es-MX'), created_at: new Date().toISOString() };
  db.clients.push(client);
  if (data.email) {
    const tempPass = Math.random().toString(36).slice(2, 8);
    const hashed = bcrypt.hashSync(tempPass, 10);
    const userId = db.users.length > 0 ? Math.max(...db.users.map(u => u.id)) + 1 : 1;
    db.users.push({ id: userId, email: data.email, password: hashed, nombre: data.nombre, apellido: data.apellido, role: 'client', created_at: new Date().toISOString() });
    client.user_id = userId;
    client.temp_password = tempPass;
  }
  saveJSON(db);
  return client;
}

async function updateClient(id, data) {
  if (usePostgres) {
    const fields = Object.keys(data).filter(f => f !== 'id');
    const vals = fields.map(f => {
      if (Array.isArray(data[f]) || typeof data[f] === 'object') return JSON.stringify(data[f]);
      return data[f];
    });
    const sets = fields.map((f, i) => `${f} = $${i+1}`).join(',');
    await pool.query(`UPDATE clients SET ${sets} WHERE id = $${fields.length+1}`, [...vals, id]);
  } else {
    const db = loadJSON();
    const idx = db.clients.findIndex(c => c.id == id);
    if (idx !== -1) { Object.assign(db.clients[idx], data); saveJSON(db); }
  }
}

async function updateClientStatus(id, estado) {
  if (usePostgres) {
    await pool.query('UPDATE clients SET estado = $1 WHERE id = $2', [estado, id]);
  } else {
    const db = loadJSON();
    const c = db.clients.find(x => x.id == id);
    if (c) { c.estado = estado; saveJSON(db); }
  }
}

async function deleteClient(id) {
  if (usePostgres) {
    await pool.query('DELETE FROM clients WHERE id = $1', [id]);
  } else {
    const db = loadJSON();
    db.clients = db.clients.filter(c => c.id != id);
    db.checklist = db.checklist.filter(ch => ch.client_id != id);
    saveJSON(db);
  }
}

async function getStats() {
  if (usePostgres) {
    const { rows } = await pool.query("SELECT COUNT(*)::int as total, COUNT(*) FILTER (WHERE estado='proceso')::int as proceso, COUNT(*) FILTER (WHERE estado='aprobado')::int as aprobado, COUNT(*) FILTER (WHERE estado='rechazado')::int as rechazado FROM clients");
    return rows[0];
  }
  const clients = loadJSON().clients;
  return { total: clients.length, proceso: clients.filter(c => c.estado === 'proceso').length, aprobado: clients.filter(c => c.estado === 'aprobado').length, rechazado: clients.filter(c => c.estado === 'rechazado').length };
}

async function updateClientLastView(id) {
  const now = new Date().toISOString();
  if (usePostgres) {
    await pool.query('UPDATE clients SET ultima_vista = $1 WHERE id = $2', [now, id]);
  } else {
    const db = loadJSON();
    const c = db.clients.find(x => x.id == id);
    if (c) { c.ultima_vista = now; saveJSON(db); }
  }
}

async function getMonthlyStats() {
  const months = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic'];
  const now = new Date();
  const result = [];
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const monthStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    result.push({ mes: months[d.getMonth()], anio: d.getFullYear(), total: 0, monthStr });
  }
  if (usePostgres) {
    for (const r of result) {
      const { rows } = await pool.query(
        "SELECT COUNT(*)::int as cnt FROM clients WHERE to_char(created_at, 'YYYY-MM') = $1",
        [r.monthStr]
      );
      r.total = rows[0].cnt;
    }
  } else {
    const clients = loadJSON().clients;
    for (const r of result) {
      r.total = clients.filter(c => {
        const reg = c.created_at || c.fecha_registro;
        return reg && reg.startsWith(r.monthStr);
      }).length;
    }
  }
  return result;
}

async function logWhatsApp(clientId, templateId, message) {
  const entry = { client_id: clientId, template_id: templateId, message: message.substring(0, 200), fecha: new Date().toISOString() };
  if (usePostgres) {
    const { rows } = await pool.query('SELECT whatsapp_log FROM clients WHERE id = $1', [clientId]);
    if (rows[0]) {
      const log = rows[0].whatsapp_log || [];
      log.push(entry);
      await pool.query('UPDATE clients SET whatsapp_log = $1::jsonb WHERE id = $2', [JSON.stringify(log), clientId]);
    }
  } else {
    const db = loadJSON();
    if (!db.whatsapp_log) db.whatsapp_log = [];
    db.whatsapp_log.push(entry);
    const c = db.clients.find(x => x.id == clientId);
    if (c) {
      if (!c.whatsapp_log) c.whatsapp_log = [];
      c.whatsapp_log.push(entry);
    }
    saveJSON(db);
  }
  return entry;
}

async function getWhatsAppLogs(clientId) {
  if (usePostgres) {
    if (clientId) {
      const { rows } = await pool.query('SELECT whatsapp_log FROM clients WHERE id = $1', [clientId]);
      return rows[0]?.whatsapp_log || [];
    }
    const { rows } = await pool.query('SELECT id, whatsapp_log FROM clients WHERE whatsapp_log IS NOT NULL AND jsonb_array_length(whatsapp_log) > 0');
    const all = [];
    for (const r of rows) {
      for (const e of (r.whatsapp_log || [])) {
        all.push({ ...e, client_id: r.id });
      }
    }
    return all.sort((a, b) => new Date(b.fecha) - new Date(a.fecha));
  }
  const db = loadJSON();
  if (clientId) {
    const c = db.clients.find(x => x.id == clientId);
    return c?.whatsapp_log || [];
  }
  const all = db.whatsapp_log || [];
  return all.sort((a, b) => new Date(b.fecha) - new Date(a.fecha));
}

// ---- Checklist ----
async function saveChecklist(list) {
  if (usePostgres) {
    await pool.query('DELETE FROM checklist');
    for (const item of list) {
      await pool.query('INSERT INTO checklist (client_id, seccion_id, completado) VALUES ($1, $2, $3)', [item.client_id || 0, item.seccion_id, item.completado]);
    }
  } else {
    const db = loadJSON();
    db.checklist = list;
    saveJSON(db);
  }
}

async function getChecklist() {
  if (usePostgres) {
    const { rows } = await pool.query('SELECT * FROM checklist');
    return rows;
  }
  return loadJSON().checklist || [];
}

async function getClientByUserId(userId) {
  if (usePostgres) {
    const { rows } = await pool.query('SELECT * FROM clients WHERE user_id = $1', [userId]);
    return rows[0] || null;
  }
  return loadJSON().clients.find(c => c.user_id === userId) || null;
}

// ---- Templates ----
const DEFAULT_TEMPLATES = [
  { icon: 'fa-hand-wave', title: 'Bienvenida', text: 'Hola {{nombre}}\n\nGracias por confiar en nosotros para tu trámite de visa americana!\n\nTu expediente ha sido creado con éxito. En breve te enviaremos los pasos a seguir y la lista de documentos que necesitas preparar.\n\nSaludos,\nVisaPro' },
  { icon: 'fa-calendar-check', title: 'Confirmación de Cita', text: 'Hola {{nombre}}\n\nTu cita para la entrevista de visa ha sido confirmada\n\nFecha: {{fecha}}\nLugar: {{lugar}}\n\nRecuerda llegar 15 minutos antes con los documentos necesarios.\n\nMucho éxito!' },
  { icon: 'fa-clipboard-list', title: 'Seguimiento Post-Entrevista', text: 'Hola {{nombre}}\n\nEsperamos que tu entrevista haya ido muy bien\n\nEl tiempo de procesamiento habitual es de 3 a 5 días hábiles. Te notificaremos en cuanto tengamos novedades.\n\nSaludos,\nVisaPro' },
  { icon: 'fa-bell', title: 'Recordatorio del Consulado', text: 'Hola {{nombre}}\n\nTe recordamos que mañana tienes tu cita en el consulado\n\nNo olvides llevar:\n- Pasaporte vigente\n- Confirmación DS-160\n- Comprobante de pago\n- Foto 5x5 reciente\n- Cita impresa\n\nMucho éxito!' },
  { icon: 'fa-party-horn', title: 'Cierre de Caso Aprobado', text: 'Hola {{nombre}}\n\nFelicidades!\n\nTu visa americana ha sido APROBADA\n\nTu pasaporte será entregado en los próximos días.\n\nGracias por confiar en nosotros. Disfruta tu viaje!\n\nAtentamente,\nVisaPro' }
];

async function getTemplates() {
  if (usePostgres) {
    const { rows } = await pool.query('SELECT * FROM templates ORDER BY id ASC');
    return rows;
  }
  const db = loadJSON();
  if (!db.templates || db.templates.length === 0) {
    db.templates = DEFAULT_TEMPLATES.map((t, i) => ({ id: i + 1, ...t }));
    saveJSON(db);
  }
  return db.templates;
}

async function saveTemplate(id, data) {
  if (usePostgres) {
    const { rows } = await pool.query(
      'UPDATE templates SET icon=$1, title=$2, text=$3 WHERE id=$4 RETURNING *',
      [data.icon, data.title, data.text, id]
    );
    return rows[0];
  }
  const db = loadJSON();
  const idx = db.templates.findIndex(t => t.id == id);
  if (idx !== -1) {
    db.templates[idx] = { ...db.templates[idx], ...data };
    saveJSON(db);
    return db.templates[idx];
  }
  return null;
}

async function createTemplate(data) {
  if (usePostgres) {
    const { rows } = await pool.query(
      'INSERT INTO templates (icon, title, text) VALUES ($1, $2, $3) RETURNING *',
      [data.icon || 'fa-comment', data.title, data.text]
    );
    return rows[0];
  }
  const db = loadJSON();
  if (!db.templates) db.templates = [];
  const id = db.templates.length > 0 ? Math.max(...db.templates.map(t => t.id)) + 1 : 1;
  const t = { id, icon: data.icon || 'fa-comment', title: data.title, text: data.text };
  db.templates.push(t);
  saveJSON(db);
  return t;
}

async function deleteTemplate(id) {
  if (usePostgres) {
    await pool.query('DELETE FROM templates WHERE id=$1', [id]);
  } else {
    const db = loadJSON();
    db.templates = db.templates.filter(t => t.id != id);
    saveJSON(db);
  }
}

module.exports = { init, findUserByEmail, createUser, updateUserPassword, getClients, getClient, createClient, updateClient, updateClientStatus, deleteClient, getStats, updateClientLastView, getMonthlyStats, logWhatsApp, getWhatsAppLogs, saveChecklist, getChecklist, getClientByUserId, getTemplates, saveTemplate, createTemplate, deleteTemplate };
