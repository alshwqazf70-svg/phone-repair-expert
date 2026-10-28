'use strict';
// طبقة البيانات: SQLite مدمجة في Node (node:sqlite) بلا اعتماديات خارجية.
// أسماء الجداول والأعمدة تأتي حصرًا من القائمة البيضاء T أدناه (لا تُبنى من مدخلات المستخدم).
const { DatabaseSync } = require('node:sqlite');
const fs = require('fs'), path = require('path');

const T = {
  brands:   ['name'],
  models:   ['brand', 'name', 'model_number', 'os_versions', 'region', 'notes'],
  issues:   ['title', 'symptoms', 'steps', 'stop_when', 'risk', 'brand', 'os_versions'],
  codes:    ['code', 'purpose', 'brand', 'models', 'os_versions', 'compat', 'risk', 'category', 'expected_output', 'notes'],
  commands: ['command', 'purpose', 'requirements', 'compat', 'risk', 'expected_output', 'notes'],
  sources:  ['title', 'url', 'kind'],
};

function open(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
  for (const [t, cols] of Object.entries(T)) {
    db.exec(`CREATE TABLE IF NOT EXISTS ${t}(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ${cols.map(c => c + ' TEXT').join(',')},
      status TEXT NOT NULL DEFAULT 'draft',          -- draft | published
      data_level TEXT NOT NULL DEFAULT 'unverified', -- sample | unverified | verified
      source_ids TEXT,                               -- معرّفات من جدول sources مفصولة بفواصل
      last_verified TEXT,                            -- YYYY-MM-DD
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  }
  for (const [t, cols] of Object.entries(T)) { // ترحيل بسيط: أضف الأعمدة الناقصة لقواعد أُنشئت بإصدار أقدم
    const have = db.prepare(`PRAGMA table_info(${t})`).all().map(r => r.name);
    for (const c of cols) if (!have.includes(c)) db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} TEXT`);
  }
  db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,pw TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN('admin','editor')),created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS suggestions(id INTEGER PRIMARY KEY AUTOINCREMENT,table_name TEXT NOT NULL,target_id INTEGER,payload TEXT NOT NULL,origin TEXT NOT NULL CHECK(origin IN('ai','manual')),evidence TEXT,status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','approved','rejected')),created_by TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,reviewed_by TEXT,reviewed_at TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT DEFAULT CURRENT_TIMESTAMP,actor TEXT,action TEXT,table_name TEXT,row_id INTEGER);`);
  return db;
}

// بذر أولي فقط إذا كانت الجداول فارغة. لا موديلات ولا أكواد مختلقة.
function seed(db, seedFile) {
  const s = JSON.parse(fs.readFileSync(seedFile, 'utf8'));
  const empty = t => db.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n === 0;
  const ins = (t, row) => {
    const cols = Object.keys(row);
    db.prepare(`INSERT INTO ${t}(${cols.join(',')}) VALUES(${cols.map(() => '?').join(',')})`).run(...cols.map(c => row[c]));
  };
  if (empty('sources')) s.sources.forEach(x => ins('sources', { title: x.title, url: x.url, kind: x.kind, status: 'published', data_level: 'unverified' }));
  if (empty('brands')) (s.brands || []).forEach(name => ins('brands', { name, status: 'published', data_level: 'sample' }));
  if (empty('models')) {
    const idOf = u => (db.prepare('SELECT id FROM sources WHERE url=?').get(u) || {}).id;
    (s.models || []).forEach(x => {
      const { source_urls = [], ...row } = x;
      const ids = source_urls.map(idOf).filter(Boolean).join(',');
      ins('models', { ...row, source_ids: ids || null, status: 'published', data_level: row.data_level || 'sample' });
    });
  }
  if (empty('commands')) {
    const idOf = u => (db.prepare('SELECT id FROM sources WHERE url=?').get(u) || {}).id;
    s.commands.forEach(x => {
      const { source_urls = [], ...row } = x;
      const ids = source_urls.map(idOf).filter(Boolean).join(',');
      ins('commands', { ...row, source_ids: ids || null, status: 'published', data_level: row.data_level || 'sample' });
    });
  }
  if (empty('issues')) (s.issues || []).forEach(x => ins('issues', { ...x, status: 'published', data_level: 'sample' }));
  if (empty('codes')) {
    const idOf = u => (db.prepare('SELECT id FROM sources WHERE url=?').get(u) || {}).id;
    s.codes.forEach(x => {
      const { source_urls = [], ...row } = x;
      const ids = source_urls.map(idOf).filter(Boolean).join(',');
      ins('codes', { ...row, source_ids: ids || null, status: 'published', data_level: row.data_level || 'unverified' });
    });
  }
}
module.exports = { open, seed, T };
