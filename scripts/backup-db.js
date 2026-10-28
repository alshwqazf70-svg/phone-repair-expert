'use strict';
// شغّل هذا السكربت بعد إيقاف الخادم حتى تكون نسخة SQLite متسقة.
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const root = path.resolve(__dirname, '..');
const source = path.resolve(process.env.DB_FILE || path.join(root, 'server', 'data', 'app.db'));
if (!fs.existsSync(source)) {
  console.error(`لم أعثر على قاعدة البيانات: ${source}`);
  process.exit(1);
}
const db = new DatabaseSync(source);
try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); }
finally { db.close(); }
const dir = path.join(root, 'backups');
fs.mkdirSync(dir, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const dest = path.join(dir, `app-${stamp}.db`);
fs.copyFileSync(source, dest, fs.constants.COPYFILE_EXCL);
console.log(`تم إنشاء نسخة احتياطية محلية: ${dest}`);
console.log('احتفظ بنسخة ثانية خارج هذا الجهاز، واختبر الاستعادة دوريًا.');
