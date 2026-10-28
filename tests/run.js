'use strict';
// اختبارات تكاملية: تشغّل الخادم الحقيقي بقاعدة مؤقتة، وخدمة ذكاء اصطناعي وهمية محلية (لا اتصال بالإنترنت).
const { spawn } = require('child_process'), http = require('http'), os = require('os'), path = require('path'), fs = require('fs');
const FAKE_KEY = 'sk-test-FAKE-KEY-123';
let pass = 0, failN = 0;
const ok = (c, n) => { if (c) { pass++; console.log('نجح  ', n); } else { failN++; console.log('فشل  ', n); } };
const wait = ms => new Promise(r => setTimeout(r, ms));
function mock(port, status = 200) {
  const seen = [];
  const s = http.createServer((req, res) => { let b = ''; req.on('data', d => b += d); req.on('end', () => { seen.push({ h: req.headers, b }); res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify({ candidates: [{ content: { parts: [{ text: 'ردّ تجريبي من خدمة وهمية' }] } }] })); }); });
  return new Promise(r => s.listen(port, () => r({ s, seen })));
}
function start(env, port) {
  const db = path.join(os.tmpdir(), 'pre-' + Date.now() + Math.random() + '.db');
  const p = spawn(process.execPath, ['server/index.js'], { env: { ...process.env, PORT: port, DB_FILE: db, SESSION_SECRET: 'test-secret-test-secret', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; p.stdout.on('data', d => out += d); p.stderr.on('data', d => out += d);
  return new Promise(r => { const t = setInterval(() => { if (out.includes('listening')) { clearInterval(t); r({ p, db, log: () => out }); } }, 50); });
}
const H = { 'content-type': 'application/json', 'x-requested-with': 'fetch' };
async function call(port, m, u, b, cookie, hdr = H) {
  const r = await fetch(`http://127.0.0.1:${port}${u}`, { method: m, headers: { ...hdr, ...(cookie ? { cookie } : {}) }, body: b ? JSON.stringify(b) : undefined });
  let j = null; try { j = await r.clone().json(); } catch {} return { r, j, text: await r.text() };
}
(async () => {
  const mk = await mock(4599);
  const A = await start({ ADMIN_EMAIL: 'admin@test.local', ADMIN_PASSWORD: 'correct-horse-battery', GEMINI_API_KEY: FAKE_KEY, GEMINI_BASE_URL: 'http://127.0.0.1:4599', AI_DAILY_LIMIT: '50' }, 4501);
  const P = 4501;
  // عام
  let x = await call(P, 'GET', '/api/health'); ok(x.j.ok && x.j.ai === true, 'health يعمل ويُظهر أن المساعد مهيأ');
  x = await call(P, 'GET', '/api/data'); ok(x.j.models.length === 15 && x.j.models.every(m => m.data_level === 'sample' && !m.model_number), 'عائلات الأجهزة الأولية موسومة كعينات بلا أرقام طراز مختلقة');
  ok(x.j.commands.every(c => c.data_level === 'sample') && x.j.commands.length === 40 && x.j.codes.length >= 10, '40 أمرًا مبذورًا موسومًا كعينات، وقائمة الأكواد الأساسية موجودة');
  ok(x.j.brands.length >= 10 && x.j.issues.length >= 6 && x.j.sources.length >= 10, 'واجهة API تعرض الشركات والأعطال والمصادر المنشورة');
  ok(x.j.commands.some(c => c.command === 'adb shell dumpsys connectivity') && x.j.commands.some(c => c.command === 'adb shell getprop ro.boot.verifiedbootstate') && x.j.commands.filter(c => c.command.startsWith('adb shell dumpsys ') || c.command.startsWith('adb shell getprop ')).every(c => c.risk === 'low'), 'أوامر التشخيص الإضافية موجودة وموسومة منخفضة الخطورة');
  ok(x.j.codes.filter(c => c.data_level === 'verified').every(c => c.source_ids && c.last_verified) && x.j.codes.some(c => c.code === '*#*#4636#*#*' && c.data_level === 'unverified'), 'كل كود «موثّق» له مصدر وتاريخ، و4636 موسوم غير موثّق');
  x = await call(P, 'GET', '/'); ok(x.r.status === 200 && x.text.includes('خبير صيانة الهواتف'), 'الواجهة تُخدَّم');
  x = await call(P, 'GET', '/sw.js'); ok(x.r.status === 200 && /javascript/.test(x.r.headers.get('content-type')) && x.r.headers.get('cache-control') === 'no-cache', 'sw.js بنوع صحيح وبلا كاش');
  x = await call(P, 'GET', '/manifest.webmanifest'); ok(x.r.status === 200 && x.j.display === 'standalone', 'manifest يُخدَّم');
  x = await call(P, 'GET', '/..%2f..%2fetc/passwd'); ok(x.r.status === 404, 'منع تجاوز المسارات');
  ok(x.r.headers.get('content-security-policy').includes("frame-ancestors 'none'"), 'ترويسات الأمان موجودة');
  // حماية الإدارة
  x = await call(P, 'GET', '/api/admin/models'); ok(x.r.status === 401, 'الإدارة ترفض غير المسجل');
  x = await call(P, 'POST', '/api/admin/login', { email: 'admin@test.local', password: 'wrong' }); ok(x.r.status === 401, 'كلمة مرور خاطئة ترفض');
  x = await call(P, 'POST', '/api/admin/login', { email: 'admin@test.local', password: 'correct-horse-battery' }, null, { 'content-type': 'application/json' }); ok(x.r.status === 403, 'رفض الطلب بلا ترويسة CSRF');
  x = await call(P, 'POST', '/api/admin/login', { email: 'admin@test.local', password: 'correct-horse-battery' }); ok(x.r.status === 200, 'دخول صحيح');
  const ck = x.r.headers.get('set-cookie'); const cookie = ck.split(';')[0];
  ok(/HttpOnly/.test(ck) && /SameSite=Strict/.test(ck), 'الكوكي HttpOnly وSameSite=Strict');
  x = await call(P, 'GET', '/api/admin/me', null, cookie + 'x'); ok(x.r.status === 401, 'كوكي معبَث به يُرفض');
  // إدارة المحتوى
  x = await call(P, 'POST', '/api/admin/models', { brand: 'Samsung', name: 'اختبار', data_level: 'verified' }, cookie); ok(x.r.status === 400, 'لا يُقبل «موثّق» بلا مصدر وتاريخ');
  x = await call(P, 'POST', '/api/admin/sources', { title: 'x', url: 'http://bad' }, cookie); ok(x.r.status === 400, 'رفض مصدر غير https');
  x = await call(P, 'POST', '/api/admin/models', { brand: 'Samsung' }, cookie); ok(x.r.status === 400, 'رفض سجل موديل بلا اسم مطلوب');
  x = await call(P, 'POST', '/api/admin/models', { brand: 'Samsung', name: 'BadDate', data_level: 'verified', source_ids: '999999', last_verified: '2026-02-30' }, cookie); ok(x.r.status === 400, 'رفض مصدر غير موجود وتاريخ تقويمي غير صالح');
  x = await call(P, 'POST', '/api/admin/models', { brand: 'TestBrand', name: 'Draft', status: 'draft' }, cookie); ok(x.r.status === 201, 'إضافة مسودة');
  x = await call(P, 'GET', '/api/data'); ok(x.j.models.length === 15 && !x.j.models.some(m => m.name === 'Draft'), 'المسودة لا تظهر للعامة');
  x = await call(P, 'POST', '/api/admin/models', { brand: 'TestBrand', name: 'Pub', status: 'published', data_level: 'unverified' }, cookie);
  x = await call(P, 'GET', '/api/data'); ok(x.j.models.length === 16 && x.j.models.some(m => m.name === 'Pub'), 'المنشور يظهر للعامة دون إخفاء العائلات الأولية');
  const pubRow = x.j.models.find(m => m.name === 'Pub');
  x = await call(P, 'PUT', '/api/admin/models/' + pubRow.id, { brand: 'TestBrand', name: 'Pub', notes: '' }, cookie); ok(x.r.status === 200, 'تحديث جزئي يسمح بمسح حقل اختياري');
  x = await call(P, 'GET', '/api/data'); ok(x.j.models.find(m => m.name === 'Pub').notes === '', 'مسح الحقل الاختياري يُحفظ في قاعدة البيانات');
  x = await call(P, 'GET', '/api/admin/sources', null, cookie);
  const linkedSource = x.j[0];
  x = await call(P, 'DELETE', '/api/admin/sources/' + linkedSource.id, null, cookie); ok(x.r.status === 409, 'منع حذف مصدر مرتبط بمحتوى منشور');
  // محرر
  x = await call(P, 'POST', '/api/admin/users', { email: 'ed@test.local', password: 'editor-password-12', role: 'editor' }, cookie); ok(x.r.status === 201, 'إنشاء محرر');
  x = await call(P, 'POST', '/api/admin/users', { email: 'e2@test.local', password: 'short', role: 'editor' }, cookie); ok(x.r.status === 400, 'رفض كلمة مرور قصيرة');
  x = await call(P, 'POST', '/api/admin/login', { email: 'ed@test.local', password: 'editor-password-12' }); const ec = x.r.headers.get('set-cookie').split(';')[0];
  x = await call(P, 'POST', '/api/admin/models', { brand: 'B', name: 'N', status: 'published' }, ec); ok(x.r.status === 403, 'المحرر لا ينشر');
  x = await call(P, 'POST', '/api/admin/users', { email: 'e3@test.local', password: 'editor-password-12', role: 'admin' }, ec); ok(x.r.status === 403, 'المحرر لا ينشئ مستخدمين');
  // اقتراحات AI: مراجعة بشرية إلزامية
  x = await call(P, 'POST', '/api/admin/suggestions', { table: 'codes', origin: 'ai', payload: { code: '*#0000#', purpose: 'اختبار', status: 'published' }, evidence: '' }, ec); ok(x.r.status === 403, 'لا يمرّر المحرر status=published داخل اقتراح');
  x = await call(P, 'POST', '/api/admin/suggestions', { table: 'codes', origin: 'ai', payload: { code: '*#0000#', purpose: 'اختبار', data_level: 'unverified' }, evidence: '' }, ec); const sid = x.j.id; ok(x.r.status === 201, 'إنشاء اقتراح AI معلّق');
  x = await call(P, 'GET', '/api/data'); ok(!x.j.codes.some(c => c.code === '*#0000#'), 'الاقتراح لا يُنشر تلقائيًا');
  x = await call(P, 'POST', `/api/admin/suggestions/${sid}/decide`, { approve: true, reviewed: true }, ec); ok(x.r.status === 403, 'المحرر لا يعتمد');
  x = await call(P, 'POST', `/api/admin/suggestions/${sid}/decide`, { approve: true }, cookie); ok(x.r.status === 400, 'المدير بلا تأكيد مراجعة يُرفض');
  x = await call(P, 'POST', `/api/admin/suggestions/${sid}/decide`, { approve: true, reviewed: true }, cookie); ok(x.r.status === 400, 'اقتراح AI بلا أدلة يُرفض');
  x = await call(P, 'POST', '/api/admin/suggestions', { table: 'codes', origin: 'ai', payload: { code: '*#1111#', purpose: 'اختبار 2' }, evidence: 'دليل مكتوب من صفحة الدعم الرسمية (اختبار)' }, ec);
  x = await call(P, 'POST', `/api/admin/suggestions/${x.j.id}/decide`, { approve: true, reviewed: true }, cookie); ok(x.r.status === 200, 'اعتماد بشري كامل ينجح');
  x = await call(P, 'GET', '/api/data'); ok(x.j.codes.some(c => c.code === '*#1111#'), 'بعد الاعتماد البشري يُنشر');
  // المساعد
  x = await call(P, 'POST', '/api/assistant', { message: 'الهاتف يعيد التشغيل', consent: false }); ok(x.r.status === 400, 'المساعد يتطلب موافقة');
  x = await call(P, 'POST', '/api/assistant', { message: 'ab', consent: true }); ok(x.r.status === 400, 'رفض رسالة قصيرة');
  x = await call(P, 'POST', '/api/assistant', { message: 'x'.repeat(9000), consent: true }); ok(x.r.status === 413, 'رفض طلب كبير الحجم');
  x = await call(P, 'POST', '/api/assistant', { message: 'هاتفي سامسونج يعيد التشغيل بعد التحديث', brand: 'Samsung', consent: true }, null, { 'content-type': 'application/json' });
  ok(x.r.status === 200 && x.j.answer.includes('ردّ تجريبي'), 'المساعد يعمل ضد الخدمة الوهمية (لا ضد Gemini الحقيقية)');
  ok(mk.seen.length === 1 && mk.seen[0].h['x-goog-api-key'] === FAKE_KEY && !x.text.includes(FAKE_KEY), 'المفتاح يُرسل للخدمة من الخادم ولا يظهر في رد العميل');
  const mainHtml = fs.readFileSync(path.join(__dirname, '..', 'public/index.html'), 'utf8');
  ok(mainHtml.includes('CMD.splice(0,CMD.length') && mainHtml.includes('KB.splice(0,KB.length') && mainHtml.includes('verifiedCount'), 'الواجهة تتزامن مع بيانات الخادم وتفرّق بين الموديلات المنشورة والموثقة');
  ok(!mainHtml.includes('codes:[[{') && mainHtml.includes('codes:[{\"code\":\"*#06#'), 'بيانات أكواد الاتصال المحلية في مصفوفة صحيحة عند تشغيل الواجهة المستقلة');
  const pubFiles = ['public/index.html', 'public/sw.js', 'public/admin/index.html'].map(f => fs.readFileSync(path.join(__dirname, '..', f), 'utf8')).join('');
  ok(!pubFiles.includes('GEMINI_API_KEY') && !/sk-ant/.test(pubFiles), 'لا مفاتيح داخل ملفات الواجهة');
  ok(!A.log().includes('هاتفي سامسونج'), 'نص المستخدم لا يُكتب في سجل الخادم');
  for (let i = 0; i < 12; i++) x = await call(P, 'POST', '/api/assistant', { message: 'رسالة اختبار للحد', consent: true });
  ok(x.r.status === 429, 'حد معدل الطلبات يعمل');
  // تحديد محاولات الدخول
  for (let i = 0; i < 6; i++) x = await call(P, 'POST', '/api/admin/login', { email: 'zz@test.local', password: 'wrongwrongwrong' }); ok(x.r.status === 429, 'تحديد محاولات الدخول');
  A.p.kill();
  // بلا مفتاح API
  const B = await start({}, 4502);
  x = await call(4502, 'GET', '/api/health'); ok(x.j.ai === false, 'بلا مفتاح: المساعد غير مهيأ');
  x = await call(4502, 'POST', '/api/assistant', { message: 'اختبار بلا مفتاح', consent: true }); ok(x.r.status === 503, 'بلا مفتاح: رسالة واضحة 503');
  x = await call(4502, 'POST', '/api/admin/login', { email: 'a@a.a', password: 'x' }); ok(x.r.status === 401, 'بلا ADMIN_EMAIL: لا حساب مدير ولا دخول');
  x = await call(4502, 'GET', '/api/data'); ok(x.r.status === 200, 'المحتوى العام يعمل دون API');
  B.p.kill(); mk.s.close();
  // إنتاج بلا سر جلسة
  const bad = spawn(process.execPath, ['server/index.js'], { env: { ...process.env, NODE_ENV: 'production', PORT: 4503, DB_FILE: path.join(os.tmpdir(), 'x' + Date.now() + '.db'), SESSION_SECRET: '' } });
  const code = await new Promise(r => bad.on('exit', r)); ok(code === 1, 'الإنتاج بلا SESSION_SECRET يرفض التشغيل');
  console.log(`\nالنتيجة: ${pass} نجح، ${failN} فشل`); process.exit(failN ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
