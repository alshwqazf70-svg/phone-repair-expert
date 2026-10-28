'use strict';
// يخزّن غلاف التطبيق الثابت فقط. لا يخزّن /api (لا بيانات إدارة ولا ردود مساعد ولا أسرار).
const V = 'phone-repair-v7-1'; // غيّر الرقم عند تعديل الملفات ليصل التحديث للمستخدمين
const SHELL = ['/', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png'];
self.addEventListener('install', e => e.waitUntil(caches.open(V).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/') || u.pathname.startsWith('/admin')) return;
  if (e.request.mode === 'navigate') { // الشبكة أولًا ثم النسخة المخزنة عند انقطاع الاتصال
    e.respondWith(fetch(e.request).then(r => { const c = r.clone(); caches.open(V).then(x => x.put('/', c)); return r; }).catch(() => caches.match('/')));
    return;
  }
  e.respondWith(caches.match(e.request).then(h => h || fetch(e.request)));
});
