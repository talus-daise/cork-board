// Corkboard service worker: offline app shell + runtime caching
const VERSION = 'v1';
const SHELL = `cork-shell-${VERSION}`;
const RUNTIME = `cork-runtime-${VERSION}`;
const SHELL_URLS = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/icon-192.png',
  '/icon-512.png',
  '/icon-maskable-512.png',
  '/apple-touch-icon.png',
  '/favicon-32.png'
];

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(SHELL);
    await c.addAll(SHELL_URLS.map(u => new Request(u, { cache: 'reload' })));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== SHELL && k !== RUNTIME).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  if (url.origin === self.location.origin && url.pathname.startsWith('/api/')) return;

  if (req.mode === 'navigate') {
    e.respondWith((async () => {
      try {
        const fresh = await fetch(req);
        if (fresh && fresh.status === 200) {
          const c = await caches.open(SHELL);
          c.put('/index.html', fresh.clone());
        }
        return fresh;
      } catch {
        return (await caches.match(req)) || (await caches.match('/index.html')) || Response.error();
      }
    })());
    return;
  }

  if (url.origin === self.location.origin) {
    e.respondWith(staleWhileRevalidate(req, SHELL));
    return;
  }
  e.respondWith(cacheFirst(req, RUNTIME));
});

async function staleWhileRevalidate(req, cacheName) {
  const c = await caches.open(cacheName);
  const cached = await c.match(req);
  const network = fetch(req).then(res => {
    if (res && res.status === 200) c.put(req, res.clone());
    return res;
  }).catch(() => null);
  return cached || network || Response.error();
}

async function cacheFirst(req, cacheName) {
  const c = await caches.open(cacheName);
  const cached = await c.match(req);
  if (cached) return cached;
  try {
    const res = await fetch(req);
    if (res && (res.status === 200 || res.type === 'opaque')) c.put(req, res.clone());
    return res;
  } catch {
    return cached || Response.error();
  }
}
