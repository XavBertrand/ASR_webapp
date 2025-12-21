const CACHE_NAME = 'asr-app-cache-v4';

// Pas de mise en cache agressive : on laisse le navigateur gérer pour éviter tout HTML/CSP périmé.
self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    await caches.delete(CACHE_NAME);
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map((key) => caches.delete(key)));
    await self.clients.claim();
  })());
});

// Pas d'interception fetch : tout passe en direct (plus de cache SW).
