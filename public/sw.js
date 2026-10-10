// Minimal service worker: cache the static app shell for installability/offline.
// API calls and capability links always go to the network (never cache ciphertext
// reads or auth). Bump CACHE to invalidate the shell.
const CACHE = "relay-shell-v1";
const SHELL = [
  "/", "/index.html", "/css/style.css",
  "/js/app.js", "/js/api.js", "/js/ui.js", "/js/crypto.js", "/js/webauthn.js",
  "/manifest.webmanifest",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  // Never intercept the API or cross-origin (CDN modules) requests.
  if (url.origin !== location.origin || url.pathname.startsWith("/api/")) return;

  // Capability links (/c/, /g/) and navigations: serve the app shell.
  if (e.request.mode === "navigate") {
    e.respondWith(fetch(e.request).catch(() => caches.match("/index.html")));
    return;
  }
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
});
