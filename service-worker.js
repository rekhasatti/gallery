const C='my-gallery-shell-v2',F=['./','index.html','style.css','script.js','manifest.json','icon-192.png','icon-512.png','icon-maskable-512.png'];
self.addEventListener('install',e=>e.waitUntil(caches.open(C).then(c=>c.addAll(F.map(f=>new Request(f,{cache:'reload'})))).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{const r=e.request;if(r.method!=='GET'||new URL(r.url).origin!==location.origin)return;
e.respondWith(caches.match(r,{ignoreSearch:true}).then(m=>m||fetch(r).then(n=>{if(n.ok&&F.some(f=>r.url.endsWith(f.replace('./',''))))caches.open(C).then(c=>c.put(r,n.clone()));return n}).catch(()=>r.mode==='navigate'?caches.match('index.html'):undefined)))});
