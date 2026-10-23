// The page is the game world. Scrolling goes down from the sky, where each falling bug is a real
// advisory, past your org on the surface, and through the layers br reads. Sections pick their layer
// with data-zone and name it with data-level, which the HUD shows. Click the sky to check a bug.
(() => {
  const {P, SEV, text, bug: drawBug, machine} = window.PX;
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const R = (a, b) => a + Math.random() * (b - a);
  const $ = id => document.getElementById(id);
  const say = (id, v) => { const e = $(id); if (e && e.textContent !== String(v)) e.textContent = v; };

  // ---------- data ----------
  // Used only when the live feed can't be reached; the page says so wherever it shows them.
  const SAMPLE = [
    {id:'CVE-2026-109618', sev:'critical', pkg:'runtime php', sum:'PHP2Shell: code execution in PHP', cmd:'br hunt runtime:php@fixed:8.5.12,8.4.27,8.3.36,8.2.35'},
    {id:'NODE 2026-10', sev:'high', pkg:'runtime node', sum:'Node.js October security release', cmd:'br hunt runtime:node@fixed:22.23.4,24.22.1,26.12.1'},
    {id:'CA DISTRUST', sev:'high', pkg:'cert emSign ECC G3', sum:'emSign ECC Root CA - G3 distrusted', cmd:'br hunt "cert:subject:emSign ECC Root CA - G3"'},
    {id:'RAILWAY', sev:'critical', pkg:'secret RAILWAY_*', sum:'Railway breach: rotate RAILWAY_* secrets', cmd:"br hunt 'secret:RAILWAY_*' --since DATE"},
    {id:'SAMPLE-01', sev:'medium', pkg:'npm example-parser', sum:'Sample: prototype pollution in a parser', cmd:'br hunt npm:example-parser@2.1.0'},
    {id:'SAMPLE-02', sev:'low', pkg:'pypi example-yaml', sum:'Sample: unsafe load by default', cmd:'br hunt pypi:example-yaml@5.0.1'},
    {id:'SAMPLE-03', sev:'high', pkg:'cargo example-tls', sum:'Sample: certificate check skipped', cmd:'br hunt cargo:example-tls@0.9.2'},
    {id:'SAMPLE-04', sev:'medium', pkg:'go example-router', sum:'Sample: path traversal', cmd:'br hunt go:example.com/router@1.4.0'}
  ];
  let ADV = SAMPLE, live = false, qi = 0;
  const feed = new EventTarget();
  window.brFeed = feed;

  function source(isLive, why) {
    const s = $('src'), n = $('srcnote');
    if (s) { s.textContent = isLive ? 'LIVE' : 'SAMPLE'; s.className = 'src' + (isLive ? '' : ' sample'); }
    if (n) { n.textContent = isLive ? `Live: the ${ADV.length} newest reviewed advisories on GitHub.` : `Sample advisories: the live feed is ${why}.`; n.className = 'src' + (isLive ? '' : ' sample'); }
  }
  function emit(d) { window.brData = d; feed.dispatchEvent(new CustomEvent('data', {detail:d})); }
  async function load() {
    const key = 'br-adv-v2';
    try { const c = JSON.parse(sessionStorage.getItem(key) || 'null'); if (c && Date.now() - c.t < 6e5 && c.list.length) return use(c.list); } catch {}
    try {
      const ctl = new AbortController(); setTimeout(() => ctl.abort(), 5000);
      const r = await fetch('https://api.github.com/advisories?per_page=50&type=reviewed', {signal:ctl.signal, headers:{Accept:'application/vnd.github+json'}});
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const list = (await r.json()).map(a => {
        const p = (a.vulnerabilities || [])[0]?.package;
        return {id:a.ghsa_id, sev:SEV[a.severity] ? a.severity : 'medium', pkg:p ? `${p.ecosystem} ${p.name}` : (a.cve_id || ''),
          sum:a.summary || '', url:a.html_url, date:a.published_at || '', cmd:`br hunt --advisory ${a.ghsa_id}`};
      }).filter(a => a.id);
      if (list.length < 5) throw new Error('short list');
      try { sessionStorage.setItem(key, JSON.stringify({t:Date.now(), list})); } catch {}
      use(list);
    } catch (e) {
      const why = e.name === 'AbortError' ? 'timed out' : /HTTP 403|HTTP 429/.test(e.message) ? 'rate limited right now' : 'not reachable from here';
      source(false, why); emit({list:ADV, live:false, why});
    }
  }
  function use(list) { ADV = list; live = true; qi = 0; source(true); emit({list, live:true}); }

  // ---------- world ----------
  const out = $('world'); if (!out) { load(); return; }
  const o = out.getContext('2d'), buf = document.createElement('canvas'), x = buf.getContext('2d');
  const KINDS = [['repo', 'REPO'], ['ci', 'CI'], ['images', 'IMAGES'], ['laptop', 'LAPTOP'], ['cache', 'CACHE'], ['keys', 'SECRETS'], ['certs', 'CERTS']];
  // Underground layers: base, band, pebble and highlight colours, a decoration and how often it appears.
  const LAYERS = {
    topsoil:{a:'#22173a', b:'#2a1d48', p:'#3f2c66', hi:'#5a4290', deco:'roots', dn:.35},
    clay:{a:'#271532', b:'#2f1a3e', p:'#4a2656', hi:'#6a3a78', deco:'files', dn:.4},
    stone:{a:'#131b34', b:'#182240', p:'#26365e', hi:'#3a5288', deco:'cables', dn:.3},
    deep:{a:'#0d1630', b:'#111c3a', p:'#1b2e52', hi:'#2a4a7a', deco:'crystals', dn:.35},
    bedrock:{a:'#100c1c', b:'#161124', p:'#241d3c', hi:'#3a3060', deco:'files', dn:.15},
    core:{a:'#170e10', b:'#1e1214', p:'#3a1e16', hi:'#6a3a1a', deco:'gold', dn:.45}
  };
  const hash = (a, b) => { let h = (a * 374761393 + b * 668265263) | 0; h = Math.imul(h ^ (h >>> 13), 1274126177); return ((h ^ (h >>> 16)) >>> 0) / 4294967296; };
  const short = id => String(id).slice(0, 15);
  let k = 3, W = 0, H = 0, dpr = 1, zones = [], ground = null, ms = [], sy = 0;
  let bugs = [], nets = [], floats = [], spawnT = .4, fireT = .9, checked = 0, found = 0, clock = 0, scan = 0;

  function layout() {
    const vw = document.documentElement.clientWidth, vh = innerHeight;
    k = vw < 640 ? 2 : vw < 1700 ? 3 : 4; dpr = devicePixelRatio || 1;
    W = Math.ceil(vw / k); H = Math.ceil(vh / k);
    out.width = Math.round(vw * dpr); out.height = Math.round(vh * dpr);
    buf.width = W; buf.height = H;
    zones = [...document.querySelectorAll('[data-zone]')].map(el => {
      const r = el.getBoundingClientRect();
      return {name:el.dataset.zone, level:el.dataset.level || '', top:(r.top + scrollY) / k, bot:(r.bottom + scrollY) / k};
    });
    // Layers run edge to edge: each one reaches down to the next, the first starts at the top, the last runs to the end.
    zones.forEach((z, i) => { if (zones[i + 1]) z.bot = zones[i + 1].top; });
    if (zones.length) { zones[0].top = 0; zones[zones.length - 1].bot = document.documentElement.scrollHeight / k + H; }
    const sky = zones.find(z => z.name === 'sky');
    ground = sky ? Math.round(sky.bot) : null;
    const n = Math.max(3, Math.min(7, Math.floor(W / 58)));
    const old = ms; ms = [];
    for (let i = 0; i < n; i++) ms.push({kind:KINDS[i][0], label:KINDS[i][1], x:Math.round(W * (i + .5) / n), sick:old[i]?.sick || 0, fix:0});
    bugs.forEach(b => { b.m = ms[Math.min(ms.length - 1, b.mi)] || ms[0]; b.tx = b.m.x - 4; });
    sy = scrollY / k;
  }

  function step(dt) {
    clock += dt;
    if (ground != null && sy < ground && ms.length) {
      spawnT -= dt;
      if (spawnT <= 0 && bugs.length < 7) {
        spawnT = R(1, 2); const mi = Math.random() * ms.length | 0, m = ms[mi];
        bugs.push({a:ADV[qi++ % ADV.length], x:m.x - 4 + R(-40, 40), tx:m.x - 4, y:sy - 10, v:R(11, 18), m, mi, f:0});
      }
    }
    for (const b of bugs) {
      b.y += b.v * dt; b.x += (b.tx - b.x) * Math.min(1, dt * .3); b.f += dt;
      if (!b.dead && b.y + 8 >= ground - 20) {
        b.dead = true; found++; b.m.sick = 4; b.m.fix = 0;
        floats.push({x:b.m.x, y:ground - 32, txt:'FOUND IN ' + b.m.label, col:P.hot, t:0});
      }
    }
    for (const m of ms) {
      if (m.sick > 0) { m.sick -= dt; if (m.sick <= 0) { m.fix = 1; floats.push({x:m.x, y:ground - 32, txt:'FIXED', col:P.go, t:0}); } }
      else if (m.fix > 0) m.fix = Math.max(0, m.fix - dt);
    }
    // Autopilot: check the lowest bug on screen, and let a few through so the places light up too.
    fireT -= dt;
    if (fireT <= 0) {
      fireT = R(.7, 1.3);
      const vis = bugs.filter(b => !b.dead && !b.aimed && b.y > sy + 6 && b.y < Math.min(sy + H - 10, ground - 44));
      if (vis.length && Math.random() < .78) { const b = vis.sort((p, q) => q.y - p.y)[0]; b.aimed = true; shoot(b.x + 4, b.y + 4 + b.v * .14); }
    }
    for (const n of nets) {
      n.t += dt;
      if (!n.done && n.t >= .14) {
        n.done = true;
        for (const b of bugs) if (!b.dead && Math.abs(b.x + 4 - n.x) < 11 && Math.abs(b.y + 4 - n.y) < 11) {
          b.dead = true; checked++; floats.push({x:b.x + 4, y:b.y - 6, txt:'CHECKED ' + short(b.a.id), col:P.go, t:0});
        }
      }
    }
    nets = nets.filter(n => n.t < .5); bugs = bugs.filter(b => !b.dead);
    for (const f of floats) f.t += dt; floats = floats.filter(f => f.t < 1.6);
    scan = Math.max(0, scan - dt);
    say('checked', checked); say('found', found);
  }
  const droid = () => ({x:W > 380 ? W - 22 : W - 14, y:Math.round(H * .46 + Math.sin(clock * 2) * 2)});
  function shoot(tx, ty) { const d = droid(); nets.push({x:tx, y:ty, sx:d.x, sy:d.y + sy, t:0}); }

  function line(x0, y0, x1, y1, c) {
    const n = Math.max(Math.abs(x1 - x0), Math.abs(y1 - y0)) | 0; x.fillStyle = c;
    for (let i = 0; i <= n; i += 2) x.fillRect(Math.round(x0 + (x1 - x0) * i / n), Math.round(y0 + (y1 - y0) * i / n), 1, 1);
  }
  function ring(cx, cy, r, c) { x.fillStyle = c; for (let a = 0; a < 6.283; a += .35) x.fillRect(Math.round(cx + Math.cos(a) * r), Math.round(cy + Math.sin(a) * r), 1, 1); }
  function gem(px, py, c) { x.fillStyle = c; x.fillRect(px + 2, py, 1, 1); x.fillRect(px + 1, py + 1, 3, 1); x.fillRect(px, py + 2, 5, 1); x.fillRect(px + 1, py + 3, 3, 1); x.fillRect(px + 2, py + 4, 1, 1); x.fillStyle = P.white; x.fillRect(px + 2, py + 1, 1, 1); }

  function sky(t, b) {
    const g = x.createLinearGradient(0, t, 0, b); g.addColorStop(0, P.sky0); g.addColorStop(.7, P.sky1); g.addColorStop(1, P.sky2);
    x.fillStyle = g; x.fillRect(0, Math.max(t, 0), W, Math.min(b, H) - Math.max(t, 0));
    const off = Math.round(sy * .5), y1 = Math.min(b, H);
    for (let gy = Math.floor((Math.max(t, 0) + off) / 7); gy * 7 - off < y1; gy++) for (let gx = 0; gx * 7 < W; gx++) {
      const h = hash(gx, gy); if (h > .05) continue;
      const py = gy * 7 - off + ((h * 1e4 | 0) % 7); if (py >= y1 - 30) continue;
      x.fillStyle = h < .012 ? (((clock * 1.5 + h * 300) | 0) % 3 ? P.white : P.m1) : P.m2; x.fillRect(gx * 7 + ((h * 1e3 | 0) % 7), py, 1, 1);
    }
    const mx = Math.round(W * .84), my = Math.round(26 - sy * .5);    // moon
    if (my > -12) { x.fillStyle = '#e9e4ff'; for (let j = -7; j <= 7; j++) { const w = Math.round(Math.sqrt(49 - j * j)); x.fillRect(mx - w, my + j, w * 2, 1); }
      x.fillStyle = '#c9c2ff'; x.fillRect(mx - 3, my - 2, 2, 2); x.fillRect(mx + 2, my + 2, 3, 2); x.fillRect(mx - 1, my + 4, 2, 1); }
    const gy = b;
    if (gy > 0 && gy - 40 < H) for (let i = 0; i < W; i++) {    // two ranges of hills on the horizon
      const h1 = 22 + Math.round(Math.sin(i * .021 + 1) * 8 + Math.sin(i * .053) * 4), h2 = 10 + Math.round(Math.sin(i * .037 + 2) * 4 + Math.sin(i * .11) * 2);
      x.fillStyle = '#1b1838'; x.fillRect(i, gy - h1, 1, h1); x.fillStyle = '#14122a'; x.fillRect(i, gy - h2, 1, h2);
    }
  }
  function deco(L, px, py, h) {
    if (L.deco === 'roots') { x.fillStyle = L.p; for (let j = 0; j < 12; j++) x.fillRect(px + Math.round(Math.sin(j * .7 + h * 9) * 2), py + j, 1, 1); }
    if (L.deco === 'files') { // deleted layers: buried file pages
      x.fillStyle = L.p; x.fillRect(px, py, 7, 9); x.fillStyle = L.a; x.fillRect(px + 5, py, 2, 2);
      x.fillStyle = L.hi; x.fillRect(px + 1, py + 3, 4, 1); x.fillRect(px + 1, py + 5, 5, 1); x.fillRect(px + 1, py + 7, 3, 1);
    }
    if (L.deco === 'cables') { x.fillStyle = L.p; x.fillRect(px - 24, py, 64, 1); x.fillStyle = ((clock * 2 + h * 10) | 0) % 2 ? P.cool : L.hi; x.fillRect(px, py - 1, 3, 3); }
    if (L.deco === 'crystals') { x.globalAlpha = .75; gem(px, py, P.cool); x.globalAlpha = 1; }
    if (L.deco === 'gold') { x.globalAlpha = .18; x.fillStyle = P.org; x.fillRect(px - 3, py - 3, 11, 11); x.globalAlpha = 1; gem(px, py, P.coin); }
  }
  function layer(z, i, t, b) {
    const L = LAYERS[z.name] || LAYERS.stone, y0 = Math.max(t, 0), y1 = Math.min(b, H), s = Math.round(sy);
    x.save(); x.beginPath(); x.rect(0, y0, W, y1 - y0); x.clip();
    x.fillStyle = L.a; x.fillRect(0, y0, W, y1 - y0);
    for (let gy = Math.floor((y0 + s) / 16); gy * 16 - s < y1; gy++) if (hash(gy, 5) < .4) { x.fillStyle = L.b; x.fillRect(0, gy * 16 - s, W, 3 + (hash(gy, 6) * 6 | 0)); }
    for (let gy = Math.floor((y0 + s) / 6); gy * 6 - s < y1; gy++) for (let gx = 0; gx * 6 < W; gx++) {
      const h = hash(gx, gy); if (h > .2) continue;
      x.fillStyle = h < .03 ? L.hi : h < .1 ? L.p : L.b; x.fillRect(gx * 6 + (h * 97 | 0) % 5, gy * 6 - s + (h * 53 | 0) % 5, h < .06 ? 2 : 1, 1);
    }
    for (let gy = Math.floor((y0 + s) / 48) - 1; gy * 48 - s < y1; gy++) for (let gx = 0; gx * 48 < W + 48; gx++) {
      const h = hash(gx + 777, gy); if (h < L.dn) deco(L, gx * 48 + (h * 311 | 0) % 30, gy * 48 - s + (h * 173 | 0) % 30, h);
    }
    if (z.name === 'core') { const g = x.createLinearGradient(0, t, 0, b); g.addColorStop(0, 'rgba(255,154,60,0)'); g.addColorStop(1, 'rgba(255,154,60,.28)'); x.fillStyle = g; x.fillRect(0, y0, W, y1 - y0); }
    x.restore();
    if (t > -4 && t < H) for (let xx = 0; xx < W; xx += 3) {    // ragged top edge into the layer above
      const d = hash(xx / 3 | 0, i * 13) * 4 | 0; x.fillStyle = L.a; x.fillRect(xx, t - d, 3, d); x.fillStyle = L.hi; x.fillRect(xx, t - d, 3, 1);
    }
  }
  function draw() {
    x.fillStyle = P.sky0; x.fillRect(0, 0, W, H);
    zones.forEach((z, i) => { const t = Math.round(z.top - sy), b = Math.round(z.bot - sy); if (b < 0 || t > H) return; z.name === 'sky' ? sky(t, b) : layer(z, i, t, b); });
    if (ground != null) {
      const g = Math.round(ground - sy);
      if (g > -30 && g < H + 30) {
        x.fillStyle = P.m1; x.fillRect(0, g, W, 2); x.fillStyle = P.m2; x.fillRect(0, g, W, 1);
        for (const m of ms) machine(x, m.kind, m.x, g, clock, m.sick > 0, m.fix, m.label);
      }
    }
    for (const b of bugs) { const by = Math.round(b.y - sy); drawBug(x, b.x, by, SEV[b.a.sev] || P.coin, (b.f * 6 | 0) & 1); if (by > 10) text(x, short(b.a.id), b.x + 4, by - 7, P.m2, true); }
    for (const n of nets) n.t < .14 ? line(n.sx, n.sy - sy, n.x, n.y - sy, P.cool) : ring(n.x, n.y - sy, Math.round((n.t - .14) / .36 * 11) + 2, P.go);
    for (const f of floats) { x.globalAlpha = Math.max(0, 1 - f.t / 1.6); text(x, f.txt, f.x, f.y - sy - f.t * 8, f.col, true); }
    x.globalAlpha = 1;
    const d = droid();
    if (scan > 0) { x.globalAlpha = Math.min(1, scan * 3) * .55; x.fillStyle = P.cool; x.fillRect(0, d.y + 2, W, 1); x.globalAlpha *= .3; x.fillRect(0, d.y, W, 5); x.globalAlpha = 1; }
    const blink = (clock * 2 | 0) % 2, eye = Math.round(Math.sin(clock * .8) * 2);
    x.fillStyle = P.ink; x.fillRect(d.x - 6, d.y - 4, 13, 10); x.fillRect(d.x, d.y - 7, 1, 3);
    x.fillStyle = P.m1; x.fillRect(d.x - 5, d.y - 3, 11, 8); x.fillStyle = P.m2; x.fillRect(d.x - 5, d.y - 3, 11, 1);
    x.fillStyle = P.ink; x.fillRect(d.x - 4, d.y - 1, 9, 3); x.fillStyle = P.cool; x.fillRect(d.x - 1 + eye, d.y, 3, 1);
    x.fillStyle = blink ? P.go : '#2a7a4a'; x.fillRect(d.x - 1, d.y - 9, 3, 2);
    x.fillStyle = (clock * 12 | 0) % 2 ? P.org : P.coin; x.fillRect(d.x - 2, d.y + 6, 5, 1 + ((clock * 12 | 0) % 2));
    o.imageSmoothingEnabled = false; o.drawImage(buf, 0, 0, W, H, 0, 0, W * k * dpr, H * k * dpr);
  }
  function hud() {
    const probe = (scrollY + innerHeight * .35) / k; let cur = zones[0];
    for (const z of zones) if (z.top <= probe) cur = z;
    if (cur) say('lvl', cur.level);
  }

  addEventListener('scroll', () => { const ny = scrollY / k; if (Math.abs(ny - sy) > .3) scan = .45; sy = ny; hud(); if (reduce) draw(); }, {passive:true});
  document.addEventListener('pointerdown', e => {
    if (ground == null || e.button > 0 || e.target.closest('a,button,input,summary,pre,table,.win,.hud')) return;
    const wx = e.clientX / k, wy = e.clientY / k + sy; if (wy < ground - 20) shoot(wx, wy);
  });
  const refit = () => { layout(); hud(); draw(); };
  new ResizeObserver(refit).observe(document.body);
  addEventListener('resize', refit);

  let last = 0, running = false;
  function frame(now) {
    if (document.hidden) { running = false; return; }
    const dt = Math.min(.05, last ? (now - last) / 1000 : 0); last = now; step(dt); draw(); requestAnimationFrame(frame);
  }
  function start() { if (running || reduce) return; running = true; last = 0; requestAnimationFrame(frame); }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) start(); });
  window.brGame = () => ({checked, found, bugs:bugs.length, source:live ? 'live' : 'sample', k, W, H, zones:zones.map(z => z.name), running});

  refit(); load(); start();
})();
