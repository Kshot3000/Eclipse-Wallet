/* ============================================================
   Eclipse Wallet — living background
   Three blockchains in one canvas:
     · Midnight  — a breathing eclipse whose moon is the NIGHT
                   token mark (ring + three squares), pulsing
                   gently like a slow heartbeat
     · Bitcoin   — a chain of ₿ blocks drifting with data pulses
     · Cardano   — a hexagonal relay lattice with hopping signals,
                   plus small ADA tokens streaking across the sky
                   as shooting stars
   Plus dust motes, mouse parallax and click ripples.
   Vanilla canvas 2D, no dependencies. Respects prefers-reduced-motion.
   ============================================================ */
(() => {
  'use strict';
  const cv = document.getElementById('bg');
  if (!cv || !cv.getContext) return;
  const ctx = cv.getContext('2d');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

  const BLUE = [61, 111, 224];      // Cardano
  const ORANGE = [247, 147, 26];    // Bitcoin
  const WHITE = [230, 236, 248];    // Midnight stars
  const SILVER = [201, 212, 234];   // Midnight (NIGHT mark)
  const BRIGHT = [233, 238, 249];   // Midnight (hands / highlights)
  const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

  const rand = (a, b) => a + Math.random() * (b - a);
  const lerp = (a, b, t) => a + (b - a) * t;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  let W = 0, H = 0;
  let stars = [], motes = [], ripples = [];
  let hexes = [], paths = [];
  let blocks = { xs: [], s: 40 };
  let meteors = [], meteorTimer = 0.8;   // Cardano shooting stars
  const mouse = { tx: 0, ty: 0, x: 0, y: 0 };
  let rippleHue = 0;

  /* ------------------------------ layout ------------------------------ */

  function layout() {
    // Starfield (relative coords so resize keeps them sensible).
    const nStars = Math.round(clamp((W * H) / 14000, 60, 160));
    stars = Array.from({ length: nStars }, () => ({
      x: Math.random(), y: Math.random() * 0.95,
      r: rand(0.4, 1.6), ph: rand(0, Math.PI * 2), sp: rand(0.4, 1.6),
      blue: Math.random() < 0.35,
    }));

    // Dust motes.
    const nMotes = Math.round(clamp((W * H) / 30000, 25, 60));
    motes = Array.from({ length: nMotes }, () => {
      const pick = Math.random();
      return {
        x: Math.random(), y: Math.random(),
        r: rand(0.8, 2.3), vy: rand(4, 13), ph: rand(0, Math.PI * 2),
        col: pick < 0.45 ? BLUE : pick < 0.8 ? ORANGE : WHITE,
        depth: rand(0.4, 1),
      };
    });

    // Cardano hex lattice (lower-left band).
    const hr = clamp(Math.min(W, H) * 0.062, 15, 44);
    const x0 = W * 0.04, y0 = H * 0.72;
    const cols = clamp(Math.floor((W * 0.52) / (hr * Math.sqrt(3))), 4, 10);
    hexes = [];
    for (let row = 0; row < 3; row++) {
      for (let col = 0; col < cols; col++) {
        const cx = x0 + col * hr * Math.sqrt(3) + (row % 2 ? hr * Math.sqrt(3) / 2 : 0);
        const cy = y0 + row * hr * 1.5;
        if (cx > W * 0.60) continue;
        hexes.push({ cx, cy, r: hr });
      }
    }
    // Relay "paths": random walks across the lattice (O(1)-style hops).
    const neighbor = (h) => {
      const cand = hexes.filter((o) => {
        const d = Math.hypot(o.cx - h.cx, o.cy - h.cy);
        return d > hr * 1.3 && d < hr * 2.2;
      });
      return cand.length ? cand[(Math.random() * cand.length) | 0] : null;
    };
    paths = [];
    for (let i = 0; i < 6; i++) {
      const pts = [];
      let cur = hexes[(Math.random() * hexes.length) | 0];
      for (let s = 0; s < 4 && cur; s++) { pts.push({ x: cur.cx, y: cur.cy }); cur = neighbor(cur); }
      if (pts.length >= 2) paths.push({ pts, speed: rand(0.10, 0.2), phase: Math.random() });
    }

    // Bitcoin block chain (full-width band).
    const bs = clamp(Math.min(W, H) * 0.052, 26, 58);
    const n = clamp(Math.round(W / (bs * 3.4)), 5, 11);
    blocks = {
      s: bs,
      xs: Array.from({ length: n }, (_, i) => -bs + ((W + 2 * bs) / (n - 1)) * i),
    };
    ripples = [];
    meteors = [];
    meteorTimer = 0.6;
  }

  function resize() {
    W = window.innerWidth; H = window.innerHeight;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    layout();
    if (reduced) draw(2.2, 0); // one static, composed frame
  }

  /* ------------------------------ layers ------------------------------ */

  function drawStars(t) {
    for (const s of stars) {
      const a = 0.22 + 0.5 * (0.5 + 0.5 * Math.sin(t * s.sp + s.ph));
      ctx.fillStyle = s.blue ? rgba(BLUE, a * 0.9) : rgba(WHITE, a);
      ctx.beginPath();
      ctx.arc(s.x * W + mouse.x * -6, s.y * H + mouse.y * -6, s.r, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  // Shared eclipse geometry so the corona, disk and NIGHT mark stay centered.
  function eclipseCenter() {
    const cx = W * 0.74 + mouse.x * -16;
    const cy = H * 0.40 + mouse.y * -16;
    const R = clamp(Math.min(W, H) * 0.30, 100, 300);
    return { cx, cy, R };
  }

  function drawEclipse(t) {
    const { cx, cy, R } = eclipseCenter();
    const breathe = 1 + 0.035 * Math.sin(t * 0.7);

    // Corona (brightest at the rim, fading orange outward).
    const cr = R * 1.85 * breathe;
    const g = ctx.createRadialGradient(cx, cy, R * 0.90, cx, cy, cr);
    g.addColorStop(0, 'rgba(255, 240, 214, 0.95)');
    g.addColorStop(0.16, rgba(ORANGE, 0.50));
    g.addColorStop(0.45, rgba(ORANGE, 0.15));
    g.addColorStop(1, rgba(ORANGE, 0));
    ctx.fillStyle = g;
    ctx.beginPath(); ctx.arc(cx, cy, cr, 0, Math.PI * 2); ctx.fill();

    // Expanding shock rings (eclipses have personality).
    for (let i = 0; i < 2; i++) {
      const ph = (t * 0.10 + i * 0.5) % 1;
      ctx.strokeStyle = rgba(ORANGE, 0.20 * (1 - ph));
      ctx.lineWidth = 1.2;
      ctx.beginPath(); ctx.arc(cx, cy, R * (1.02 + ph * 0.6), 0, Math.PI * 2); ctx.stroke();
    }

    // The eclipsed disk — near-black with a faint blue sheen (the "moon").
    const dg = ctx.createRadialGradient(cx - R * 0.3, cy - R * 0.35, R * 0.1, cx, cy, R);
    dg.addColorStop(0, '#12141d');
    dg.addColorStop(0.72, '#08090f');
    dg.addColorStop(1, '#04050a');
    ctx.fillStyle = dg;
    ctx.beginPath(); ctx.arc(cx, cy, R * 0.985, 0, Math.PI * 2); ctx.fill();
  }

  /* ----- The moon as the pulsing Midnight NIGHT token mark ----- */
  function drawMidnightPulse(t) {
    const { cx, cy, R } = eclipseCenter();
    const pulse = 0.5 + 0.5 * Math.sin(t * 1.05);  // slow breathing, ≈6s cycle
    const scale = 1 + 0.06 * pulse;                 // gentle size pulse
    const glow = 0.35 + 0.45 * pulse;               // pulsing halo

    const ringR = R * 0.58 * scale;

    // Faint face glow so it reads as a luminous coin, not just a ring.
    const face = ctx.createRadialGradient(cx, cy, R * 0.05, cx, cy, ringR);
    face.addColorStop(0, rgba(SILVER, 0.07 + 0.10 * pulse));
    face.addColorStop(1, rgba(SILVER, 0));
    ctx.fillStyle = face;
    ctx.beginPath(); ctx.arc(cx, cy, ringR, 0, Math.PI * 2); ctx.fill();

    ctx.save();
    ctx.shadowColor = rgba(BRIGHT, glow);
    ctx.shadowBlur = R * (0.06 + 0.10 * pulse);

    // The NIGHT ring.
    ctx.strokeStyle = rgba(SILVER, 0.92);
    ctx.lineWidth = Math.max(2, R * 0.026 * scale);
    ctx.beginPath(); ctx.arc(cx, cy, ringR, 0, Math.PI * 2); ctx.stroke();

    // Three vertical squares (the NIGHT motif) — same proportions as the
    // mark used across the site: side = 0.30·ringR, centers at ±0.444·ringR.
    const s = ringR * 0.30;
    const off = ringR * 0.444;
    ctx.fillStyle = rgba(BRIGHT, 0.98);
    for (const dy of [-off, 0, off]) {
      ctx.beginPath();
      ctx.rect(cx - s / 2, cy + dy - s / 2, s, s);
      ctx.fill();
    }
    ctx.restore();
  }

  /* ------------ Cardano tokens streaking as shooting stars ------------- */
  function spawnMeteor() {
    const fromLeft = Math.random() < 0.5;
    const speed = rand(280, 560) * clamp(W / 1100, 0.7, 1.4);
    const ang = (fromLeft ? 0.62 : Math.PI - 0.62) + rand(-0.10, 0.10);
    const ux = Math.cos(ang), uy = Math.sin(ang);
    meteors.push({
      x: fromLeft ? -60 : W + 60,
      y: rand(-30, H * 0.32),
      vx: ux * speed, vy: uy * speed, ux, uy,
      size: rand(9, 15),
    });
  }

  function updateMeteors(dt) {
    meteorTimer -= dt;
    if (meteorTimer <= 0 && meteors.length < 5) {
      spawnMeteor();
      meteorTimer = rand(1.4, 3.6);
    }
    for (let i = meteors.length - 1; i >= 0; i--) {
      const m = meteors[i];
      m.x += m.vx * dt;
      m.y += m.vy * dt;
      if (m.x < -140 || m.x > W + 140 || m.y > H + 140) meteors.splice(i, 1);
    }
  }

  // The real Cardano mark: a #0133ae coin with 30 white dots in 5 hex rings
  // (measured from the official token). Rings: { r: radius/coinR, s: dotR/coinR,
  // off: base angle, degrees from 12 o'clock clockwise }.
  const ADA_BLUE = [1, 51, 174];
  const ADA_DOTS = [
    { r: 0.22, s: 0.092, off: 30 },
    { r: 0.365, s: 0.054, off: 0 },
    { r: 0.46, s: 0.054, off: 30 },
    { r: 0.60, s: 0.034, off: 0 },
    { r: 0.70, s: 0.033, off: 30 },
  ];
  function drawAdaCoin(x, y, R) {
    ctx.fillStyle = rgba(ADA_BLUE, 1);
    ctx.beginPath(); ctx.arc(x, y, R, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = 'rgba(255,255,255,0.98)';
    for (const d of ADA_DOTS) {
      for (let k = 0; k < 6; k++) {
        const a = (d.off + k * 60) * Math.PI / 180;
        const dx = x + Math.sin(a) * d.r * R;
        const dy = y - Math.cos(a) * d.r * R;
        ctx.beginPath(); ctx.arc(dx, dy, d.s * R, 0, Math.PI * 2); ctx.fill();
      }
    }
  }

  function drawMeteors() {
    if (!meteors.length) return;
    for (const m of meteors) {
      const tl = m.size * 9;
      const bx = m.x - m.ux * tl, by = m.y - m.uy * tl;
      const g = ctx.createLinearGradient(bx, by, m.x, m.y);
      g.addColorStop(0, rgba(BLUE, 0));
      g.addColorStop(0.5, rgba(BLUE, 0.28));
      g.addColorStop(1, rgba([185, 208, 255], 0.85));
      ctx.strokeStyle = g;
      ctx.lineWidth = m.size * 0.55;
      ctx.lineCap = 'round';
      ctx.beginPath(); ctx.moveTo(bx, by); ctx.lineTo(m.x, m.y); ctx.stroke();
      ctx.save();
      ctx.shadowColor = rgba([150, 185, 255], 0.9);
      ctx.shadowBlur = Math.min(m.size * 1.6, 26);
      drawAdaCoin(m.x, m.y, m.size);
      ctx.restore();
    }
  }

  function chainY(x, t) {
    return H * 0.60 + H * 0.022 * Math.sin(x * 0.004 + t * 0.5) + mouse.y * -10;
  }

  function drawChain(t) {
    const { xs, s } = blocks;
    const x0 = -s, x1 = W + s;

    // Link line.
    ctx.strokeStyle = rgba(ORANGE, 0.30);
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let x = x0; x <= x1; x += 10) {
      const y = chainY(x, t);
      x === x0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Blocks.
    for (let i = 0; i < xs.length; i++) {
      const bx = xs[i] + mouse.x * -10;
      const by = chainY(xs[i], t);
      const pulse = 0.7 + 0.3 * Math.sin(t * 2 + i * 1.1);
      const h2 = s / 2;
      ctx.beginPath();
      ctx.rect(bx - h2, by - h2, s, s);
      ctx.fillStyle = rgba(ORANGE, 0.07);
      ctx.fill();
      ctx.strokeStyle = rgba(ORANGE, 0.55 + 0.25 * pulse);
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.beginPath();
      ctx.rect(bx - h2 * 0.55, by - h2 * 0.55, s * 0.55, s * 0.55);
      ctx.strokeStyle = rgba(ORANGE, 0.35);
      ctx.stroke();
      ctx.fillStyle = rgba([255, 208, 140], 0.85 * pulse);
      ctx.font = `700 ${Math.round(s * 0.52)}px system-ui, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('₿', bx, by + s * 0.03);
    }

    // Data pulse traveling the chain (with a short trail).
    const p = (t * 0.09) % 1;
    for (let k = 3; k >= 0; k--) {
      const q = p - k * 0.012;
      if (q < 0 || q > 1) continue;
      const px = x0 + q * (x1 - x0);
      const py = chainY(px, t);
      ctx.fillStyle = k === 0 ? 'rgba(255, 216, 150, 0.95)' : rgba(ORANGE, 0.5 - k * 0.12);
      ctx.beginPath();
      ctx.arc(px, py, k === 0 ? 3.4 : 2.2, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function hexPath(cx, cy, r) {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const a = Math.PI / 6 + (i * Math.PI) / 3;
      const x = cx + r * Math.cos(a), y = cy + r * Math.sin(a);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.closePath();
  }

  function drawHex(t) {
    const ox = mouse.x * -14, oy = mouse.y * -14;
    for (const h of hexes) {
      const breath = 0.30 + 0.18 * Math.sin(t * 0.6 + h.cx * 0.01 + h.cy * 0.008);
      hexPath(h.cx + ox, h.cy + oy, h.r);
      ctx.fillStyle = rgba(BLUE, 0.045);
      ctx.fill();
      ctx.strokeStyle = rgba(BLUE, breath);
      ctx.lineWidth = 1.2;
      ctx.stroke();
      // Node dots at vertices.
      ctx.fillStyle = rgba(BLUE, 0.55);
      for (let i = 0; i < 6; i++) {
        const a = Math.PI / 6 + (i * Math.PI) / 3;
        ctx.beginPath();
        ctx.arc(h.cx + ox + h.r * Math.cos(a), h.cy + oy + h.r * Math.sin(a), 1.5, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    // Relay signals hopping between nodes.
    for (const p of paths) {
      const n = p.pts.length;
      const u = (t * p.speed + p.phase) % 1;
      const seg = Math.min(n - 2, Math.floor(u * (n - 1)));
      const local = u * (n - 1) - seg;
      const a = p.pts[seg], b = p.pts[seg + 1];
      const px = lerp(a.x, b.x, local) + ox, py = lerp(a.y, b.y, local) + oy;
      ctx.fillStyle = 'rgba(150, 185, 255, 0.9)';
      ctx.beginPath(); ctx.arc(px, py, 2.6, 0, Math.PI * 2); ctx.fill();
      const q = ((t * p.speed + p.phase) % 1) - 0.02;
      if (q >= 0) {
        const seg2 = Math.min(n - 2, Math.floor(q * (n - 1)));
        const local2 = q * (n - 1) - seg2;
        const a2 = p.pts[seg2], b2 = p.pts[seg + 1];
        ctx.fillStyle = rgba(BLUE, 0.45);
        ctx.beginPath();
        ctx.arc(lerp(a2.x, b2.x, local2) + ox, lerp(a2.y, b2.y, local2) + oy, 1.8, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  function drawMotes(t) {
    for (const m of motes) {
      const y = ((m.y - (t * m.vy) / H) % 1 + 1) % 1;
      const x = (m.x + 0.004 * Math.sin(t * 0.5 + m.ph)) % 1;
      const a = 0.10 + 0.22 * m.depth;
      ctx.fillStyle = rgba(m.col, a);
      ctx.beginPath();
      ctx.arc(x * W + mouse.x * -16 * m.depth, y * H + mouse.y * -16 * m.depth, m.r * m.depth, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function drawRipples(t) {
    for (let i = ripples.length - 1; i >= 0; i--) {
      const rp = ripples[i];
      const age = t - rp.t0;
      if (age > 0.9 || age < 0) { ripples.splice(i, 1); continue; }
      const k = age / 0.9;
      ctx.strokeStyle = rp.blue ? rgba(BLUE, 0.4 * (1 - k)) : rgba(ORANGE, 0.4 * (1 - k));
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(rp.x, rp.y, 8 + k * 130, 0, Math.PI * 2);
      ctx.stroke();
    }
  }

  function draw(t, dt) {
    ctx.clearRect(0, 0, W, H);
    drawStars(t);
    if (!reduced) updateMeteors(dt);
    drawMeteors();
    drawEclipse(t);
    drawMidnightPulse(t);
    drawChain(t);
    drawHex(t);
    drawMotes(t);
    drawRipples(t);
  }

  /* ------------------------------ loop -------------------------------- */

  let raf = 0;
  let lastNow = 0;
  function frame(now) {
    const dt = clamp((now - lastNow) / 1000, 0, 0.05);
    lastNow = now;
    const t = now / 1000;
    mouse.x += (mouse.tx - mouse.x) * 0.06;
    mouse.y += (mouse.ty - mouse.y) * 0.06;
    draw(t, dt);
    raf = requestAnimationFrame(frame);
  }

  function start() {
    if (reduced) { draw(2.2, 0); return; } // static composed frame
    cancelAnimationFrame(raf);
    lastNow = performance.now();
    raf = requestAnimationFrame(frame);
  }

  /* ------------------------------ events ------------------------------ */

  let rt = 0;
  window.addEventListener('resize', () => {
    clearTimeout(rt);
    rt = setTimeout(resize, 120);
  });
  window.addEventListener('pointermove', (e) => {
    mouse.tx = e.clientX / W - 0.5;
    mouse.ty = e.clientY / H - 0.5;
  }, { passive: true });
  window.addEventListener('pointerdown', (e) => {
    if (reduced) return;
    ripples.push({ x: e.clientX, y: e.clientY, t0: performance.now() / 1000, blue: (rippleHue++ % 2 === 0) });
  }, { passive: true });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) cancelAnimationFrame(raf);
    else start();
  });

  resize();
  start();
})();
