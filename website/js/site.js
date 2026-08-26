/* ============================================================
   Eclipse Wallet — site interactions
   · scroll-reveal
   · copy buttons (clipboard + fallback)
   · donation QR codes (vendored qrcode.js — zero network calls)
   · footer year
   ============================================================ */
(() => {
  'use strict';

  /* ------------------------- scroll reveal ------------------------- */
  const reveals = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && reveals.length) {
    const io = new IntersectionObserver((entries) => {
      for (const en of entries) {
        if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); }
      }
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });
    reveals.forEach((el) => io.observe(el));
  } else {
    reveals.forEach((el) => el.classList.add('in'));
  }

  /* --------------------------- copy buttons ------------------------ */
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch { ok = false; }
      ta.remove();
      return ok;
    }
  }

  document.addEventListener('click', async (e) => {
    const btn = e.target && e.target.closest ? e.target.closest('[data-copy]') : null;
    if (!btn) return;
    const ok = await copyText(btn.dataset.copy);
    const label = btn.querySelector('.copy-label') || btn;
    const orig = label.dataset.orig || (label.dataset.orig = label.textContent);
    label.textContent = ok ? 'Copied ✓' : 'Copy failed';
    setTimeout(() => { label.textContent = orig; }, 1600);
  });

  /* ------------------------- donation QR codes --------------------- */
  function makeQR(el, text) {
    if (typeof window.qrcode !== 'function') { el.innerHTML = ''; return; }
    try {
      const qr = window.qrcode(10, 'M');
      qr.addData(text);
      qr.make();
      el.innerHTML = qr.createImgTag(2, 2);
      const img = el.querySelector('img');
      if (img) { img.style.width = '100%'; img.style.height = 'auto'; img.style.imageRendering = 'pixelated'; }
    } catch { el.innerHTML = ''; }
  }
  document.querySelectorAll('.qr[data-addr]').forEach((el) => makeQR(el, el.dataset.addr));

  /* ------------------------------ year ------------------------------ */
  const y = document.querySelector('[data-year]');
  if (y) y.textContent = String(new Date().getFullYear());
})();
