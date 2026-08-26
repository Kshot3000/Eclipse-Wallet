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

  /* ------------------- nav / TOC active link scroll-spy ------------- */
  const navLinks = Array.from(
    document.querySelectorAll('.nav .links a[href^="#"], .toc a[href^="#"]')
  );
  if (navLinks.length && 'IntersectionObserver' in window) {
    const byId = new Map(navLinks.map((a) => ['#' + a.getAttribute('href').slice(1), a]));
    const io = new IntersectionObserver((entries) => {
      for (const en of entries) {
        if (!en.isIntersecting) continue;
        const link = byId.get('#' + en.target.id);
        if (!link) continue;
        navLinks.forEach((a) => a.classList.remove('active'));
        link.classList.add('active');
      }
    }, { rootMargin: '-40% 0px -55% 0px' });
    byId.forEach((_, id) => {
      const el = document.getElementById(id.slice(1));
      if (el) io.observe(el);
    });
  }

  /* ---------------------------- back to top -------------------------- */
  const totop = document.querySelector('.totop');
  if (totop) {
    let ticking = false;
    const onScroll = () => {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        totop.classList.toggle('show', window.scrollY > 700);
        ticking = false;
      });
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    totop.addEventListener('click', () => {
      const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
      window.scrollTo({ top: 0, behavior: reduced ? 'auto' : 'smooth' });
    });
  }
})();
