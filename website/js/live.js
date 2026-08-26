/* ============================================================
   Eclipse Wallet — live network strip
   Real, live data from CORS-open public APIs (no keys, no CDN):
     · ADA + BTC prices — CoinGecko public API
     · BTC block height — Blockstream public API
   Polls every 60 s, pauses while the tab is hidden, and degrades
   gracefully to "offline" when any call fails (e.g. no network).
   ============================================================ */
(() => {
  'use strict';

  const els = {
    ada: document.getElementById('live-ada'),
    btcPrice: document.getElementById('live-btc-price'),
    btcHeight: document.getElementById('live-btc-height'),
    stamp: document.getElementById('live-stamp'),
  };
  if (!els.ada && !els.btcPrice) return;

  const fmtUsd = (n) => {
    if (n == null || !isFinite(n)) return null;
    const v = Number(n);
    const opts = v < 1 ? { minimumFractionDigits: 2, maximumFractionDigits: 4 }
                        : { maximumFractionDigits: 2 };
    return '$' + v.toLocaleString('en-US', opts);
  };
  const fmtInt = (n) => Number(n).toLocaleString('en-US');

  async function getJson(url) {
    const r = await fetch(url, { headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }

  async function refresh() {
    let ok = false;
    try {
      const p = await getJson(
        'https://api.coingecko.com/api/v3/simple/price?ids=cardano,bitcoin&vs_currencies=usd'
      );
      if (p && p.cardano && p.cardano.usd != null) {
        if (els.ada) els.ada.textContent = fmtUsd(p.cardano.usd);
        ok = true;
      }
      if (p && p.bitcoin && p.bitcoin.usd != null) {
        if (els.btcPrice) els.btcPrice.textContent = fmtUsd(p.bitcoin.usd);
        ok = true;
      }
    } catch { /* offline or rate-limited — keep previous value */ }
    try {
      const h = await getJson('https://blockstream.info/api/blocks/tip/height');
      if (els.btcHeight) els.btcHeight.textContent = 'blk ' + fmtInt(h);
      ok = true;
    } catch { /* keep previous value */ }
    if (els.stamp) {
      els.stamp.textContent = ok
        ? 'live · updated ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : 'waiting for network…';
    }
  }

  let timer = 0;
  function start() {
    if (timer) return;
    refresh();
    timer = setInterval(refresh, 60000);
  }
  function stop() {
    clearInterval(timer);
    timer = 0;
  }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stop(); else start();
  });
  start();
})();
