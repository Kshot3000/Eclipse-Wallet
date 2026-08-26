/* ============================================================
   Eclipse Wallet — live network strip
   Real, live data from CORS-open public APIs (no keys, no CDN):
     · ADA + NIGHT + BTC prices & 24 h change — CoinGecko public API
       (NIGHT is Midnight's token, CoinGecko id `midnight-3`)
     · BTC block height — Blockstream public API
   Polls every 60 s, pauses while the tab is hidden, and degrades
   gracefully to "offline" when any call fails (e.g. no network).
   Prices also feed the chain cards (live price badges) and the
   wallet mock's portfolio total.
   ============================================================ */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const els = {
    ada: $('live-ada'), adaChg: $('live-ada-chg'),
    btcPrice: $('live-btc-price'), btcChg: $('live-btc-chg'), btcHeight: $('live-btc-height'),
    night: $('live-night'), nightChg: $('live-night-chg'),
    priceAda: $('price-ada'), priceNight: $('price-night'), priceBtc: $('price-btc'),
    wmTotal: $('wm-total'),
    stamp: $('live-stamp'),
  };
  if (!els.ada && !els.btcPrice && !els.night) return;

  const fmtUsd = (n) => {
    if (n == null || !isFinite(n)) return null;
    const v = Number(n);
    const opts = v < 1 ? { minimumFractionDigits: 2, maximumFractionDigits: 4 }
                        : { maximumFractionDigits: 2 };
    return '$' + v.toLocaleString('en-US', opts);
  };
  const fmtInt = (n) => Number(n).toLocaleString('en-US');

  const setChg = (el, pct) => {
    if (!el) return;
    if (pct == null || !isFinite(Number(pct))) { el.textContent = ''; el.className = 'chg'; return; }
    const up = Number(pct) >= 0;
    el.textContent = (up ? '▲ ' : '▼ ') + Math.abs(Number(pct)).toFixed(2) + '%';
    el.className = 'chg ' + (up ? 'up' : 'down');
  };

  async function getJson(url) {
    const r = await fetch(url, { headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }

  // Quantities shown in the "Why Eclipse" wallet mock (static demo balances).
  const MOCK = { ada: 1234.56, night: 0.85, btc: 0.04218 };

  async function refresh() {
    let ok = false;
    try {
      const p = await getJson(
        'https://api.coingecko.com/api/v3/simple/price?ids=cardano,bitcoin,midnight-3&vs_currencies=usd&include_24hr_change=true'
      );
      const apply = (key, priceEl, chgEl, cardEl) => {
        const row = p && p[key];
        if (!row || row.usd == null) return;
        if (priceEl) priceEl.textContent = fmtUsd(row.usd);
        if (cardEl) cardEl.textContent = fmtUsd(row.usd);
        setChg(chgEl, row.usd_24h_change);
        ok = true;
      };
      apply('cardano', els.ada, els.adaChg, els.priceAda);
      apply('bitcoin', els.btcPrice, els.btcChg, els.priceBtc);
      apply('midnight-3', els.night, els.nightChg, els.priceNight);
      // Live portfolio total in the wallet mock (sums the demo balances).
      if (els.wmTotal && p) {
        const total =
          (p.cardano && p.cardano.usd != null ? p.cardano.usd * MOCK.ada : 0) +
          (p['midnight-3'] && p['midnight-3'].usd != null ? p['midnight-3'].usd * MOCK.night : 0) +
          (p.bitcoin && p.bitcoin.usd != null ? p.bitcoin.usd * MOCK.btc : 0);
        if (total > 0) {
          els.wmTotal.textContent = '$' + total.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
        }
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