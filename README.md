# Eclipse Wallet

**All-in-one, self-custody browser-extension wallet for [Cardano](https://cardano.org) (ADA), [Midnight](https://midnight.network/night) (NIGHT) and [Bitcoin](https://bitcoin.org) (BTC).** One Manifest-V3 codebase that runs on **Chrome** and **Brave**.

> **Website:** <https://kshot3000.github.io/eclipse-wallet/> · **Developer docs:** <https://kshot3000.github.io/eclipse-wallet/docs.html> — source in [`website/`](website/), deployed to GitHub Pages via [`.github/workflows/pages.yml`](.github/workflows/pages.yml).
>
> **Built by** [@kshot9000](https://x.com/kshot9000) · [github.com/Kshot3000](https://github.com/Kshot3000) — creator of NightDream.io, EUTXO.DEX, Cardano SPO Tracker, Nocturne Messenger and The Cold Front.

- Your keys, your coins — the seed is generated on your machine, encrypted with a password, and never leaves the device.
- Send ADA / BTC, see balances, sign messages on all three chains.
- A minimal `window.eclipse` provider so dApps can request your address or a message signature — always behind an explicit approval.

---

## Features

| | Cardano (ADA) | Midnight (NIGHT) | Bitcoin (BTC) |
|---|---|---|---|
| Addresses | base (`addr1…`), stake (`stake1…`), enterprise (`addr1v…`) | unshielded (`mn_addr…`, bech32m) | native segwit P2WPKH (`bc1…`) |
| Balance | live, from on-chain UTXOs (Koios) | *v1: not available* | live (Blockstream, funded − spent) |
| Send | ✅ ADA transfers (fee auto, UTXO selection, TTL from chain tip) | *v1: not available* | ✅ BTC transfers (fee tiers: fastest / half-hour / economy) |
| Sign message | ✅ Ed25519 over the raw message | ✅ BIP340 Schnorr over the raw message | ✅ ECDSA over SHA-256(message) |
| Explorer links | cardanoscan.io | — | mempool.space |
| Networks | Mainnet / Preview / Preprod | Mainnet / Testnet / Devnet | Mainnet / Testnet |

Plus: QR codes for every address, per-chain network selection, lock/wipe, and a dApp approval queue with a badge counter and desktop notification when a request arrives while the popup is closed.

## Install (Chrome or Brave)

Eclipse is loaded as an unpacked extension — no store required.

1. Open the extensions page:
   - **Chrome:** `chrome://extensions`
   - **Brave:** `brave://extensions`
2. Turn on **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `extension/` folder in this repository.
4. Pin **Eclipse Wallet** from the puzzle-piece menu, then click the icon to open it.

First run walks you through **Create a wallet** (or import an existing BIP39 recovery phrase) and setting a password (≥ 8 characters) that encrypts the keys on this device.

## Getting started

- **Create a wallet** — generates a 24-word BIP39 recovery phrase. It is shown **once** and is never stored anywhere. Write it down; it is the only way to recover the wallet.
- **Set a password** — the 64-byte seed is encrypted (scrypt + AES-256-GCM) before it is saved to `chrome.storage.local`. The seed itself exists only in page memory while you are unlocked.
- **Unlock** — enter your password to use the wallet; **Lock** (settings or toolbar) clears it from memory.
- **Send** — choose a chain, enter recipient + amount, review fee/total, confirm with your password. Signing and broadcast happen locally in the popup; nothing is pre-signed without your approval.
- **dApps** — approve/reject address and message-signing requests in the dApps tab; optionally *remember* an origin so it doesn't ask again.

## Security model

- **Encrypted vault** — seed → AES-256-GCM, key from scrypt (N = 2¹⁴, r = 8, p = 1) over your password + random salt. Wrong password or tampered vault → decryption fails, no seed material leaks.
- **Seed is memory-only** — after unlock the seed lives only in the popup page's JS memory; it is not written to storage, IndexedDB, or any other surface. Locking discards it.
- **The service worker never touches keys** — the background worker only brokers the dApp request queue and notifications. All derivation/signing happens in the popup.
- **Per-request dApp approval** — every `getAddress` / `signMessage` request must be approved individually (unless you remember the origin), and signing always requires the wallet to be unlocked.
- **Minimal permissions** — `storage` + `notifications`, with host permissions restricted to the three public APIs used (Koios for Cardano, Blockstream + mempool.space for Bitcoin). There is no broad network access permission.
- **Recovery** — the 24-word phrase is your only backup. It is displayed once at creation, never persisted, and cannot be re-shown.

## dApp integration

> **Building a dApp?** Start with the full developer reference: <https://kshot3000.github.io/eclipse-wallet/docs.html> — detection, `getAddress`, `signMessage`, `request`, every error string, the approval lifecycle, and best practices.

On `http:`/`https:` pages Eclipse injects `window.eclipse` (alias `window.EclipseWallet`):

```js
window.eclipse.isEclipse          // true
window.eclipse.chains             // ['cardano', 'midnight', 'bitcoin']

// Request your address (requires user approval):
const { address, chain, network } = await window.eclipse.getAddress('cardano');

// Request a message signature (requires user approval + password):
const sig = await window.eclipse.signMessage('bitcoin', 'Hello from my dApp!');
// sig => {
//   chain:   'bitcoin',
//   scheme:  'ecdsa-secp256k1-sha256',
//   signature: '<base64, 64 bytes>',
//   pubKey:  '<hex, compressed>',
//   address: 'bc1…'
// }
```

`window.eclipse.request({ type, chain, message })` is the generic form; `type` is `eclipse_getAddress` or `eclipse_signMessage`.

Result shapes:

- **getAddress** → `{ address: string, chain: 'cardano'|'midnight'|'bitcoin', network: string }`
- **signMessage** → `{ chain, scheme, signature, pubKey, address }` where `scheme` is:
  - `ed25519` (Cardano, signature = Ed25519 over the raw UTF-8 message bytes),
  - `bip340-schnorr` (Midnight, 64-byte Schnorr over the raw message, `pubKey` is the 32-byte x-only key),
  - `ecdsa-secp256k1-sha256` (Bitcoin, 64-byte compact low-S over `SHA-256(message)`, `pubKey` is the compressed 33-byte key).

Behaviour: requests queue in the wallet (badge + notification if the popup is closed), wait up to **5 minutes** for a decision, then resolve with the result or reject with `Rejected by user` / `Request timed out`.

## Networks & APIs

| Chain | API | Used for |
|---|---|---|
| Cardano | [Koios](https://docs.koios.rest) (`api.koios.rest`, Preview/Preprod subdomains) | balances/UTXOs, fee parameters, chain tip (TTL), transaction submission |
| Bitcoin | [Blockstream](https://blockstream.info) + [mempool.space](https://mempool.space) | balances/UTXOs, fee estimates, transaction broadcast |

All calls are made directly by the popup; the network can be changed per chain in **Settings** (the wallet validates that recipient addresses match the selected network before letting you sign).

## Repository layout

```
extension/
  manifest.json            MV3 manifest (Chrome + Brave, single build)
  background/service-worker.js   dApp request broker (no key access)
  content/content.js       window.eclipse provider injected on http/https pages
  popup/                   the UI (html/css/js) — all crypto happens here
  lib/                     pure-JS core: vault, bip39, slip10, bech32, cbor,
                           chains/{cardano,bitcoin,midnight}.js, dapp-queue
  vendor/                  vendored deps: noble curves, BLAKE2b/SHA, scrypt, qrcode
  icons/                   icon16 / icon48 / icon128
tests/
  run_tests.mjs            113 checks vs. official spec vectors
  smoke_extension.mjs      63 offline integration checks of the real popup code paths
  vectors/                 spec test vectors (BIP39, RFC 8032, BIP143, BIP340, CBOR, …)
website/                   GitHub Pages site (vanilla HTML/CSS/JS, no build step):
  index.html · docs.html (developer docs) · 404.html · css/site.css
  js/background.js (living 3-chain canvas) · js/live.js (live network strip)
  js/site.js · js/vendor/qrcode.js · robots.txt · sitemap.xml
  assets/logo.png · assets/favicon.png
.github/workflows/pages.yml   deploys website/ to GitHub Pages on push to main
```

## Tests

Both suites run fully **offline** on **Node 22+** (Node's built-in WebCrypto is used for the vault):

```bash
node tests/run_tests.mjs       # unit: 113 checks against official vectors
node tests/smoke_extension.mjs # integration: 63 checks (fake chrome + stubbed network)
```

Coverage highlights: BIP39 (official vectors, English wordlist), SLIP-0010 ed25519/secp256k1 chains, RFC 8032 Ed25519 sign/verify, BIP143 sighash + byte-exact signed transactions, BIP340 (27 official vectors), BIP84/BIP-173 addresses, Midnight SDK vectors, CBOR (RFC 8949 Appendix A), BLAKE2b KATs, plus the full build→sign→broadcast pipelines for ADA and BTC and the dApp approval queue — with every signature independently verified against the spec.

## Known limitations (v0.1)

- **Midnight v1** is address + BIP340 message-signing only — no on-chain Midnight transactions or balances yet.
- **Bitcoin**: native P2WPKH only (no P2SH-legacy, no Taproot); one input per transaction; no RBF.
- **Cardano**: ADA only (no native tokens in the send form), no delegation/staking operations, no CIP-30.
- **BIP39 English wordlist only** (the standard 2048 words).
- **No transaction history UI** — each send shows the new txid and an explorer link; the full history is one click away in the explorer.
- **No multi-account** — one vault per browser profile (you can wipe and start over in Settings).
- **No hardware-wallet integration** in v1.

## Support Eclipse

Eclipse is free, open source and ad-free. If it earns a place in your toolbar, a tip in any of these chains (the same addresses used across the creator's past projects) keeps the lights on:

| Chain | Address | Explorer |
|---|---|---|
| **BTC** | `3GnR7TWBXAB3pPztBWpNF4LMNEX5yX8vZK` | [mempool.space](https://mempool.space/address/3GnR7TWBXAB3pPztBWpNF4LMNEX5yX8vZK) |
| **ADA** | `addr1q8hnl6vl5a6k3rw3n5g3jtte696zcl76kfatzv7gpswa9r0dj7fma6klq55y4ffm7tf0em09udnyhuk4ah92pl5x9jpqjae44v` | [cardanoscan.io](https://cardanoscan.io/addresses/addr1q8hnl6vl5a6k3rw3n5g3jtte696zcl76kfatzv7gpswa9r0dj7fma6klq55y4ffm7tf0em09udnyhuk4ah92pl5x9jpqjae44v) |
| **ERG** | `9fcM5RWnAjmP4vx5bnW6yohB6H9bLq8sJbaPLHtwZLtQPB32Pvy` | [explorer.ergoplatform.com](https://explorer.ergoplatform.com/addresses/9fcM5RWnAjmP4vx5bnW6yohB6H9bLq8sJbaPLHtwZLtQPB32Pvy) |

Creator: **[@kshot9000 on X](https://x.com/kshot9000)** · [github.com/Kshot3000](https://github.com/Kshot3000) — verify addresses on X before sending anything of value.

## Notes

- This is a personal/open-source wallet implementation. The crypto layers are checked against official specification vectors in `tests/`, but you should still review the code (especially `extension/lib/` and `extension/popup/`) before trusting it with significant funds.
- Use **Preview/Preprod (Cardano)** or **Testnet (Bitcoin)** with test assets when evaluating.
