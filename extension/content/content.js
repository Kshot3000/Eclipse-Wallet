/**
 * Eclipse Wallet — content script.
 *
 * Injects a minimal wallet provider (`window.eclipse`, plus an
 * `window.EclipseWallet` alias) on http/https pages, in the spirit of the
 * Phantom / MetaMask / Eternl provider objects:
 *
 *   window.eclipse.request({ type: 'eclipse_getAddress', chain: 'cardano' })
 *     -> { address: 'addr1...' }
 *
 *   window.eclipse.request({ type: 'eclipse_signMessage', chain: 'bitcoin', message: 'hi' })
 *     -> { signature: '<base64 compact>', pubKey: '<hex>', scheme: 'bitcoin-message' }
 *
 * Every request is routed through the background service worker and requires
 * an explicit user approval in the Eclipse popup. Nothing here sees secrets.
 */
(() => {
  if (window.eclipse) return; // already injected (e.g. page re-run)

  const api = {
    isEclipse: true,
    name: 'EclipseWallet',
    version: '0.1.0',
    chains: ['cardano', 'midnight', 'bitcoin'],

    /**
     * Send a request to Eclipse Wallet and wait for the user's decision.
     * Resolves with the result object; rejects with an Error on rejection,
     * timeout or transport failure.
     */
    request(args = {}) {
      return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (fn) => { if (!settled) { settled = true; fn(); } };
        try {
          chrome.runtime.sendMessage(
            { type: 'eclipse_dapp_request', args, origin: location.origin },
            (resp) => {
              finish(() => {
                const err = chrome.runtime.lastError;
                if (err) return reject(new Error('Eclipse Wallet unreachable: ' + err.message));
                if (!resp) return reject(new Error('Eclipse Wallet did not respond'));
                if (resp.error) return reject(new Error(resp.error));
                resolve(resp.result);
              });
            }
          );
        } catch (e) {
          finish(() => reject(e instanceof Error ? e : new Error(String(e))));
        }
      });
    },

    /** Convenience wrappers */
    getAddress(chain) {
      return this.request({ type: 'eclipse_getAddress', chain });
    },
    signMessage(chain, message) {
      return this.request({ type: 'eclipse_signMessage', chain, message: String(message) });
    },
  };

  window.eclipse = api;
  window.EclipseWallet = api;
})();
