/**
 * Eclipse Wallet — background service worker (MV3 module).
 *
 * Responsibilities:
 *  - Broker dApp requests: content script -> (queue) -> popup approval
 *    -> decision relayed back to the content script.
 *  - Queue survives service-worker restarts via chrome.storage.local.
 *  - If no extension page is listening, notify the user so they can open
 *    Eclipse and approve the pending request.
 *
 * All crypto happens in the popup/extension page (the seed only exists in
 * the page's memory); this worker never touches private keys.
 */
import {
  listPending,
  pushPending,
  popPending,
  makeRequestId,
} from '../lib/dapp-queue.js';

const DECISION_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const NOTIF_ID = 'eclipse-dapp-request';

/** id -> resolver for the waiting handleDAppRequest() call. */
const waiters = new Map();

const storageAdapter = {
  get: (keys) => chrome.storage.local.get(keys),
  set: (obj) => chrome.storage.local.set(obj),
  remove: (keys) => chrome.storage.local.remove(keys),
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== 'object') return false;

  if (msg.type === 'eclipse_dapp_request') {
    handleDAppRequest(msg)
      .then(sendResponse)
      .catch((e) => sendResponse({ error: e?.message || String(e) }));
    return true; // respond asynchronously

  }
  if (msg.type === 'eclipse_dapp_decided') {
    const waiter = waiters.get(msg.id);
    if (waiter) {
      waiters.delete(msg.id);
      waiter({ approved: !!msg.approved, result: msg.result || null, reason: msg.reason });
    }
    return false;

  }
  if (msg.type === 'eclipse_dapp_hello') {
    // An extension page (popup) just opened; let it pick up pending items.
    sendResponse({ ok: true });
    return false;
  }

  return false;
});

async function handleDAppRequest(msg) {
  const args = msg.args || {};
  const req = {
    id: msg.id && typeof msg.id === 'string' ? msg.id : makeRequestId(),
    origin: typeof msg.origin === 'string' ? msg.origin.slice(0, 512) : 'unknown origin',
    type: typeof args.type === 'string' ? args.type : 'unknown',
    chain: typeof args.chain === 'string' ? args.chain : null,
    message: typeof args.message === 'string' ? args.message.slice(0, 100000) : null,
    ts: Date.now(),
  };

  // Queue it (survives worker restarts) and try to wake an open popup.
  try {
    await pushPending(storageAdapter, req);
  } catch { /* storage hiccup — the waiter flow still works */ }

  let popupAwake = false;
  try {
    await chrome.runtime.sendMessage({ type: 'eclipse_dapp_new', req });
    popupAwake = true;
  } catch {
    popupAwake = false; // no extension page listening
  }
  if (!popupAwake) notifyUser(req);

  // Wait for the user's decision (the popup sends `eclipse_dapp_decided`).
  const decision = await new Promise((resolve) => {
    const timer = setTimeout(() => {
      waiters.delete(req.id);
      resolve({ approved: false, reason: 'timeout' });
    }, DECISION_TIMEOUT_MS);
    waiters.set(req.id, (d) => {
      clearTimeout(timer);
      resolve(d);
    });
  });

  try {
    await popPending(storageAdapter, req.id);
  } catch { /* already removed by the popup */ }

  if (decision.approved && decision.result) return { result: decision.result };
  const reason = decision.reason === 'timeout' ? 'Request timed out' : 'Rejected by user';
  return { error: reason };
}

function notifyUser(req) {
  const label =
    req.type === 'eclipse_getAddress' ? `wants your ${req.chain || ''} address`
    : req.type === 'eclipse_signMessage' ? `asks you to sign a ${req.chain || ''} message`
    : 'has a request for you';
  const body = `${req.origin} ${label}. Open Eclipse Wallet to approve.`;
  const create = () =>
    chrome.notifications.create(
      NOTIF_ID,
      {
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: 'Eclipse Wallet — approval needed',
        message: body,
        priority: 2,
      },
      () => { /* ignore creation errors (e.g. notifications unavailable) */ }
    );
  create();
}

chrome.notifications?.onClicked?.addListener((id) => {
  if (id === NOTIF_ID) {
    // Open the popup as a tab so the pending request can be answered.
    chrome.tabs?.create({ url: chrome.runtime.getURL('popup/popup.html') });
    chrome.notifications.clear(NOTIF_ID);
  }
});
