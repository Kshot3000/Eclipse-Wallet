/**
 * Eclipse Wallet — dApp request queue (shared by the background service
 * worker and the popup). Deliberately dependency-free so the service worker
 * stays lightweight.
 *
 * A dApp request is queued in chrome.storage.local so it survives the
 * service worker being recycled, then the popup (or the extension page opened
 * from a notification) presents it for approval. The decision is relayed back
 * to the waiting service worker via `eclipse_dapp_decided`.
 */
import { randomBytes } from './bip39.js';

export const DAPP_PENDING_KEY = 'eclipse.dapp.pending';
export const DAPP_APPROVALS_KEY = 'eclipse.dapp.approvals';

export const DAPP_TYPES = {
  getAddress: 'eclipse_getAddress',
  signMessage: 'eclipse_signMessage',
};

function hex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function makeRequestId() {
  return hex(randomBytes(16));
}

/** @returns {Promise<object[]>} the pending request list */
export async function listPending(storage) {
  const o = await storage.get([DAPP_PENDING_KEY]);
  return o[DAPP_PENDING_KEY] || [];
}

/** Add a request to the front of the queue. */
export async function pushPending(storage, req) {
  const pending = await listPending(storage);
  pending.unshift(req);
  await storage.set({ [DAPP_PENDING_KEY]: pending.slice(0, 20) });
  return pending;
}

/** Remove one request by id. @returns {boolean} true when it was present. */
export async function popPending(storage, id) {
  const pending = await listPending(storage);
  const next = pending.filter((r) => r.id !== id);
  if (next.length === pending.length) return false;
  await storage.set({ [DAPP_PENDING_KEY]: next });
  return true;
}

export async function clearPending(storage) {
  await storage.set({ [DAPP_PENDING_KEY]: [] });
}

/** Read the persisted dApp approvals (origin -> { chains, ts }). */
export async function getApprovals(storage) {
  const o = await storage.get([DAPP_APPROVALS_KEY]);
  return o[DAPP_APPROVALS_KEY] || {};
}

export async function saveApproval(storage, origin, chain) {
  const approvals = await getApprovals(storage);
  const entry = approvals[origin] || { chains: [], ts: Date.now() };
  if (chain && !entry.chains.includes(chain)) entry.chains.push(chain);
  entry.ts = Date.now();
  approvals[origin] = entry;
  await storage.set({ [DAPP_APPROVALS_KEY]: approvals });
}

export async function clearApproval(storage, origin) {
  const approvals = await getApprovals(storage);
  if (!(origin in approvals)) return approvals;
  delete approvals[origin];
  await storage.set({ [DAPP_APPROVALS_KEY]: approvals });
  return approvals;
}
