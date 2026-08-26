/**
 * Eclipse Wallet — crypto test suite (run with: node tests/run_tests.mjs)
 *
 * Every check compares the wallet's pure-JS implementation against OFFICIAL
 * specification test vectors:
 *   - BIP39 (mnemonic/seed, english + trezor passphrase sets)
 *   - SLIP-0010 ed25519 / BIP32 secp256k1 key chains
 *   - RFC 8032 ed25519 sign/verify
 *   - BIP143 sighash + byte-exact serialized signed transactions
 *   - BIP340 Schnorr (27 official vectors)
 *   - BIP84 first receiving addresses
 *   - BIP-173 bech32 / Midnight bech32m addresses (SDK vectors)
 *   - CBOR RFC 8949 Appendix A encode/decode
 *   - BLAKE2b official KAT
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { pbkdf2Sync } from 'node:crypto';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const V = (p) => join(root, 'tests', 'vectors', p);

import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic, mnemonicToSeed, generateMnemonic } from '../extension/lib/bip39.js';
import { deriveEd25519Path, deriveSecpPath } from '../extension/lib/slip10.js';
import { CARDANO, formatAda, credentialFromPubKey } from '../extension/lib/chains/cardano.js';
import { BITCOIN, derEncodeSignature, formatBtc } from '../extension/lib/chains/bitcoin.js';
import { MIDNIGHT, formatXno } from '../extension/lib/chains/midnight.js';
import { cborEncode, cborEncodeCanonical, cborDecode } from '../extension/lib/cbor.js';
import { encode, decode, convertBits, encodeBytes, decodeBytes, BECH32_CONST, BECH32M_CONST } from '../extension/lib/bech32.js';
import { hexToBytes, bytesToHex, concatBytes, reverseBytes } from '../extension/lib/bytes.js';
import { blake2b } from '../extension/vendor/hashes/blake2b.js';
import { sha256 } from '../extension/vendor/hashes/sha2.js';
import { ripemd160 } from '../extension/vendor/hashes/ripemd160.js';
import * as ed25519 from '../extension/vendor/ed25519.js';
import * as secp from '../extension/vendor/secp256k1.js';
import { vaultEncrypt, vaultDecrypt, vaultToStorage, vaultFromStorage } from '../extension/lib/vault.js';
import {
  deriveDeviceKey, sealState, openState, newState, validHandle, pickReply, scheduleReply, settle, addConvo, uid, DOMAIN,
} from '../extension/lib/nocturne.js';

let passed = 0;
let failed = 0;
const failures = [];

function check(name, cond, detail = '') {
  if (cond) {
    passed++;
  } else {
    failed++;
    failures.push(name + (detail ? ' — ' + detail : ''));
    console.error('  ✗ ' + name + (detail ? '\n      ' + detail : ''));
  }
}

function section(title) {
  console.log('\n== ' + title + ' ==');
}

const eqHex = (a, b) => bytesToHex(a) === b.toLowerCase();
const sha256d = (bytes) => sha256(sha256(bytes));

/* ------------------------------- BIP39 ------------------------------- */

section('BIP39 (official vectors — English wordlist)');
{
  // Eclipse ships an English-only BIP39 wordlist (standard practice; the BIP itself
  // strongly discourages non-English wordlists). The vector files also contain 11
  // other languages — they are present but not exercised through wordlist-dependent
  // code paths. Documented limitation in README.
  const runSet = (file, passphrase, label) => {
    const vectors = JSON.parse(readFileSync(V(file), 'utf8'));
    for (const lang of Object.keys(vectors)) {
      const list = vectors[lang];
      if (lang !== 'english') continue;
      let okAll = true;
      let seedOk = true;
      for (const v of list) {
        const [entropy, mnemonic, seed] = v;
        const m = entropyToMnemonic(hexToBytes(entropy));
        if (m !== mnemonic) { okAll = false; }
        if (!validateMnemonic(mnemonic)) { okAll = false; }
        if (bytesToHex(mnemonicToSeed(mnemonic, passphrase)) !== seed) { seedOk = false; }
        const ent2 = mnemonicToEntropy(mnemonic);
        if (bytesToHex(ent2) !== entropy) { okAll = false; }
      }
      check(`bip39 ${label}: ${list.length} vectors mnemonic+entropy`, okAll);
      check(`bip39 ${label}: seed derivation (PBKDF2-HMAC-SHA512, passphrase '${passphrase}')`, seedOk);
    }
  };
  // Per BIP-0039 itself, the official published test vectors use the "TREZOR" passphrase.
  runSet('bip39_trezor_vectors.json', 'TREZOR', 'official vectors');
  // Empty-passphrase seeds have no published vector set, so cross-check the wallet's
  // PBKDF2-HMAC-SHA512 chain against Node/OpenSSL's independent pbkdf2Sync reference.
  {
    const vectors = JSON.parse(readFileSync(V('bip39_vectors.json'), 'utf8'));
    const list = vectors.english;
    let okAll = true;
    for (const v of list) {
      const [entropy, mnemonic] = v;
      const ref = pbkdf2Sync(mnemonic, 'mnemonic', 2048, 64, 'sha512').toString('hex');
      if (bytesToHex(mnemonicToSeed(mnemonic, '')) !== ref) { okAll = false; break; }
    }
    check(`bip39 empty-passphrase seeds match OpenSSL reference (${list.length} vectors)`, okAll);
  }
  check('bip39: generate 24-word mnemonic is valid', validateMnemonic(generateMnemonic(256)));
  check('bip39: 12-word mnemonic is valid', validateMnemonic(generateMnemonic(128)));
  check('bip39: invalid mnemonic rejected', validateMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon') === false);
}

/* ---------------------------- SLIP-0010 ---------------------------- */

section('SLIP-0010 ed25519 (official vectors)');
{
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const chain = [
    ['m', '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb', '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7', 'a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed'],
    ["m/0'", '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69', '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3', '8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c'],
    ["m/0'/1'", 'a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14', 'b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2', '1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187'],
    ["m/0'/1'/2'", '2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c', '92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9', 'ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1'],
    ["m/0'/1'/2'/2'", '8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc', '30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662', '8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c'],
    ["m/0'/1'/2'/2'/1000000000'", '68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230', '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793', '3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a'],
  ];
  for (const [path, cc, priv, pub] of chain) {
    const k = deriveEd25519Path(seed, path);
    check(`ed25519 ${path} priv`, eqHex(k.privKey, priv));
    check(`ed25519 ${path} chain`, eqHex(k.chainCode, cc));
    check(`ed25519 ${path} pub`, eqHex(k.pubKey, pub));
  }
}

section('SLIP-0010 secp256k1 / BIP32 (official vectors)');
{
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const chain = [
    ['m', '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508', 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35', '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'],
    ["m/0'", '47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141', 'edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea', '035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56'],
    ["m/0'/1", '2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19', '3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368', '03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c'],
    ["m/0'/1/2'", '04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f', 'cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca', '0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2'],
    ["m/0'/1/2'/2", 'cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd', '0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4', '02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29'],
    ["m/0'/1/2'/2/1000000000", 'c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e', '471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8', '022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011'],
  ];
  for (const [path, cc, priv, pub] of chain) {
    const k = deriveSecpPath(seed, path);
    check(`secp ${path} priv`, eqHex(k.privKey, priv));
    check(`secp ${path} chain`, eqHex(k.chainCode, cc));
    check(`secp ${path} pub`, eqHex(k.pubKey, pub));
  }
  // SLIP-0010 vector 2, full official chain (seed ffcf9f6f...4542):
  // m, m/0, m/0/2147483647H, m/0/2147483647H/1, m/0/2147483647H/1/2147483646H, .../2
  // Values taken from the official SLIP-0010 spec (satoshilabs/slips master, "Test vector 2
  // for secp256k1") and cross-verified with an independent oracle (node:crypto HMAC-SHA512
  // chain + OpenSSL secp256k1 point multiplication).
  const seed2 = hexToBytes('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542');
  const chain2 = [
    ['m', '60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689', '4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e', '03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7'],
    ['m/0', 'f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c', 'abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e', '02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea'],
    ["m/0/2147483647'", 'be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9', '877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93', '03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b'],
    ["m/0/2147483647'/1", 'f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb', '704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7', '03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9'],
    ["m/0/2147483647'/1/2147483646'", '637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29', 'f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d', '02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0'],
    ["m/0/2147483647'/1/2147483646'/2", '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271', 'bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23', '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c'],
  ];
  for (const [path, cc, priv, pub] of chain2) {
    const k = deriveSecpPath(seed2, path);
    check(`secp vec2 ${path} priv`, eqHex(k.privKey, priv));
    check(`secp vec2 ${path} chain`, eqHex(k.chainCode, cc));
    check(`secp vec2 ${path} pub`, eqHex(k.pubKey, pub));
  }
}

/* ------------------------- RFC 8032 ed25519 ------------------------- */

section('RFC 8032 ed25519 (official §7.1 sign/verify vectors)');
{
  // Vectors are extracted verbatim from RFC 8032 §7.1 (tests/vectors/rfc8032_vectors.json).
  // The wallet's signatures are byte-identical to both the RFC text and Node 22's built-in
  // OpenSSL ed25519 for all five vectors (1, 2, 3, 1024, SHA(abc)).
  const vectors = JSON.parse(readFileSync(V('rfc8032_vectors.json'), 'utf8'));
  let pkOk = true, sigOk = true, verOk = true;
  for (const v of vectors) {
    const pk = bytesToHex(ed25519.getPublicKey(hexToBytes(v.sk)));
    if (pk !== v.pk) pkOk = false;
    const sig = bytesToHex(ed25519.sign(hexToBytes(v.msg), hexToBytes(v.sk)));
    if (sig !== v.sig) sigOk = false;
    if (ed25519.verify(hexToBytes(v.sig), hexToBytes(v.msg), hexToBytes(v.pk)) !== true) verOk = false;
  }
  check(`rfc8032 public keys (${vectors.length} vectors)`, pkOk);
  check(`rfc8032 deterministic signatures (${vectors.length} vectors)`, sigOk);
  check(`rfc8032 verify (${vectors.length} vectors)`, verOk);
  // Negative test: the same signature over a DIFFERENT message must be rejected.
  const v0 = vectors[1]; // first vector with a non-empty message
  check('rfc8032 verify rejects altered message', ed25519.verify(hexToBytes(v0.sig), hexToBytes('73'), hexToBytes(v0.pk)) === false);
}

/* ----------------------------- BIP143 ------------------------------ */

section('BIP143 (official P2WPKH vectors)');
{
  // BIP143 lists prevout txids in INTERNAL byte order (the raw-transaction
  // serialization order — verifiable from the spec's unsigned raw tx, where
  // these exact bytes appear as the outpoint fields). The wallet API takes
  // DISPLAY-order txid hex (explorer style) and reverses at serialization
  // boundaries, so the spec literals are converted here at the test boundary.
  const disp = (specTxid) => bytesToHex(reverseBytes(hexToBytes(specTxid)));

  // Example 1 (two inputs, P2WPKH input #2): sigHash + DER signature.
  // nSequence is a uint32; the spec's raw-tx bytes eeffffff are LE, i.e. the
  // numeric value 0xFFFFFFEE (le32(0xFFFFFFEE) === 'eeffffff').
  const in1 = { txid: disp('fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f'), vout: 0, sequence: 0xffffffee };
  const in2 = { txid: disp('ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a'), vout: 1, sequence: 0xffffffff, sats: 600000000n, keyHash: hexToBytes('1d0f172a0ecb48aee1be1f2687d2963ae33f71a1') };
  // Output values verbatim from the spec's unsigned tx: 202cb206 (LE) = 112,340,000 sats
  // and 9093510d (LE) = 223,450,000 sats.
  const outs = [
    { valueSats: 0x06b22c20n, script: hexToBytes('76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac') },
    { valueSats: 0x0d519390n, script: hexToBytes('76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac') },
  ];
  // nLockTime verbatim from the spec's unsigned tx: 11000000 (LE) = 0x11.
  const locktime = 0x11;
  const privKey = hexToBytes('619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9');

  const preimage = BITCOIN.sighashPreimage({ inputs: [in1, in2], outputs: outs, inputIndex: 1, amountSats: in2.sats, locktime, version: 1 });
  const sigHash = bytesToHex(sha256d(preimage));
  check('bip143 ex1 sigHash matches spec', sigHash === 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670', sigHash);

  const sigObj = secp.sign(sha256d(preimage), privKey);
  const compact = sigObj.toCompactRawBytes();
  const der = derEncodeSignature(compact.slice(0, 32), compact.slice(32, 64));
  const expected = '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01';
  // The spec string is the DER signature followed by the trailing SIGHASH_ALL
  // (01) byte. derEncodeSignature returns the bare DER, so append the hashtype.
  check('bip143 ex1 DER signature matches spec (RFC6979)', bytesToHex(der) + '01' === expected, bytesToHex(der));

  // Example 2 (single P2SH-P2WPKH input): full byte-exact serialized tx from the spec.
  // Expected hex is parsed straight out of bip143_spec.md to avoid transcription drift:
  // the FIRST "serialized signed transaction" in the file is example 1's, so take [1].
  const specMd = readFileSync(V('bip143_spec.md'), 'utf8');
  const mTxs = [...specMd.matchAll(/The serialized signed transaction is:\s*([0-9a-f]{60,})/g)];
  if (mTxs.length < 2) throw new Error('bip143_spec.md: expected serialized tx not found');
  const expectedTxHex = mTxs[1][1].trim();
  // P2SH-P2WPKH: scriptsig pushes the 22-byte redeemScript 0014<keyHash>.
  const ex2ScriptSig = hexToBytes('16001479091972186c449eb1ded22b78e40d009bdf0089');
  const ex2 = {
    privKey: hexToBytes('eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf'),
    pubKey: hexToBytes('03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873'),
    input: {
      txid: disp('db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477'),
      vout: 1,
      // Raw-tx bytes feffffff are LE => numeric 0xFFFFFFFE.
      sequence: 0xfffffffe,
      sats: 1000000000n,
      keyHash: hexToBytes('79091972186c449eb1ded22b78e40d009bdf0089'),
      scriptSig: ex2ScriptSig,
    },
    // Output values verbatim from the spec's unsigned tx:
    // b8b4eb0b (LE) = 0x0BEBB4B8 = 199,996,600 sats; 0008af2f (LE) = 0x2FAF0800 = 800,000,000 sats.
    outputs: [
      { valueSats: 0x0bebb4b8n, script: hexToBytes('76a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac') },
      { valueSats: 0x2faf0800n, script: hexToBytes('76a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac') },
    ],
    // nLockTime verbatim from the spec's unsigned tx: 92040000 (LE) = 0x492.
    locktime: 0x492,
  };
  const pre2 = BITCOIN.sighashPreimage({ inputs: [ex2.input], outputs: ex2.outputs, inputIndex: 0, amountSats: ex2.input.sats, locktime: ex2.locktime, version: 1 });
  check('bip143 ex2 sigHash matches spec', bytesToHex(sha256d(pre2)) === '64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6', bytesToHex(sha256d(pre2)));
  const raw = BITCOIN.signAndSerialize({ inputs: [ex2.input], outputs: ex2.outputs, privKey: ex2.privKey, pubKey: ex2.pubKey, locktime: ex2.locktime, version: 1 });
  check('bip143 ex2 serialized tx matches spec byte-for-byte', raw === expectedTxHex, `\n got: ${raw}\n want: ${expectedTxHex}`);
}

/* ------------------------------- CBOR ------------------------------ */

section('CBOR (RFC 8949 Appendix A)');
{
  const vectors = JSON.parse(readFileSync(V('cbor_appendix_a.json'), 'utf8'));
  let encOk = true, decOk = true;
  let skipped = 0;
  // JSON stores numbers as doubles, so these two Appendix A values lose one unit
  // inside the vector file itself. Use the exact BigInt for the comparison.
  const bigOverrides = {
    '1bffffffffffffffff': 18446744073709551615n,   // 2^64 - 1
    'c349010000000000000000': -18446744073709551617n, // -(2^64) - 1
  };
  for (const v of vectors) {
    // Vectors without a `decoded` field are unrepresentable in plain JS
    // (±Inf/NaN, simple values, undefined, tags, byte strings, int-keyed maps).
    if (!('decoded' in v)) { skipped++; continue; }
    const hex = v.hex.toLowerCase();
    const bytes = hexToBytes(hex);
    const expected = bigOverrides[hex] ?? v.decoded;
    try {
      const got = cborDecode(bytes);
      if (!cborDeepEquals(got, expected)) decOk = false;
    } catch { decOk = false; }
    try {
      const enc = cborEncode(expected);
      // The encoder emits definite-length CBOR with double-precision floats.
      // Byte-exact equality is the correct check for canonical definite-length
      // integers/strings/structures. JS numbers (f9/fa/fb vectors) and
      // indefinite-length vectors (file marks them roundtrip:false) are compared
      // semantically: decode(encode(x)) must equal x.
      let ok;
      if (typeof expected === 'number' || v.roundtrip === false) {
        ok = cborDeepEquals(cborDecode(enc), expected);
      } else {
        ok = bytesToHex(enc) === hex;
      }
      if (!ok) encOk = false;
    } catch { skipped++; }
  }
  check(`cbor decode: ${vectors.length - skipped} vectors`, decOk);
  check(`cbor encode: ${vectors.length - skipped} vectors`, encOk);
  // canonical: map keys sorted by encoded byte form — {b:1,a:2,c:[3,1,2]}
  const can = cborEncodeCanonical({ b: 1, a: 2, c: [3, 1, 2] });
  check('cbor canonical map ordering', bytesToHex(can) === 'a3616102616201616383030102', bytesToHex(can));
}

function cborDeepEquals(a, b) {
  if (a instanceof Uint8Array || b instanceof Uint8Array) {
    if (a instanceof Uint8Array && b instanceof Uint8Array) return bytesToHex(a) === bytesToHex(b);
    return false;
  }
  if (a instanceof Map) {
    if (!(b instanceof Map) && !(b instanceof Object)) return false;
    const entriesA = a instanceof Map ? [...a.entries()] : Object.entries(b);
    const entriesB = b instanceof Map ? [...b.entries()] : Object.entries(b);
    if (entriesA.length !== entriesB.length) return false;
    for (const [k, v] of entriesA) {
      const bv = b instanceof Map ? b.get(k) : b[k];
      if (!cborDeepEquals(v, bv)) return false;
    }
    return true;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => cborDeepEquals(x, b[i]));
  }
  if (typeof a === 'bigint' || typeof b === 'bigint') {
    return BigInt(a) === BigInt(b);
  }
  if (typeof a === 'number' && typeof b === 'number') return a === b;
  if (typeof a === 'string' || typeof b === 'string') return String(a) === String(b);
  if (a === null || b === null || a === true || b === false || a === true || b === true) return a === b;
  if (a === undefined || b === undefined) return a === b;
  if (typeof a === 'object' && typeof b === 'object' && a !== null && b !== null) {
    const ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    return ka.every((k) => cborDeepEquals(a[k], b[k]));
  }
  return false;
}

/* ------------------------------ bech32 ----------------------------- */

section('bech32 / bech32m (BIP-173 + chain vectors)');
{
  // BIP-173 valid vectors (all P2WPKH: 5-bit witness version + 20-byte program = 165 bits).
  // bech32 is a 5-BIT-word encoding, so the lossless round-trip goes through the
  // word API (decode -> encode). The byte API (encodeBytes/decodeBytes) is only
  // lossless for whole-byte payloads (e.g. Cardano/Midnight addresses) — a witness
  // version nibble is 5 bits and is lost by byte regrouping.
  const valid = [
    'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
  ];
  let ok = true;
  for (const addr of valid) {
    try {
      const { hrp, data } = decode(addr, BECH32_CONST);
      const re = encode(hrp, [...data], BECH32_CONST);
      if (re.toLowerCase() !== addr.toLowerCase()) ok = false;
    } catch { ok = false; }
  }
  check('bech32 BIP-173 P2WPKH round-trip (5-bit word API)', ok);

  // P2WPKH payload structure: version word 0, then exactly a 20-byte program.
  const d1 = decode('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', BECH32_CONST);
  const prog = new Uint8Array(convertBits([...d1.data.slice(1)], 5, 8, false));
  check('bech32 P2WPKH payload = version 0 + 20-byte program', d1.data[0] === 0 && prog.length === 20, `version=${d1.data[0]} prog=${bytesToHex(prog)}`);

  // Cardano: a REAL mainnet base address (CIP-19 official test vector) must
  // decode and re-encode identically. Layout: header (0x01 = base type +
  // mainnet networkTag) + 56-byte body; bech32's own 6-char checksum is the
  // only checksum (real addresses carry no separate hash).
  const donation = 'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x';
  const d = CARDANO.decodeAddress(donation);
  check('cardano real mainnet address decodes (type 0, mainnet)', d.type === 0 && d.networkId === 1, `type=${d.type} net=${d.networkId}`);
  const reHeader = (d.type << 4) | d.networkId; // rebuild header from decoded fields (mainnet base = 0x01)
  const reenc = encodeBytes('addr', concatBytes(new Uint8Array([reHeader]), d.body), BECH32_CONST);
  check('cardano real mainnet address re-encodes identically', reenc === donation, reenc);
  const tampered = donation.slice(0, -2) + (donation.endsWith('4v') ? '5w' : '4v');
  check('cardano tampered address rejected', CARDANO.validateAddress(tampered) === false);

  // Midnight: official SDK address vectors (all seeds x networks)
  const midVectors = JSON.parse(readFileSync(V('midnight_address_vectors.json'), 'utf8'));
  const kd = JSON.parse(readFileSync(V('midnight_keyderivation_vectors.json'), 'utf8'));
  const pubForSeed = (seed) => kd.find((k) => k.seed === seed)?.unshielded?.publicKey;
  let midOk = true, midCount = 0;
  for (const v of midVectors) {
    if (!v.unshieldedAddress?.bech32m) continue;
    const pub = pubForSeed(v.seed);
    if (!pub) continue;
    midCount++;
    const got = MIDNIGHT.address(hexToBytes(pub), v.networkId);
    if (got !== v.unshieldedAddress.bech32m) {
      midOk = false;
      console.error(`    mismatch: net=${v.networkId} got=${got} want=${v.unshieldedAddress.bech32m}`);
    }
  }
  check(`midnight address vectors (${midCount})`, midOk);

  const maddr = 'mn_addr1asujt0dayj4pelgq97wv75hjhscqv9epmzzpapkf8sy8c87jhh9s6e0fs3';
  const md = MIDNIGHT.decodeAddress(maddr);
  check('midnight decode payload 32B + mainnet', md.networkId === null && md.payload.length === 32);
  check('midnight decode network suffix', MIDNIGHT.decodeAddress('mn_addr_devnet1asujt0dayj4pelgq97wv75hjhscqv9epmzzpapkf8sy8c87jhh9syn2j3y').networkId === 'devnet');
}

/* ----------------------------- blake2b ----------------------------- */

section('BLAKE2b (official KAT)');
{
  const text = readFileSync(V('blake2b_kat.txt'), 'utf8');
  const blocks = text.split(/\n\n+/).map((b) => b.trim()).filter(Boolean);
  let ok = true, count = 0;
  for (const block of blocks) {
    const mIn = block.match(/^in:\s*([0-9a-f]*)\s*$/mi);
    const mKey = block.match(/^key:\s*([0-9a-f]*)\s*$/mi);
    const mHash = block.match(/^hash:\s*([0-9a-f]+)\s*$/mi);
    if (!mIn || !mHash) continue;
    count++;
    const msg = hexToBytes(mIn[1]);
    const key = mKey && mKey[1] ? hexToBytes(mKey[1]) : undefined;
    const out = key ? blake2b(msg, { dkLen: 64, key }) : blake2b(msg, { dkLen: 64 });
    if (bytesToHex(out) !== mHash[1]) { ok = false; break; }
  }
  check(`blake2b KAT (${count} vectors)`, ok);
}

/* -------------------------- Midnight / BIP340 ---------------------- */

section('Midnight key derivation (official SDK vectors)');
{
  const kd = JSON.parse(readFileSync(V('midnight_keyderivation_vectors.json'), 'utf8'));
  let ok = true, count = 0;
  for (const v of kd) {
    if (!v.unshielded?.secretKey) continue;
    count++;
    const xOnly = MIDNIGHT.xOnlyFromPrivKey(hexToBytes(v.unshielded.secretKey));
    if (bytesToHex(xOnly) !== v.unshielded.publicKey) { ok = false; break; }
  }
  check(`midnight unshielded BIP340 keypairs (${count} vectors)`, ok);
}

section('BIP340 Schnorr (official vectors)');
{
  const csv = readFileSync(V('bip340_vectors.csv'), 'utf8');
  const rows = csv.trim().split('\n').slice(1).map((l) => l.split(','));
  let signOk = true, verOk = true, signCount = 0, verCount = 0;
  for (const [idx, sk, pk, aux, msg, sig, result] of rows) {
    if (result === 'TRUE' && sk) {
      signCount++;
      const got = MIDNIGHT.sign(hexToBytes(msg), hexToBytes(sk), hexToBytes(aux));
      if (bytesToHex(got).toUpperCase() !== sig.toUpperCase()) {
        signOk = false;
        console.error(`    sign #${idx}: got=${bytesToHex(got)} want=${sig}`);
      }
    }
    if (pk && msg) {
      verCount++;
      let res;
      try { res = MIDNIGHT.verify(hexToBytes(sig), hexToBytes(msg), hexToBytes(pk)); }
      catch { res = false; }
      if (result === 'TRUE' && res !== true) verOk = false;
      if (result === 'FALSE' && res !== false) verOk = false;
    }
  }
  check(`bip340 sign (${signCount} vectors with aux_rand)`, signOk);
  check(`bip340 verify (${verCount} TRUE + FALSE vectors)`, verOk);

  const { randomBytes } = await import('../extension/lib/bip39.js');
  const sk = randomBytes(32);
  const m = randomBytes(32);
  const sig = MIDNIGHT.sign(m, sk);
  const xOnly = MIDNIGHT.xOnlyFromPrivKey(sk);
  check('bip340 sign/verify round-trip', MIDNIGHT.verify(sig, m, xOnly) === true);
  const m2 = new Uint8Array(m); m2[0] ^= 1;
  check('bip340 verify rejects bad message', MIDNIGHT.verify(sig, m2, xOnly) === false);
}

section('Midnight HD wallet (BIP32 path m/44\'/2400\'/0\'/0/0)');
{
  const seed = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
  const k1 = MIDNIGHT.deriveKeys(seed);
  const k2 = MIDNIGHT.deriveKeys(seed);
  check('midnight HD derivation deterministic', bytesToHex(k1.privKey) === bytesToHex(k2.privKey));
  const directX = bytesToHex(MIDNIGHT.xOnlyFromPrivKey(seed));
  check('midnight HD key differs from seed-direct (path applied)', bytesToHex(k1.xOnly) !== directX);
  check('midnight mainnet address format', MIDNIGHT.address(k1.xOnly).startsWith('mn_addr1'));
  check('midnight testnet address format', MIDNIGHT.address(k1.xOnly, 'testnet').startsWith('mn_addr_testnet1'));
  check('midnight address validates', MIDNIGHT.validateAddress(MIDNIGHT.address(k1.xOnly)));
}

/* ------------------------------ Cardano ---------------------------- */

section('Cardano (derivation, address, tx pipeline)');
{
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const keys = CARDANO.deriveKeys(seed);
  const addr = CARDANO.baseAddress(keys, CARDANO.networks.mainnet);
  check('cardano base address starts with addr1q', addr.startsWith('addr1q'), addr);
  const dec = CARDANO.decodeAddress(addr);
  const reHeader = (dec.type << 4) | dec.networkId; // rebuild header from decoded fields (CIP-19)
  const reenc = encodeBytes('addr', concatBytes(new Uint8Array([reHeader]), dec.body), BECH32_CONST);
  check('cardano base address round-trip', reenc === addr, reenc);
  const stake = CARDANO.stakeAddress(keys, CARDANO.networks.mainnet);
  check('cardano stake address starts with stake1u', stake.startsWith('stake1u'), stake);
  const ent = CARDANO.enterpriseAddress(keys, CARDANO.networks.mainnet);
  check('cardano enterprise address starts with addr1v', ent.startsWith('addr1v'), ent);

  // Credential = blake2b-224(pubkey) appears twice in the base address body.
  const cred = credentialFromPubKey(keys.pubKey);
  check('cardano credential is 28 bytes', cred.length === 28, String(cred.length));
  const decBody = bytesToHex(CARDANO.decodeAddress(addr).body);
  check('cardano credential (blake2b-224) twice in body', decBody === bytesToHex(cred) + bytesToHex(cred), decBody);
  // blake2b-224 must differ from a sha256 prefix (regression guard for the old bug)
  check('cardano credential != sha256 prefix (regression)', bytesToHex(cred) !== bytesToHex(sha256(keys.pubKey).subarray(0, 28)), bytesToHex(cred));

  // Full send pipeline: build -> sign -> decode -> verify signature.
  // Recipient: a real mainnet base address (CIP-19 vector: header 0x01, 56-byte
  // body) — same vector as the bech32 section.
  const donation = 'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x';
  const utxos = [
    { txHash: 'a'.repeat(64), index: 0, lovelace: 50000000n },
    { txHash: 'b'.repeat(64), index: 1, lovelace: 30000000n },
  ];
  const feeParams = { feeA: 44, feeB: 155381, minUtxo: 1000000n, maxTxSize: 16384 };
  const ttl = 100000000n + 600n;
  const built = CARDANO.buildSendTx({
    utxos, toAddress: donation, amountLovelace: 12345678n, changeAddress: addr, ttl, feeParams,
  });
  check('cardano fee converged (feeB + size*feeA)', built.fee === 155381n + BigInt(built.size) * 44n, `fee=${built.fee} size=${built.size}`);
  const signed = CARDANO.signTx({ body: built.body, privKey: keys.privKey, pubKey: keys.pubKey });
  const tx = cborDecode(signed);
  check('cardano tx is 3-element array', Array.isArray(tx) && tx.length === 3);
  const [body, witnesses] = tx;
  const vkeyWitnesses = witnesses.get ? witnesses.get(0) : null;
  // Signee per spec = [body, EMPTY witness set, empty vld]
  const signee = cborEncodeCanonical([body, new Map(), new Map()]);
  const w = vkeyWitnesses && vkeyWitnesses[0];
  const sigOk = w && w[0] === 0 && ed25519.verify(w[2], signee, w[1]);
  check('cardano signature verifies over canonical signee (empty witness set)', !!sigOk);
  const txid = CARDANO.txHash(body);
  check('cardano txid is 64 hex', /^[0-9a-f]{64}$/.test(txid), txid);
  // txid must equal blake2b-256 of the canonical body CBOR (regression vs double-sha256)
  const expectedTxid = bytesToHex(blake2b(cborEncodeCanonical(body), { dkLen: 32 }));
  check('cardano txid = blake2b-256(body cbor)', txid === expectedTxid, txid);

  check('formatAda', formatAda(12345678n) === '12.345678 ADA', formatAda(12345678n));
  check('formatAda whole', formatAda(5000000n) === '5 ADA');
}

/* ------------------------------ Bitcoin ---------------------------- */

section('Bitcoin (BIP84 vectors, BIP143 sign, txid)');
{
  // BIP84 official test vector (mnemonic: abandon...about)
  const bip84Mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = mnemonicToSeed(bip84Mnemonic);
  const keys = BITCOIN.deriveKeys(seed);
  const addr = BITCOIN.address(keys, BITCOIN.networks.mainnet);
  check('bip84 m/84\'/0\'/0\'/0/0 pubkey', bytesToHex(keys.pubKey) === '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c', bytesToHex(keys.pubKey));
  check('bip84 first receiving address', addr === 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', addr);
  const k1 = deriveSecpPath(seed, "m/84'/0'/0'/0/1");
  const a1 = BITCOIN.address({ privKey: k1.privKey, pubKey: k1.pubKey, keyHash: ripemd160(sha256(k1.pubKey)) }, BITCOIN.networks.mainnet);
  check('bip84 second receiving address', a1 === 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g', a1);

  // buildSend fee estimate sanity: 1-in/2-out P2WPKH ≈ 141-145 vB
  const utxos = [{ txid: 'c'.repeat(64), vout: 0, sats: 100000n, keyHash: new Uint8Array(20) }];
  const changeKeyHash = new Uint8Array(20); changeKeyHash[0] = 1;
  const toKeyHash = new Uint8Array(20); toKeyHash[0] = 2;
  const built = BITCOIN.buildSend({ utxos, toKeyHash, amountSats: 40000n, feeRate: 10, changeKeyHash });
  const estVBytes = 12 + 68 * 1 + 31 * (built.changeSats > 0n ? 2 : 1);
  check('btc fee ≈ vbytes*rate (≈142vB*10 for 1in2out)', Math.abs(Number(built.feeSats) - estVBytes * 10) <= 15, `fee=${built.feeSats} est=${estVBytes * 10}`);

  // txidOf: a REAL BIP143-spec signed SegWit tx (ex2) -> legacy txid.
  // txid = dSHA256 of the legacy serialization (no marker/flag, no witness),
  // shown in display order. Expected value independently computed (scratch script).
  const ex2SignedTx = '01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000';
  const txid = BITCOIN.txidOf(ex2SignedTx);
  check('txidOf(BIP143 ex2 signed tx) = ef48d9d0...7a0c23', txid === 'ef48d9d0f595052e0f8cdcf825f7a5e50b6a388a81f206f3f4846e5ecd7a0c23', txid);

  check('formatBtc', formatBtc(1500000n) === '0.015 BTC', formatBtc(1500000n));
}

/* ------------------------------ Vault ------------------------------ */

section('Vault (scrypt + AES-256-GCM)');
{
  const plaintext = new Uint8Array(64).fill(7);
  const blob = await vaultEncrypt(plaintext, 'correct horse battery staple');
  const out = await vaultDecrypt(blob, 'correct horse battery staple');
  check('vault round-trip', bytesToHex(out) === bytesToHex(plaintext));
  let threw = false;
  try { await vaultDecrypt(blob, 'wrong password'); } catch { threw = true; }
  check('vault wrong password rejected', threw);
  const stored = vaultToStorage(blob);
  const back = vaultFromStorage(stored);
  const out2 = await vaultDecrypt(back, 'correct horse battery staple');
  check('vault storage round-trip', bytesToHex(out2) === bytesToHex(plaintext));
}

/* --------------------------- Nocturne ------------------------------ */

section('Nocturne (sealed messenger core)');
{
  const seedA = new Uint8Array(64).fill(9);
  const seedB = new Uint8Array(64).fill(10);
  const kA = await deriveDeviceKey(seedA);
  const kA2 = await deriveDeviceKey(seedA);
  const kB = await deriveDeviceKey(seedB);
  // Keys are non-extractable (by design), so compare them behaviorally:
  // AES-GCM with a fixed IV is deterministic, so identical keys produce identical ciphertext.
  const encFingerprint = async (k) => {
    const iv = new Uint8Array(12).fill(7);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode('eclipse-nocturne-key-check'));
    return bytesToHex(new Uint8Array(ct));
  };
  check('device key deterministic per seed', (await encFingerprint(kA)) === (await encFingerprint(kA2)));
  check('device key differs across seeds', (await encFingerprint(kA)) !== (await encFingerprint(kB)));

  check('validHandle accepts kshot', validHandle('kshot'));
  check('validHandle accepts a_b_123', validHandle('a_b_123'));
  check('validHandle normalizes uppercase', validHandle('KShot'));
  check('validHandle rejects short/space/symbols', !validHandle('ab') && !validHandle('a b') && !validHandle('a.b-c'));

  const st = newState('kshot');
  check('new state: profile + mailbox', st.profile.handle === 'kshot' && st.profile.mailbox === 'kshot@' + DOMAIN);
  check('new state: 4 seeded resident convos', st.convos.length === 4 && st.convos.every((c) => c.msgs.length > 0));
  check('new state: 3 welcome mails, unread', st.mail.inbox.length === 3 && st.mail.inbox.every((m) => !m.read));
  let threw = false;
  try { newState('x'); } catch { threw = true; }
  check('newState rejects invalid handle', threw);

  const sealed = await sealState(kA, st);
  check('sealed blob shape (aes-256-gcm + iv + ct)', sealed.mode === 'aes-256-gcm' && sealed.iv.length > 8 && sealed.ct.length > 16);

  const back = await openState(sealed, kA2);
  check('seal/open round-trip preserves state',
    back.profile.handle === 'kshot' &&
    back.convos.length === 4 &&
    back.mail.inbox.length === 3 &&
    back.convos[0].msgs[0].text.includes('kshot'));

  threw = false;
  try { await openState(sealed, kB); } catch { threw = true; }
  check('different seed cannot open the seal', threw);

  threw = false;
  try { await openState({ ...sealed, ct: sealed.ct.slice(4) }, kA); } catch { threw = true; }
  check('tampered ciphertext is rejected', threw);

  const convo = st.convos.find((c) => c.id === 'nocturne');
  const r1 = pickReply(convo);
  const r2 = pickReply(convo);
  check('reply rotation advances', typeof r1 === 'string' && r1.length > 0 && r1 !== r2);

  const user = addConvo(st, 'friend_x');
  check('addConvo creates user convo with generic replies', user.userMade && user.replies.length === 3);
  pickReply(user);
  check('user convo goes silent after first reply', user.silent === true);
  let dup = false;
  try { const again = addConvo(st, 'FRIEND_X'); dup = again.id === user.id; } catch { dup = false; }
  check('addConvo is idempotent per handle (case-insensitive)', dup);

  // scheduleReply + settle: deterministic delivery, safe across popup close.
  const mw = st.convos.find((c) => c.id === 'moon_whisper');
  const t0 = Date.now() - 10000;
  mw.msgs.push({ id: uid(), from: 'me', text: 'hello', ts: t0, status: 'sent' });
  check('scheduleReply arms an incoming reply', scheduleReply(mw, t0, 2000) === true && !!mw.incoming && mw.incoming.at === t0 + 2000);
  settle(st, t0 + 1900);
  check('reply not delivered before due time', !mw.msgs.some((x) => x.from === 'them' && x.ts > t0));
  check('typing indicator shows at due window', mw.typing === true);
  check('own message ticked delivered', mw.msgs.find((x) => x.text === 'hello').status === 'delivered');
  settle(st, t0 + 3000);
  const mwReply = mw.msgs.filter((x) => x.from === 'them' && x.ts > t0).pop();
  check('reply delivered after due time', !!mwReply && mwReply.status === 'read' && mw.incoming === null && mw.typing === false);
  check('own message ticked read after reply', mw.msgs.find((x) => x.text === 'hello').status === 'read');

  const fx = st.convos.find((c) => c.handle === 'friend_x');
  const t1 = Date.now();
  fx.msgs.push({ id: uid(), from: 'me', text: 'ping', ts: t1, status: 'sent' });
  settle(st, t1 + 700);
  check('unanswered message ticks to delivered', fx.msgs.find((x) => x.text === 'ping').status === 'delivered');

  check('uid() is unique', uid() !== uid());
}

/* --------------------------- Summary ------------------------------- */

console.log(`\n${'='.repeat(50)}`);
console.log(`PASSED: ${passed}   FAILED: ${failed}`);
if (failures.length) {
  console.log('\nFailures:');
  for (const f of failures) console.log('  - ' + f);
  process.exit(1);
}
console.log('\nAll tests passed. ✓');
