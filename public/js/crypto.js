// All cryptography runs here, in the page. The server never sees any of these
// outputs in the clear — only ciphertext and public keys leave this module.
import _sodium from "https://esm.sh/libsodium-wrappers-sumo@0.7.15";

await _sodium.ready;
export const sodium = _sodium;

const B64 = sodium.base64_variants.URLSAFE_NO_PADDING;
export const b64 = (bytes) => sodium.to_base64(bytes, B64);
export const unb64 = (str) => sodium.from_base64(str, B64);
const enc = (obj) => sodium.from_string(JSON.stringify(obj));
const dec = (bytes) => JSON.parse(sodium.to_string(bytes));

// ---- identity: X25519 (sealed boxes) + Ed25519 (signing) ----
export function genIdentity() {
  const box = sodium.crypto_box_keypair();
  const sign = sodium.crypto_sign_keypair();
  return {
    pub_x25519: b64(box.publicKey),
    pub_ed25519: b64(sign.publicKey),
    _x_sk: box.privateKey,
    _x_pk: box.publicKey,
    _s_sk: sign.privateKey,
    _s_pk: sign.publicKey,
  };
}

// ---- wrapping key: Argon2id over a passphrase (PRF path lives in app.js) ----
export function deriveWrapKeyArgon(passphrase, saltB64) {
  const salt = saltB64 ? unb64(saltB64) : sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const key = sodium.crypto_pwhash(
    32, passphrase, salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  return { key, kdf: `argon2id:${b64(salt)}` };
}

// ---- symmetric blob encryption (profile tiers, group blobs) ----
export function encryptBlob(obj, key) {
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const ct = sodium.crypto_secretbox_easy(enc(obj), nonce, key);
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce); out.set(ct, nonce.length);
  return b64(out);
}

export function decryptBlob(blobB64, key) {
  const raw = unb64(blobB64);
  const nonce = raw.slice(0, sodium.crypto_secretbox_NONCEBYTES);
  const ct = raw.slice(sodium.crypto_secretbox_NONCEBYTES);
  return dec(sodium.crypto_secretbox_open_easy(ct, nonce, key));
}

export const newSymKey = () => sodium.crypto_secretbox_keygen();

// ---- key bundle: wrap the private keys for backup/restore ----
export function wrapBundle(identity, wrapKey) {
  const secretJson = { x_sk: b64(identity._x_sk), s_sk: b64(identity._s_sk) };
  return encryptBlob(secretJson, wrapKey);
}

export function unwrapBundle(encBundle, wrapKey, pub_x25519, pub_ed25519) {
  const secret = decryptBlob(encBundle, wrapKey);
  return {
    pub_x25519, pub_ed25519,
    _x_sk: unb64(secret.x_sk), _x_pk: unb64(pub_x25519),
    _s_sk: unb64(secret.s_sk), _s_pk: unb64(pub_ed25519),
  };
}

// ---- sealed box: encrypt to a peer's X25519 pubkey (no sender key needed) ----
export function sealTo(pub_x25519_b64, obj) {
  return b64(sodium.crypto_box_seal(enc(obj), unb64(pub_x25519_b64)));
}

export function sealOpen(sealedB64, identity) {
  return dec(sodium.crypto_box_seal_open(unb64(sealedB64), identity._x_pk, identity._x_sk));
}
