// Browser-side WebAuthn glue: translate the server's options to/from the
// structured-clone formats the platform APIs want, and drive the PRF extension
// that deterministically yields a 32-byte wrapping-key secret from the passkey.
import { api } from "./api.js";

// url-safe base64 <-> ArrayBuffer (WebAuthn speaks base64url)
const toB64 = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64 = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

// Stable per-app salt → PRF gives the same secret every time for this passkey.
const PRF_SALT = new TextEncoder().encode("relay-prf-v1");

export const prfSupported = () =>
  typeof PublicKeyCredential !== "undefined" &&
  typeof window.PublicKeyCredential.isConditionalMediationAvailable === "function";

function serializeRegistration(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: toB64(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: toB64(r.clientDataJSON),
      attestationObject: toB64(r.attestationObject),
      transports: r.getTransports ? r.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

function serializeAssertion(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: toB64(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: toB64(r.clientDataJSON),
      authenticatorData: toB64(r.authenticatorData),
      signature: toB64(r.signature),
      userHandle: r.userHandle ? toB64(r.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

function prfResult(cred) {
  const ext = cred.getClientExtensionResults?.();
  const first = ext?.prf?.results?.first;
  return first ? new Uint8Array(first) : null;
}

// Register a new passkey; returns { user_id, prf } where prf (if present) is the
// wrapping-key secret.
export async function register() {
  const opts = await api.registerBegin();
  opts.challenge = fromB64(opts.challenge);
  opts.user.id = fromB64(opts.user.id);
  (opts.excludeCredentials || []).forEach((c) => (c.id = fromB64(c.id)));
  opts.extensions = { ...(opts.extensions || {}), prf: { eval: { first: PRF_SALT } } };

  const cred = await navigator.credentials.create({ publicKey: opts });
  const { user_id } = await api.registerComplete(serializeRegistration(cred));
  // PRF on create is unreliable across platforms; confirm via an assertion.
  let prf = prfResult(cred);
  if (!prf) prf = await evaluatePrf([{ id: cred.rawId, type: "public-key" }]);
  return { user_id, prf };
}

// Log in with an existing passkey. Returns { user_id, prf }.
export async function login() {
  const opts = await api.loginBegin();
  opts.challenge = fromB64(opts.challenge);
  (opts.allowCredentials || []).forEach((c) => (c.id = fromB64(c.id)));
  opts.extensions = { ...(opts.extensions || {}), prf: { eval: { first: PRF_SALT } } };

  const cred = await navigator.credentials.get({ publicKey: opts });
  const { user_id } = await api.loginComplete(serializeAssertion(cred));
  return { user_id, prf: prfResult(cred) };
}

// A bare assertion purely to read the PRF output (used right after register).
async function evaluatePrf(allowCredentials) {
  try {
    const opts = await api.loginBegin();
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: fromB64(opts.challenge),
        allowCredentials: allowCredentials || [],
        userVerification: "preferred",
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    });
    // Don't complete login (we're already registered this session); just read PRF.
    return prfResult(cred);
  } catch {
    return null;
  }
}
