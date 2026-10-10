// Thin fetch wrapper. Credentials are the session cookie (set by the server after
// a passkey ceremony). No symmetric key or plaintext is ever sent through here.
async function req(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  if (!res.ok) {
    let detail;
    try { detail = (await res.json()).detail; } catch { detail = res.statusText; }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.status === 204 ? null : res.json();
}

export const api = {
  // webauthn
  registerBegin: () => req("POST", "/api/webauthn/register/begin"),
  registerComplete: (credential) => req("POST", "/api/webauthn/register/complete", { credential }),
  loginBegin: () => req("POST", "/api/webauthn/login/begin"),
  loginComplete: (credential) => req("POST", "/api/webauthn/login/complete", { credential }),
  logout: () => req("POST", "/api/webauthn/logout"),
  // keys
  putKeys: (b) => req("POST", "/api/keys", b),
  myBundle: () => req("GET", "/api/keys/me"),
  pubKeys: (uid) => req("GET", `/api/keys/${uid}`),
  // tokens
  createToken: (b) => req("POST", "/api/tokens", b),
  readToken: (tid) => req("GET", `/api/tokens/${tid}`),
  rotateToken: (tid, b) => req("POST", `/api/tokens/${tid}/rotate`, b),
  // connections
  connect: (b) => req("POST", "/api/connections", b),
  connections: () => req("GET", "/api/connections"),
  // groups
  createGroup: (b) => req("POST", "/api/groups", b),
  joinGroup: (gid, b) => req("POST", `/api/groups/${gid}/members`, b),
  readGroup: (gid) => req("GET", `/api/groups/${gid}`),
};
