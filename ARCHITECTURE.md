# Relay — Architecture

A QR-native, **end-to-end encrypted** contact network. The server is a
zero-knowledge store: it holds ciphertext, public keys, and an opaque connection
graph. It never sees profile plaintext or any symmetric key.

> Working name "Relay". Rename freely.

---

## 1. Threat model & trust boundaries

**What the server CAN see**
- `user_id` (128-bit random) and public keys (X25519, Ed25519).
- Each user's *encrypted* private-key bundle (opaque ciphertext).
- Ciphertext blobs (profile tiers, group blobs) + their sizes.
- The connection graph: which `user_id` connected to which, and when.

**What the server CANNOT see**
- Any profile field plaintext (name, phone, socials, comment, geolocation).
- Any symmetric key. Keys live only on devices and inside QR fragments.

**Defended threats**
| Threat | Defense |
|---|---|
| Guess another user's id | 128-bit random ids; never appear in URLs; all reads go through tokens/edges. |
| Enumerate share tokens | 128-bit random opaque `token_id`; no sequential values; rate-limited. |
| Read data you aren't connected to | Ciphertext is useless without the symmetric key, which only travels in the QR fragment / wrapped to your pubkey. |
| DB breach / stolen disk | Only ciphertext + ids at rest. |
| Forge a QR | Capability = random id + random key; forging ≈ guessing 256 bits. |
| Leaked/old QR | Share tokens are rotatable, support expiry and N-use; connections are individually revocable. |

**Explicitly OUT of scope (documented caveats)**
1. **Browser-E2E delivery trust.** The server serves the PWA JS, so a *malicious*
   server could ship tampered JS that exfiltrates fragment keys. E2E here protects
   against DB breach / passive or at-rest compromise — not an actively hostile
   server. Mitigations: Subresource Integrity, code transparency, a native app later.
2. **Group forward secrecy.** The group key `K_G` is static; anyone who ever held
   the group QR can decrypt the group. Member removal requires key rotation +
   re-encrypt (deferred to the future comms layer, MLS-style).
3. **Metadata privacy.** The connection graph and timing are visible to the server.

---

## 2. The capability-in-QR trick

A QR encodes a URL where the **secret lives in the fragment**:

```
https://relay.local/c/<token_id>#k=<base64 symmetric key>[&s=<sender pubkey>]
```

Browsers never send the `#fragment` to the server. So:
- The scanner's browser reads `k` locally.
- It fetches ciphertext with `GET /api/tokens/<token_id>` (no key sent).
- It decrypts in-page. The server only ever saw `token_id`.

---

## 3. Keys & identity

Per user, generated on-device (libsodium):
- **X25519** keypair — ECDH / sealed-box (receiving data others encrypt to you).
- **Ed25519** keypair — signing (authenticating your QR / future messages).

Private keys are packed into a **key bundle**, encrypted with a **wrapping key**,
and uploaded as opaque ciphertext so a new device can restore them.

**Wrapping key derivation**
- Primary: **WebAuthn PRF extension** — the passkey deterministically derives a
  stable 32-byte secret → wrapping key. Phishing-resistant, nothing to remember.
- Fallback: **Argon2id** over a user passphrase (when PRF is unsupported).

---

## 4. Data tiers

Each profile field is tagged with a visibility tier. Each tier is encrypted as its
own blob under its own key:

| Tier | Who can decrypt | Key delivery |
|---|---|---|
| `public` | anyone who scans | key in the personal QR fragment |
| `connect` | users who form a connection | key in the personal QR fragment (same QR reveals public+connect) |
| `group` | fellow members of a joined group | group key `K_G` in the group QR fragment |
| `private` | only you | never shared |

(MVP keeps it simple: the personal QR fragment carries the key that decrypts the
public+connect blob. `group` uses `K_G`. `private` fields are never uploaded.)

---

## 5. Flows

### Signup (first scan or direct)
1. WebAuthn registration (passkey) + PRF → wrapping key.
2. Generate X25519/Ed25519 keypairs → encrypt bundle → `POST /api/keys`.
3. Fill card; encrypt tier blobs; create personal share token
   (`POST /api/tokens`), get `token_id`; show QR `/c/<token_id>#k=…`.

### Scan → connect (1:1)
1. Scanner opens `/c/<token_id>#k=…`.
   - Not signed up → run Signup first.
2. `GET /api/tokens/<token_id>` → ciphertext + owner pubkey.
3. Decrypt with `k` from fragment → render card.
4. `POST /api/connections` (authenticated) records the edge
   `scanner → owner` and ships the scanner's own blob key **sealed to the owner's
   X25519 pubkey**, so the connection becomes mutual and seeds the comms channel.

### Group chain
1. A: `POST /api/groups` → `group_id`; generate `K_G`; upload A's group blob
   (`POST /api/groups/<id>/members`, ciphertext under `K_G`). Share `/g/<group_id>#k=K_G`.
2. B scans → decrypts roster with `K_G` → uploads B's group blob under `K_G` → re-shares the same `/g/<group_id>#k=K_G`.
3. C scans B's QR → same `K_G` → joins → roster {A,B,C}. Chain continues.
4. `GET /api/groups/<id>` returns all member ciphertext blobs; client decrypts with `K_G`.

---

## 6. API surface (all under `/api`)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/webauthn/register/begin` | – | start passkey registration |
| POST | `/webauthn/register/complete` | – | finish; create user; returns session |
| POST | `/webauthn/login/begin` | – | start passkey auth |
| POST | `/webauthn/login/complete` | – | finish; returns session |
| POST | `/keys` | session | store encrypted key bundle + pubkeys |
| GET | `/keys/me` | session | fetch own encrypted bundle (new device) |
| GET | `/keys/<user_id>` | session | fetch a user's public keys |
| POST | `/tokens` | session | create share token (upload ciphertext) |
| GET | `/tokens/<token_id>` | – | fetch ciphertext + owner pubkey (key is in fragment) |
| POST | `/tokens/<token_id>/rotate` | session | rotate (invalidate old QR) |
| POST | `/connections` | session | record edge + sealed reciprocal key |
| GET | `/connections` | session | list my connections (ciphertext) |
| POST | `/groups` | session | create group |
| POST | `/groups/<id>/members` | session | join / upload my group blob |
| GET | `/groups/<id>` | session | list member blobs (ciphertext) |

Server never receives a symmetric key or plaintext on any of these.

---

## 7. Stack
- **Backend:** FastAPI + `py_webauthn`, deployed as a Vercel Python (ASGI)
  function. Persistence is an object store (`app/store.py`): each "row" is a small
  JSON object at a deterministic path.
  - **Production:** a **private** Vercel Blob store (reads/writes go through the
    function with the store token; blobs are not world-readable).
  - **Local dev:** filesystem fallback under `backend/data/` — no cloud account
    needed. Selected automatically by the presence of `BLOB_READ_WRITE_TOKEN` /
    `VERCEL`.
  - Note: object storage is eventually consistent, so token use/revoke/expiry
    checks are **best-effort**. The real gate is always the secret fragment key.
- **Frontend:** build-free PWA — ES-module CDN imports for `libsodium-wrappers-sumo`,
  `html5-qrcode`, `qrcode`. Service worker + manifest for installability. Served
  as static assets from `/public` (by Vercel in prod; by the same uvicorn process
  locally).
- Same origin serves both (required for WebAuthn RP id + fragment handling).

## 8. Layout
```
qr-snowball/
  api/index.py              # Vercel entrypoint: re-exports the ASGI app
  vercel.json               # routes /api/* to the function; /c/ /g/ -> index.html
  requirements.txt          # Vercel installs these
  backend/
    requirements.txt
    data/                   # local-dev store (gitignored)
    app/{main,store,sessions,ids,webauthn_svc,deps,routes_*}.py
  public/                   # PWA (served static)
    index.html  manifest.webmanifest  sw.js  icon.svg
    js/{crypto,webauthn,api,app,ui}.js  css/style.css
  run.sh                    # local dev: one uvicorn serving API + PWA
```

## 9. Deploying to Vercel
1. Create a **Blob** store (Storage → Blob) and connect it to the project; Vercel
   injects `BLOB_READ_WRITE_TOKEN`.
2. Set env vars: `RELAY_SECRET` (stable session/challenge signing key),
   `RELAY_RP_ID` (your domain, e.g. `qr-snowball.vercel.app`),
   `RELAY_ORIGIN` (`https://<domain>`).
3. Deploy. `vercel.json` sends `/api/*` to the Python function and serves the PWA
   from `/public`; `/c/*` and `/g/*` fall back to the app shell.
