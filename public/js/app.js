// Controller: wires passkey onboarding, the encrypted key bundle, card sharing,
// scan-to-connect and the group snowball. All plaintext/keys stay in this tab.
import { api } from "./api.js";
import * as wa from "./webauthn.js";
import * as c from "./crypto.js";
import { $, show, toast, readCardForm, fillCardForm, renderCard } from "./ui.js";

const QR = (await import("https://esm.sh/qrcode@1.5.4")).default;

const state = {
  userId: null,
  identity: null,   // {pub_*, _x_sk, ...} — secret keys live only in memory
  card: {},         // my own profile (this device)
  cardKey: null,    // symmetric key for my public+connect blob (shareable)
  tokenId: null,    // my current share token
};

// ---- session persistence (ephemeral: sessionStorage, cleared on tab close) ----
const SKEY = "relay.session";
function saveSession() {
  if (!state.identity) return;
  sessionStorage.setItem(SKEY, JSON.stringify({
    userId: state.userId,
    pub_x25519: state.identity.pub_x25519,
    pub_ed25519: state.identity.pub_ed25519,
    x_sk: c.b64(state.identity._x_sk),
    s_sk: c.b64(state.identity._s_sk),
  }));
}
function loadSession() {
  const raw = sessionStorage.getItem(SKEY);
  if (!raw) return false;
  const s = JSON.parse(raw);
  state.userId = s.userId;
  state.identity = {
    pub_x25519: s.pub_x25519, pub_ed25519: s.pub_ed25519,
    _x_sk: c.unb64(s.x_sk), _x_pk: c.unb64(s.pub_x25519),
    _s_sk: c.unb64(s.s_sk), _s_pk: c.unb64(s.pub_ed25519),
  };
  return true;
}

// My own card + its (shareable) key persist locally for easy re-editing.
const LKEY = "relay.card";
function saveCardLocal() {
  localStorage.setItem(LKEY, JSON.stringify({
    card: state.card,
    cardKey: state.cardKey ? c.b64(state.cardKey) : null,
    tokenId: state.tokenId,
  }));
}
function loadCardLocal() {
  const raw = localStorage.getItem(LKEY);
  if (!raw) return;
  const d = JSON.parse(raw);
  state.card = d.card || {};
  state.cardKey = d.cardKey ? c.unb64(d.cardKey) : null;
  state.tokenId = d.tokenId || null;
}

// ---- wrapping key: PRF when the passkey supports it, else a passphrase ----
async function wrapKeyFromPrf(prf) {
  return { key: prf.slice(0, 32), kdf: "prf" };
}
async function wrapKeyFromPassphrase(saltB64) {
  const pass = prompt(saltB64 ? "Enter your passphrase to unlock your keys:"
                              : "Choose a passphrase to protect your keys:");
  if (!pass) throw new Error("passphrase required");
  return c.deriveWrapKeyArgon(pass, saltB64);
}

// ---- onboarding ----
async function doRegister() {
  toast("Follow your device prompt…");
  const { user_id, prf } = await wa.register();
  state.userId = user_id;
  const wrap = prf ? await wrapKeyFromPrf(prf) : await wrapKeyFromPassphrase(null);
  state.identity = c.genIdentity();
  await api.putKeys({
    pub_x25519: state.identity.pub_x25519,
    pub_ed25519: state.identity.pub_ed25519,
    enc_bundle: c.wrapBundle(state.identity, wrap.key),
    kdf: wrap.kdf,
  });
  saveSession();
  toast("Identity created", "ok");
  gotoAfterAuth();
}

async function doLogin() {
  toast("Follow your device prompt…");
  const { user_id, prf } = await wa.login();
  state.userId = user_id;
  const bundle = await api.myBundle();
  let wrapKey;
  if (bundle.kdf === "prf") {
    if (!prf) throw new Error("passkey did not return a PRF secret");
    wrapKey = prf.slice(0, 32);
  } else {
    const salt = bundle.kdf.split(":")[1];
    wrapKey = (await wrapKeyFromPassphrase(salt)).key;
  }
  state.identity = c.unwrapBundle(bundle.enc_bundle, wrapKey, bundle.pub_x25519, bundle.pub_ed25519);
  saveSession();
  toast("Welcome back", "ok");
  gotoAfterAuth();
}

function gotoAfterAuth() {
  if (pending) return resolvePending();
  show(state.card.name ? "home" : "card");
  renderHome();
}

// ---- my card + personal QR ----
async function saveCard() {
  state.card = readCardForm();
  if (!state.cardKey) state.cardKey = c.newSymKey();
  const blob = c.encryptBlob({ tier: "public+connect", card: state.card }, state.cardKey);
  if (state.tokenId) {
    const { token_id } = await api.rotateToken(state.tokenId, { blob });
    state.tokenId = token_id;
  } else {
    const { token_id } = await api.createToken({ blob });
    state.tokenId = token_id;
  }
  saveCardLocal();
  toast("Card saved & QR updated", "ok");
  show("home");
  renderHome();
}

function myShareUrl() {
  return `${location.origin}/c/${state.tokenId}#k=${c.b64(state.cardKey)}`;
}

async function renderHome() {
  $("#me-card").innerHTML = state.card.name
    ? renderCard(state.card, { label: "You" })
    : `<p class="muted">No card yet. <a href="#" data-act="edit">Create one →</a></p>`;
  if (state.tokenId) {
    await QR.toCanvas($("#me-qr"), myShareUrl(), { width: 240, margin: 1 });
    $("#me-link").textContent = myShareUrl();
    $("#me-qr-wrap").hidden = false;
  } else {
    $("#me-qr-wrap").hidden = true;
  }
  await renderConnections();
}

async function renderConnections() {
  const box = $("#connections");
  try {
    const { incoming } = await api.connections();
    if (!incoming.length) { box.innerHTML = `<p class="muted">No connections yet.</p>`; return; }
    box.innerHTML = incoming.map((edge) => {
      try {
        const payload = c.sealOpen(edge.sealed_payload, state.identity);
        return renderCard(payload.card, { label: "Connected" });
      } catch {
        return `<div class="card"><div class="card-name">(couldn't decrypt)</div></div>`;
      }
    }).join("");
  } catch (e) { box.innerHTML = `<p class="muted">${e.message}</p>`; }
}

// ---- viewing someone's card via /c/<tid>#k=... ----
let pending = null;  // a capability link we hit before being logged in

async function viewToken(tokenId, keyB64) {
  const tok = await api.readToken(tokenId);
  const key = c.unb64(keyB64);
  const { card } = c.decryptBlob(tok.blob, key);
  $("#peer-card").innerHTML = renderCard(card, { label: "Scanned" });
  const btn = $("#peer-connect");
  if (state.identity && tok.owner !== state.userId && tok.owner_pub_x25519) {
    btn.hidden = false;
    btn.onclick = async () => {
      // Seal MY connect blob + key to the owner, so the edge becomes mutual.
      const sealed = c.sealTo(tok.owner_pub_x25519, {
        from: state.userId, card: state.card, card_key: state.cardKey ? c.b64(state.cardKey) : null,
      });
      await api.connect({ to_user: tok.owner, sealed_payload: sealed });
      toast("Connected!", "ok");
      btn.hidden = true;
    };
  } else {
    btn.hidden = true;
  }
  show("peer");
}

// ---- groups (the snowball) via /g/<gid>#k=K_G ----
async function createGroup() {
  if (!state.card.name) { toast("Create your card first", "err"); return; }
  const kg = c.newSymKey();
  const blob = c.encryptBlob({ card: state.card }, kg);
  const { group_id } = await api.createGroup({ blob });
  openGroup(group_id, c.b64(kg), /*justCreated*/ true);
}

async function openGroup(groupId, keyB64, justCreated) {
  const kg = c.unb64(keyB64);
  // Join (idempotent) so the roster includes me, then render it.
  if (!justCreated && state.card.name) {
    const blob = c.encryptBlob({ card: state.card }, kg);
    try { await api.joinGroup(groupId, { blob }); } catch {}
  }
  const { members } = await api.readGroup(groupId);
  const roster = members.map((m) => {
    try { return renderCard(c.decryptBlob(m.blob, kg).card, {}); }
    catch { return ""; }
  }).join("");
  $("#group-roster").innerHTML = roster || `<p class="muted">Empty.</p>`;
  const url = `${location.origin}/g/${groupId}#k=${keyB64}`;
  await QR.toCanvas($("#group-qr"), url, { width: 240, margin: 1 });
  $("#group-link").textContent = url;
  show("group");
}

// ---- routing ----
function parseFragmentKey() {
  const m = location.hash.match(/k=([^&]+)/);
  return m ? m[1] : null;
}

function resolvePending() {
  const p = pending; pending = null;
  if (p.type === "c") return viewToken(p.id, p.k);
  if (p.type === "g") return openGroup(p.id, p.k, false);
}

async function route() {
  const mc = location.pathname.match(/^\/c\/([^/]+)$/);
  const mg = location.pathname.match(/^\/g\/([^/]+)$/);
  const k = parseFragmentKey();
  if ((mc || mg) && k) {
    const cap = { type: mc ? "c" : "g", id: (mc || mg)[1], k };
    if (state.identity) return cap.type === "c" ? viewToken(cap.id, cap.k) : openGroup(cap.id, cap.k, false);
    pending = cap;
    show("welcome");
    $("#welcome-hint").textContent = "Sign in or create an identity to open this link.";
    return;
  }
  if (state.identity) { show("home"); renderHome(); }
  else show("welcome");
}

// ---- scanner ----
let scanner = null;
async function startScan() {
  show("scan");
  const { Html5Qrcode } = await import("https://esm.sh/html5-qrcode@2.3.8");
  scanner = new Html5Qrcode("reader");
  await scanner.start({ facingMode: "environment" }, { fps: 10, qrbox: 240 }, (text) => {
    stopScan();
    try {
      const u = new URL(text);
      if (u.origin === location.origin) { history.pushState({}, "", u.pathname + u.hash); route(); return; }
    } catch {}
    toast("Not a Relay QR", "err");
  }, () => {});
}
async function stopScan() {
  if (scanner) { try { await scanner.stop(); } catch {} scanner = null; }
}

// ---- events ----
function wire() {
  document.body.addEventListener("click", async (e) => {
    const act = e.target.closest("[data-act]")?.dataset.act;
    if (!act) return;
    e.preventDefault();
    try {
      if (act === "register") await doRegister();
      else if (act === "login") await doLogin();
      else if (act === "edit") { fillCardForm(state.card); show("card"); }
      else if (act === "save-card") await saveCard();
      else if (act === "home") { show("home"); renderHome(); }
      else if (act === "scan") await startScan();
      else if (act === "stop-scan") { await stopScan(); show("home"); renderHome(); }
      else if (act === "new-group") await createGroup();
      else if (act === "copy-link") { navigator.clipboard.writeText(myShareUrl()); toast("Link copied", "ok"); }
      else if (act === "logout") { sessionStorage.removeItem(SKEY); await api.logout(); location.href = "/"; }
    } catch (err) { toast(err.message || String(err), "err"); }
  });
  window.addEventListener("popstate", route);
}

// ---- boot ----
loadSession();
loadCardLocal();
wire();
route();

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js").catch(() => {});
}
