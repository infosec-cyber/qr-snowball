// Tiny DOM helpers — no framework. Views are <section data-view> blocks toggled
// by name; everything else is small render helpers.
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function show(view) {
  $$("[data-view]").forEach((s) => (s.hidden = s.dataset.view !== view));
}

let toastTimer;
export function toast(msg, kind = "info") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = `toast ${kind} show`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = "toast"), 3200);
}

const FIELDS = [
  ["name", "Name"],
  ["title", "Title / role"],
  ["phone", "Phone"],
  ["email", "Email"],
  ["social", "Social / link"],
  ["note", "Note"],
];

export function readCardForm() {
  const card = {};
  FIELDS.forEach(([k]) => {
    const v = $(`#f_${k}`)?.value.trim();
    if (v) card[k] = v;
  });
  return card;
}

export function fillCardForm(card = {}) {
  FIELDS.forEach(([k]) => {
    const inp = $(`#f_${k}`);
    if (inp) inp.value = card[k] || "";
  });
}

export function renderCard(card, { label } = {}) {
  const rows = FIELDS.filter(([k]) => card[k])
    .map(([k, lbl]) => `<div class="row"><span class="k">${lbl}</span><span class="v">${escape(card[k])}</span></div>`)
    .join("");
  return `<div class="card">${label ? `<div class="card-badge">${escape(label)}</div>` : ""}
    <div class="card-name">${escape(card.name || "Someone")}</div>${rows}</div>`;
}

function escape(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
