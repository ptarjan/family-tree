// "Ask about the family": a visitor types a question and an answer comes back on this page (tools/site/ask).
// The question is sealed like a note (RSA-OAEP + AES-GCM under the public key in n.json) and POSTed to the ask receiver
// (n.json "a"). It carries this device's saved links, so only a real link holder can ask. The answer comes back by push:
// an EventSource on this device's own random reply topic, sealed with this device's own AES key (both made here, kept in
// localStorage, sent only inside the seal). A page that was closed asks for its missing answers on its next open ("sync").
"use strict";
const ASK = "familytree.ask";
const askState = (() => {
  let s = null;
  try { s = JSON.parse(localStorage.getItem(ASK)); } catch (_) { s = null; }
  if (!s || !s.th) {
    const r = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (x) => x.toString(16).padStart(2, "0")).join("");
    const key = crypto.getRandomValues(new Uint8Array(32));
    s = { th: "fta-" + r(16), rk: btoa(String.fromCharCode(...key)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""), items: [] };
  }
  return s;
})();
const askSave = () => { askState.items = askState.items.slice(-30); localStorage.setItem(ASK, JSON.stringify(askState)); };
const askId = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const askCreds = () => [...new Set([...(state.creds || []), ...saved().map((x) => x.pw)])].filter(Boolean);
const askOpen = (it) => it.st !== "answer" && it.st !== "refused";
// still worth listening for: open, actually sent, and asked within the last day
const askLive = (it) => askOpen(it) && it.st !== "failed" && Date.now() - (it.t || 0) < 864e5;

async function askPost(obj) {
  if (!notesCfg) notesCfg = await (await fetch("n.json", { cache: "no-store" })).json();
  if (!notesCfg.a) throw new Error("questions are not switched on");
  const { body } = await sealNote(obj);
  const res = await fetch(notesCfg.a, { method: "POST", body });
  if (!res.ok) throw new Error("status " + res.status);
}
function askBase(op) {
  return { v: 1, op, th: askState.th, rk: askState.rk, c: askCreds(), h: localStorage.getItem(HOME) || "",
    at: typeof current === "string" ? current : "", n: localStorage.getItem(NAME) || "" };
}
// The live stream alone is not enough: a browser can lose its EventSource without a sound (sleep, network change, a
// proxy, a refused reconnect leaves it closed for good), and ntfy's SSE has no event ids to resume from. A desktop page
// open the whole time once got the "working" note and never the answer a minute later. So every (re)connect asks for
// the cached messages since the last one seen (ntfy keeps them 12 h), and while any question is open the page also
// polls the same cache every 15 s; a message seen twice is harmless.
let askES = null, askTimer = null;
const askURL = (kind) => "https://ntfy.sh/" + askState.th + "/" + kind + "since=" + encodeURIComponent(askState.last || "12h");
async function askTake(m) {
  try {
    if (!m || (m.event && m.event !== "message")) return;
    if (m.id) { askState.last = m.id; askSave(); }
    const raw = b64(m.message);
    const r = await gunzipJSON(await decrypt(b64(askState.rk), raw.slice(0, 12), raw.slice(12)));
    const it = askState.items.find((x) => x.id === r.id);
    if (!it || (it.st === "answer" && r.st !== "answer")) return;
    Object.assign(it, { st: r.st, a: r.a, c: r.c || [] });
    askSave(); askDraw();
  } catch (_) { /* not ours */ }
}
async function askPoll() {
  try {
    const res = await fetch(askURL("json?poll=1&"), { cache: "no-store" });
    if (!res.ok) return;
    for (const line of (await res.text()).split("\n")) if (line.trim()) await askTake(JSON.parse(line));
  } catch (_) { /* the next tick tries again */ }
}
function askTick() {
  if (!askState.items.some(askLive)) { clearInterval(askTimer); askTimer = null; return; }
  if (!askES || askES.readyState === 2) askListen();
  askPoll();
}
function askListen() {
  if (!askTimer && askState.items.some(askLive)) askTimer = setInterval(askTick, 15000);
  if (askES && askES.readyState !== 2) return;
  if (askES) askES.close();
  askES = new EventSource(askURL("sse?"));
  askES.onerror = () => { if (askES && askES.readyState === 2) { askES = null; setTimeout(askListen, 5000); } };
  askES.onmessage = (e) => { try { askTake(JSON.parse(e.data)); } catch (_) { /* not JSON */ } };
}
async function askSend(q) {
  const it = { id: askId(), q, st: "sent", t: Date.now() };
  askState.items.push(it); askSave(); askListen(); askDraw();
  try { await askPost(Object.assign(askBase("ask"), { id: it.id, q })); }
  catch (err) { it.st = "failed"; it.a = "Could not send (" + err.message + "). Please try again."; askSave(); askDraw(); return; }
  setTimeout(() => { if (it.st === "sent") { it.a = "Not received yet; trying again..."; askDraw(); askPost(Object.assign(askBase("ask"), { id: it.id, q })).catch(() => {}); } }, 20000);
}
function askDraw() {
  const list = document.querySelector("#askpanel .asklist");
  if (!list) return;
  const who = (id) => (state.idx[id] && state.idx[id].n) || "";
  list.innerHTML = askState.items.length ? askState.items.map((it) => {
    const wait = { sent: "Sending...", working: "Looking through the family tree...", failed: "" }[it.st];
    const cites = (it.c || []).filter(who).map((id) => '<a href="#p=' + esc(id) + '">' + esc(who(id)) + "</a>").join(", ");
    return '<div class="askq">' + esc(it.q) + '</div><div class="aska' + (it.st === "answer" ? "" : " d") + '">' +
      esc(it.a || wait || "").replace(/\n/g, "<br>") + (cites ? '<div class="askc">See: ' + cites + "</div>" : "") + "</div>";
  }).join("") : '<p class="d">Ask anything about the people in this tree: who someone\'s parents were, where a family came from, ' +
    "whether there are photos. The answer comes from the tree's records, usually within a minute. If you know something " +
    "the tree has wrong, say so here too.</p>";
  list.scrollTop = list.scrollHeight;
}
function askMount() {
  if (document.getElementById("askbtn")) return;
  const btn = document.createElement("button");
  btn.id = "askbtn"; btn.type = "button"; btn.textContent = "Ask a question";
  const panel = document.createElement("section");
  panel.id = "askpanel"; panel.hidden = true;
  panel.innerHTML = '<header><b>Ask about the family</b><button type="button" class="askx" aria-label="Close">×</button></header>' +
    '<div class="asklist" aria-live="polite"></div><form><textarea maxlength="600" rows="3" required ' +
    'placeholder="e.g. Where did the family come from?" aria-label="Your question"></textarea><button type="submit">Ask</button></form>';
  document.body.append(btn, panel);
  btn.addEventListener("click", () => { panel.hidden = false; btn.hidden = true; askListen(); askDraw(); panel.querySelector("textarea").focus(); });
  panel.querySelector(".askx").addEventListener("click", () => { panel.hidden = true; btn.hidden = false; });
  panel.querySelector("form").addEventListener("submit", (e) => {
    e.preventDefault();
    const ta = panel.querySelector("textarea"), q = ta.value.trim();
    if (q) { ta.value = ""; askSend(q); }
  });
  panel.querySelector("textarea").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !matchMedia("(pointer: coarse)").matches) { // phones: Enter is a new line
      e.preventDefault(); panel.querySelector("form").requestSubmit(); }
  });
  // answers that came while the page was closed: listen, then ask for them (questions never received are sent again)
  const open = askState.items.filter(askOpen);
  if (open.length) {
    askListen(); askPoll();
    open.filter((x) => x.st === "sent").forEach((x) => askPost(Object.assign(askBase("ask"), { id: x.id, q: x.q })).catch(() => {}));
    const w = open.filter((x) => x.st !== "sent").map((x) => x.id);
    if (w.length) setTimeout(() => askPost(Object.assign(askBase("sync"), { w })).catch(() => {}), 1500);
    if (open.length) btn.classList.add("askwait");
  }
}
// coming back to the tab: reconnect from the last message seen and ask again for anything still open
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible" || !askState.items.some(askOpen)) return;
  if (askES) { askES.close(); askES = null; }
  askListen(); askPoll();
  const w = askState.items.filter((x) => askOpen(x) && x.st !== "sent" && x.st !== "failed").map((x) => x.id);
  if (w.length) askPost(Object.assign(askBase("sync"), { w })).catch(() => {});
});
// show the button once the tree is open (the header appears), never on the login screen
new MutationObserver(() => { if (!$("#bar").hidden && askCreds().length) askMount(); }).observe($("#bar"), { attributes: true });
