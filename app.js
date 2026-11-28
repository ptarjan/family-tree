// Family tree viewer. Everything is encrypted; one file per person (see tools/site/README.md).
// A share link #k=<token>&p=<id> opens k/<16 hex of sha256(token)>.json: AES-GCM(SHA-256("familytree-share:"
// + token), gzip(index)). The master password opens keys.json -> {x: index file, m: share map file}.
// index = {t, h: home id, p: {id: [key, name, dates, place, story, father, mother, [[spouse, [kids]]]]}}
// p/<16 hex of sha256("familytree-file:" + key)>.bin = iv || AES-GCM(key, gzip({n, d, h, ...})), loaded on view.
"use strict";
const STORE = "familytree.keys";
const NAME = "familytree.sender"; // the name the visitor last typed in the note form
const HOME = "familytree.home"; // page id of the person a share link was made for
const $ = (s) => document.querySelector(s);
const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const enc = new TextEncoder();
const state = { idx: {}, home: null, master: false, shares: null, pages: {}, up: 2, fit: false, zoom: 1 };
let entries = null;

async function sha(s) { return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
const hex = (b, n) => Array.from(b.slice(0, n), (x) => x.toString(16).padStart(2, "0")).join("");
async function decrypt(keyBytes, iv, ct) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
}
async function gunzipJSON(buf) {
  return JSON.parse(await new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream("gzip"))).text());
}
async function fetchBin(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error("missing " + path);
  return new Uint8Array(await res.arrayBuffer());
}
async function sealedFile(path, keyBytes) {
  const buf = await fetchBin(path);
  return gunzipJSON(await decrypt(keyBytes, buf.slice(0, 12), buf.slice(12)));
}

async function loadEntries() {
  if (!entries) entries = await (await fetch("keys.json", { cache: "no-store" })).json();
  return entries;
}
async function tryEntry(pw, e) {
  try {
    const base = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(e.s), iterations: e.i, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(e.v) }, key, b64(e.c));
    return JSON.parse(new TextDecoder().decode(pt));
  } catch (_) { return null; }
}
const TOKEN_RX = /^[A-Za-z0-9_-]{22}$/;
async function tryToken(token) {
  try {
    const res = await fetch("k/" + hex(await sha(token), 8) + ".json", { cache: "no-store" });
    if (!res.ok) return null;
    const e = await res.json();
    return await gunzipJSON(await decrypt(await sha("familytree-share:" + token), b64(e.v), b64(e.c)));
  } catch (_) { return null; }
}
// a short link code (16 characters) names the long token and the page the link was made for
const SHORT_RX = /^[A-Za-z0-9_-]{16}$/;
async function tryShort(code) {
  try {
    const res = await fetch("s/" + hex(await sha("familytree-short-file:" + code), 8) + ".json", { cache: "no-store" });
    if (!res.ok) return null;
    const e = await res.json();
    const r = await gunzipJSON(await decrypt(await sha("familytree-short:" + code), b64(e.v), b64(e.c)));
    if (r.p) localStorage.setItem(HOME, r.p);
    return await tryToken(r.k);
  } catch (_) { return null; }
}
// a token first (no key stretching), else every password entry
async function unlock(pw, hint) {
  if (SHORT_RX.test(pw)) { const r = await tryShort(pw); if (r) return ["k", r]; }
  if (TOKEN_RX.test(pw)) { const r = await tryToken(pw); if (r) return ["k", r]; }
  const es = await loadEntries();
  if (hint != null && hint !== "k" && es[hint]) { const r = await tryEntry(pw, es[hint]); if (r) return [hint, r]; }
  const rs = await Promise.all(es.map((e) => tryEntry(pw, e)));
  const i = rs.findIndex((x) => x);
  return i < 0 ? null : [i, rs[i]];
}

// several links on one device add up; a relative hidden in one index ("?") may be named in another
function merge(index, S = state) {
  for (const [id, a] of Object.entries(index.p)) {
    const c = { k: a[0], n: a[1], d: a[2], pl: a[3], s: a[4], fa: a[5], mo: a[6], fams: a[7], x: a[8] || "", a: a[9] || "" };
    const old = S.idx[id];
    if (old) {
      for (const f of ["fa", "mo"]) if (old[f] === "?" && c[f]) old[f] = c[f];
      const known = (fs) => fs.flat(2).filter((x) => x && x !== "?").length;
      if (known(c.fams) > known(old.fams)) old.fams = c.fams;
    } else S.idx[id] = c;
  }
  for (const [day, texts] of index.l || []) {  // changelog items this index may show
    S.log = S.log || {};
    const set = (S.log[day] = S.log[day] || new Map());  // text -> kind
    for (const [k, t] of texts) set.set(t, k);
  }
  if (index.c) S.codes = Object.assign(S.codes || {}, index.c); // short codes of people in this reader's own set (to pass links on)
  if (!S.home) S.home = index.h;
  if (index.w && !S.whose) { S.title = index.t; S.whose = index.w; } // the master index names its home
}
async function openResult(r, S = state) {
  if (r[0] === "k") { merge(r[1], S); return; }
  const pay = r[1];
  merge(await sealedFile("data/" + pay.x.f, b64(pay.x.k)), S);
  S.shares = await sealedFile("data/" + pay.m.f, b64(pay.m.k));
  S.codes = pay.c ? await sealedFile("data/" + pay.c.f, b64(pay.c.k)) : {};
  S.master = true;
}
function saved() { try { return JSON.parse(localStorage.getItem(STORE)) || []; } catch (_) { return []; } }
async function addPassword(pw, remember) {
  const r = await unlock(pw, null);
  if (!r) return false;
  if (!state.creds) state.creds = [];
  if (!state.creds.includes(pw)) state.creds.push(pw); // ask.js proves this device holds a real link
  await openResult(r);
  if (remember) {
    const list = saved().filter((x) => x.pw !== pw);
    list.push({ pw, i: r[0] });
    localStorage.setItem(STORE, JSON.stringify(list));
  }
  return true;
}

// A tab (or a cached index) older than the last publish names files that are gone: forget the cached
// index and pages, unlock again with what this device remembers, and look the person up once more.
let refreshing = null;
function refreshIndex() {
  if (!refreshing) refreshing = (async () => {
    // build the new index on the side and swap it in only when every saved password opened: a failed
    // or half-done refresh keeps what is on screen
    const old = entries;
    entries = null;
    const fresh = { idx: {}, home: null, master: false, shares: null, pages: {}, whose: null, title: state.title };
    try {
      for (const { pw, i } of saved()) { const r = await unlock(pw, i); if (!r) throw new Error("not opened"); await openResult(r, fresh); }
      if (!Object.keys(fresh.idx).length) throw new Error("empty");
    } catch (err) { entries = old; throw err; }
    Object.assign(state, fresh);
  })().finally(() => { refreshing = null; });
  return refreshing;
}
async function personPage(id, retried) {
  if (!state.pages[id]) {
    const k = state.idx[id].k;
    state.pages[id] = sealedFile("p/" + hex(await sha("familytree-file:" + k), 8) + ".bin", b64(k));
  }
  try { return await state.pages[id]; } catch (err) {
    delete state.pages[id];
    if (retried || !/^missing /.test(err.message)) throw err;
    await refreshIndex().catch(() => {});
    if (!state.idx[id]) throw err;
    return personPage(id, true);
  }
}

function showLogin(again) {
  $("#opening").hidden = true;
  $("#login").hidden = false; $("#view").hidden = true; $("#bar").hidden = !again;
  $("#msg").textContent = ""; $("#pw").value = ""; $("#pw").focus();
}
const first = (n) => n.split(/[ ,]/)[0];
function homeId() {
  return [localStorage.getItem(HOME), state.home].find((x) => x && state.idx[x]) || Object.keys(state.idx)[0];
}

function intro(id) {
  const n = Object.keys(state.idx).length;
  const c = state.idx[id];
  const linked = localStorage.getItem(HOME) === id;
  const head = !linked && state.whose ? esc(state.title) : "Your family";
  const whose = !linked && state.whose ? esc(state.whose) : esc(first(c.n));
  return '<section class="intro"><h1>' + head + "</h1><p>This is the family tree around " + whose + ": " + n +
    " people. Tap anyone in the chart to move the tree to them; their life story and records are underneath. " +
    "Drag the chart sideways to see more.</p>" + shareStrip() + "</section>";
}

function skeleton() {
  if ($("#chart")) return;
  $("#view").innerHTML = '<div id="intro"></div><nav id="path" class="path" aria-label="Your relative" hidden></nav><div id="chart" class="chart" aria-label="Family chart"></div>' +
    '<div class="tools"><span class="legend"><span class="ab"></span> ' + ancLabel().toLowerCase() + ' · <span class="bm"></span> has a life story · <span class="fb"></span> a relative not in your link</span>' +
    '<span class="grow"></span><span class="btns"><button type="button" id="zout">Zoom out</button><button type="button" id="fit" aria-pressed="false">Fit all</button><button type="button" id="fewer">− generation</button><button type="button" id="more">+ generation</button></span></div>' +
    '<article id="page"></article><p class="note foot">Were you given another link or password? <a href="#" id="another">Enter it here</a> to see both together.</p>';
  $("#more").addEventListener("click", () => { state.up = Math.min(maxUp(), state.up + 1); drawChart(); });
  $("#fewer").addEventListener("click", () => { state.up = Math.max(1, state.up - 1); drawChart(); });
  $("#fit").addEventListener("click", () => { if (state.fit || state.zoom !== 1) { state.fit = false; state.zoom = 1; } else state.fit = true; drawChart(); });
  $("#zout").addEventListener("click", () => { state.zoom = Math.max(0.2, Math.round(state.zoom * 70) / 100); drawChart(); });
  $("#another").addEventListener("click", (e) => { e.preventDefault(); showLogin(true); });
  pinch($("#chart"));
}

// Pinch on the zoomed-out chart ("Fit all" or "Zoom out") rescales the tree itself, keeping the point of the tree that
// was between the fingers under the fingers as they move (so a two-finger drag pans too, both ways: sideways through
// the chart's scroll, up and down through the page's): the page's own pinch-zoom does not reach inside the chart's
// scroll box on iPad. On release the chart stays at that scale (0.15 to 2x), the same state the Zoom out button sets.
// Moves and releases are read on the whole document: a finger that started just outside the chart still steers it,
// and its moves are the ones iOS would otherwise turn into a page zoom. The zoomed chart also carries
// touch-action: pan-x pan-y (class "zoomed"), so Safari never starts its own pinch inside it.
function pinch(el) {
  let g = null;
  const dist = (t) => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY);
  const mid = (t) => [(t[0].clientX + t[1].clientX) / 2, (t[0].clientY + t[1].clientY) / 2];
  const wide = () => state.fit || state.zoom !== 1;
  el.addEventListener("touchstart", (e) => {
    if (e.touches.length !== 2 || !wide()) return;
    const stage = el.querySelector(".stage");
    if (!stage) return;
    const r = el.getBoundingClientRect(), [x, y] = mid(e.touches);
    const z0 = parseFloat(stage.style.zoom) || 1;
    // the tree point under the fingers, in unscaled stage px: x through the chart's scroll, y from the chart's top
    g = { stage, d0: dist(e.touches) || 1, z0, z: z0, cx: (el.scrollLeft + x - r.left) / z0, cy: (y - r.top) / z0 };
  }, { passive: true });
  document.addEventListener("touchmove", (e) => {
    if (!g || e.touches.length !== 2) return;
    if (e.cancelable) e.preventDefault();
    g.z = Math.max(0.15, Math.min(2, g.z0 * dist(e.touches) / g.d0));
    g.stage.style.zoom = g.z;
    el.style.height = Math.ceil(parseFloat(g.stage.style.height) * g.z) + 4 + el.offsetHeight - el.clientHeight + "px";
    const [x, y] = mid(e.touches), r = el.getBoundingClientRect();
    el.scrollLeft = g.cx * g.z - (x - r.left);
    const dy = r.top + g.cy * g.z - y; // how far the tree point sits below the fingers now
    if (Math.abs(dy) >= 1) window.scrollBy(0, dy);
  }, { passive: false });
  const end = (e) => {
    if (!g || e.touches.length >= 2) return;
    state.fit = false; state.zoom = g.z === 1 ? 0.999 : g.z; g = null; // exactly 1 would mean "normal view" and redraw fewer generations
    $("#fit").textContent = "Back to normal"; $("#fit").setAttribute("aria-pressed", "false");
    $("#zout").disabled = state.zoom <= 0.2;
  };
  document.addEventListener("touchend", end, { passive: true });
  document.addEventListener("touchcancel", end, { passive: true });
  document.addEventListener("gesturestart", (e) => { if (g || (wide() && el.contains(e.target))) e.preventDefault(); });
}

let current = null;
let drawnId = null; // the person the chart was last drawn around
let lastSize = [0, 0]; // the chart's width and breakpoint at the last draw
const sizeNow = () => { const c = document.getElementById("chart"); return [c ? c.clientWidth : 0, window.matchMedia("(max-width: 600px)").matches ? 1 : 0]; };
// the most generations above the person in focus that exist (a faint "a relative" box counts, nothing is drawn above it), at most 6
function maxUp() {
  const seen = new Set();
  const d = (x, n = 0) => {
    const c = x && x !== "?" && state.idx[x];
    if (!c || n >= 6 || seen.has(x)) return 0;
    seen.add(x);
    const ps = [c.fa, c.mo].filter((y) => y);
    const r = ps.length ? 1 + Math.max(...ps.map((y) => d(y, n + 1))) : 0;
    seen.delete(x);
    return r;
  };
  return Math.max(1, Math.min(6, d(current, 0)));
}
// The home person's direct ancestors, worked out from this reader's own index (father/mother links), so nothing
// outside their set is ever needed. Null only on the home person's own page; on an ancestor's page the marks show
// which of their children and relatives lead home.
const ancLabel = () => (state.master ? "Direct ancestor" : "Your direct ancestor");
function ancestorSet(id) {
  const home = homeId();
  if (!home || !state.idx[home] || id === home) return null;
  const seen = new Set(), todo = [home];
  while (todo.length) {
    const c = state.idx[todo.pop()];
    if (!c) continue;
    for (const p of [c.fa, c.mo]) if (p && p !== "?" && state.idx[p] && !seen.has(p)) { seen.add(p); todo.push(p); }
  }
  return seen.size ? seen : null;
}
// Shortest chain of family links (parents first, then spouses, then children) from the home person to `id`.
function pathFromHome(id) {
  const home = homeId(), I = state.idx;
  if (!home || !I[home] || !I[id] || home === id) return null;
  const prev = new Map([[home, null]]), q = [home];
  while (q.length && !prev.has(id)) {
    const x = q.shift(), c = I[x];
    const nb = [c.fa, c.mo, ...c.fams.map((f) => f[0]), ...c.fams.flatMap((f) => f[1])];
    for (const y of nb) if (y && y !== "?" && I[y] && !prev.has(y)) { prev.set(y, x); q.push(y); }
  }
  if (!prev.has(id)) return null;
  const out = [];
  for (let x = id; x; x = prev.get(x)) out.unshift(x);
  return out;
}
let pathOpen = null; // the person whose collapsed path the reader expanded
function drawPath(id) {
  // the route of the tie the label names ("Your 2x great-uncle" goes up to the shared ancestor and down, never
  // through a marriage that happens to be as short); the plain shortest chain only when no named tie is found
  const k = homeId() && homeId() !== id ? kin(homeId(), id) : null;
  const el = $("#path"), p = k ? k.path : pathFromHome(id);
  if (!el) return;
  el.hidden = !p;
  if (!p) { el.innerHTML = ""; return; }
  // who this person is to the reader (the master's home person, or the person the share link was made for); the
  // path below it still shows the chain of links, and "Your relative" stands in when no plain term fits
  const rel = kinSentence(homeId(), id, true) || "Your relative";
  el.setAttribute("aria-label", rel);
  const link = (x, i) => i === p.length - 1 ? "<b>" + esc(first(state.idx[x].n)) + "</b>"
    : '<a href="#p=' + x + '" title="' + esc(state.idx[x].n) + '">' + esc(first(state.idx[x].n)) + "</a>";
  // each step's arrow says which way it moves in the tree: up to a parent, down to a child, across to a spouse
  const I = state.idx, step = (a, b) => (I[a].fa === b || I[a].mo === b) ? ["↑", "up to a parent"]
    : I[a].fams.some((f) => f[1].includes(b)) ? ["↓", "down to a child"] : ["↔", "across to a spouse"];
  const sep = (i) => { const [g, t] = step(p[i], p[i + 1]); return ' <span class="dir" title="' + t + '" aria-label="' + t + '">' + g + "</span> "; };
  // a long way home shows every step that fits on one line; when it doesn't fit, the two ends and a tap-to-open "…" for the hidden middle
  const build = (head, tail) => {
    let html = "";
    for (let i = 0; i < p.length; i++) {
      if (head + tail < p.length && i === head) { html += '<button type="button" class="more" title="Show the whole way">…</button>' + sep(p.length - tail - 1); i = p.length - tail - 1; continue; }
      html += link(p[i], i) + (i < p.length - 1 ? sep(i) : "");
    }
    return '<span class="pl">' + esc(rel) + ':</span> ' + html;
  };
  el.innerHTML = build(p.length, 0);
  if (p.length > 6 && pathOpen !== id) {
    const line = parseFloat(getComputedStyle(el).lineHeight) || 24, fits = (rows) => el.scrollHeight <= line * (rows + 0.5);
    // drop middle steps one at a time (alternating sides) until it fits in `rows` lines; never fewer than two at each end
    const shrink = (rows) => {
      let head = p.length - Math.floor(p.length / 2), tail = Math.floor(p.length / 2);
      el.innerHTML = build(p.length, 0);
      while (!fits(rows) && head + tail > 4) {
        if (head > tail) head--; else tail--;
        el.innerHTML = build(Math.max(2, head), Math.max(2, tail));
      }
    };
    // one line when the shortest form fits; on a narrow screen where it wraps anyway, fill both lines with names
    shrink(1);
    if (!fits(1)) shrink(2);
  }
  const b = el.querySelector("button.more");
  if (b) b.addEventListener("click", () => { pathOpen = id; drawPath(id); });
}
function drawChart() {
  const id = current;
  drawPath(id);
  // every brother and sister is always drawn: collapsing them on some people and not others read as missing siblings
  state.up = Math.max(1, Math.min(state.up, maxUp()));
  // the chart lays itself out and centres the person in unscaled px, so the old scale comes off first (the stage is
  // reused between draws; left on, it clamped the centring scroll to the shrunken width). Remember what was in view.
  const chartEl = $("#chart"), old = chartEl.querySelector(".stage");
  const oldZ = old ? parseFloat(old.style.zoom) || 1 : 1, oldCenter = (chartEl.scrollLeft + chartEl.clientWidth / 2) / oldZ;
  const sameFocus = id === drawnId;
  if (old) old.style.zoom = "";
  window.FamilyChart.draw(chartEl, state.idx, id, { up: state.fit || state.zoom !== 1 ? 12 : state.up, sibs: true, anc: ancestorSet(id), ancLabel: ancLabel() });
  drawnId = id;
  // "Fit all": the whole tree this reader can see, every generation, scaled down to the page width (a bird's-eye view; each box still links to its person)
  const stage = chartEl.querySelector(".stage");
  chartEl.classList.toggle("zoomed", state.fit || state.zoom !== 1);
  if (state.fit || state.zoom !== 1) {
    const sw = parseFloat(stage.style.width), cw = chartEl.clientWidth;
    // same person (Zoom out, a resize): keep the middle of the view where it was; a new person: centre them
    const center = sameFocus ? oldCenter : chartEl.scrollLeft + cw / 2;
    const z = state.fit ? Math.min(1, cw / sw) : state.zoom;
    stage.style.zoom = z;
    // leave room for the horizontal scrollbar (when the zoomed tree is still wider than the page) plus a little slack for rounding, or the bottom row is cut
    chartEl.style.height = Math.ceil(parseFloat(stage.style.height) * z) + 4 + "px";
    if (chartEl.scrollWidth > chartEl.clientWidth + 1) chartEl.style.height = Math.ceil(parseFloat(stage.style.height) * z) + 4 + chartEl.offsetHeight - chartEl.clientHeight + "px";
    chartEl.scrollLeft = state.fit ? 0 : center * z - cw / 2;
  } else stage.style.zoom = "";
  $("#fit").textContent = state.fit || state.zoom !== 1 ? "Back to normal" : "Fit all";
  $("#zout").disabled = state.fit || state.zoom <= 0.2;
  $("#fit").setAttribute("aria-pressed", state.fit ? "true" : "false");
  lastSize = sizeNow();
  const wide = state.fit || state.zoom !== 1;
  $("#more").disabled = wide || state.up >= maxUp(); $("#fewer").disabled = wide || state.up <= 1;
}

function fillRelatives(root) {
  const anc = ancestorSet(current);
  for (const s of root.querySelectorAll("span.rel")) {
    const c = state.idx[s.dataset.p];
    const mark = c && anc && anc.has(s.dataset.p);
    s.innerHTML = c ? '<a href="#p=' + s.dataset.p + '"' + (mark ? ' class="anc" title="' + ancLabel() + '"' : "") + ">" + esc(c.n) + '</a> <span class="d">(' + esc(c.d) + ")</span>" : "a relative";
  }
}

// photos: i/<hash>.bin = iv || AES-GCM(key, jpeg); the key is in the page of each person in the photo, nowhere else.
// Each is fetched only when it scrolls near the screen.
const photoURLs = {};
async function photoURL(key) {
  if (!photoURLs[key]) photoURLs[key] = (async () => {
    const buf = await fetchBin("i/" + hex(await sha("familytree-photo:" + key), 8) + ".bin");
    return URL.createObjectURL(new Blob([await decrypt(b64(key), buf.slice(0, 12), buf.slice(12))], { type: "image/jpeg" }));
  })();
  return photoURLs[key];
}
function showPhotos(pageEl, list) {
  if (!list || !list.length) return;
  const fig = ([k, cap, w, h]) => '<figure><a class="ph" data-k="' + esc(k) + '" style="aspect-ratio:' + w + "/" + h + '" href="#"></a><figcaption>' + esc(cap) + "</figcaption></figure>";
  const life = list.filter((r) => !r[5]), grave = list.filter((r) => r[5]); // grave/headstone photos are their own category
  const box = document.createElement("section");
  box.className = "gallery";
  box.innerHTML = (life.length ? "<h2>Photos (" + life.length + ")</h2>" + life.map(fig).join("") : "") +
    (grave.length ? "<h2>Grave photos (" + grave.length + ")</h2>" + grave.map(fig).join("") : "");
  // after the life story (the first heading below the opening text that is not the story), before the rest
  const heads = [...pageEl.querySelectorAll("h2")], at = heads.find((x) => x.textContent === "Family") || heads.find((x) => x.textContent === "Sources");
  if (at) at.parentNode.insertBefore(box, at); else pageEl.appendChild(box);
  if (life.length && life[0][4]) { // a life picture of just this person: the portrait beside the name
    const a = document.createElement("a");
    a.className = "ph portrait"; a.dataset.k = life[0][0]; a.style.aspectRatio = life[0][2] + "/" + life[0][3]; a.href = "#";
    a.title = life[0][1];
    const h1 = pageEl.querySelector("h1");
    if (h1) h1.parentNode.insertBefore(a, h1); else pageEl.insertBefore(a, pageEl.firstChild);
  }
  const io = new IntersectionObserver((es) => {
    for (const e of es) {
      if (!e.isIntersecting) continue;
      io.unobserve(e.target);
      photoURL(e.target.dataset.k).then((u) => { e.target.style.backgroundImage = "url(" + u + ")"; e.target.href = u; e.target.target = "_blank"; })
        .catch(() => { e.target.textContent = "(photo unavailable)"; });
    }
  }, { rootMargin: "300px" });
  for (const a of pageEl.querySelectorAll("a.ph")) { io.observe(a); a.addEventListener("click", (ev) => { if (a.getAttribute("href") === "#") ev.preventDefault(); }); }
}

// Record scans (page.rc = [key, caption, w, h, source number or 0]): shown inside the numbered source they back
// (li > span#src-N), else under a "Records" heading before the sources. Same image files and decryption as photos;
// tapping one opens it full size in a new tab.
function showRecords(pageEl, list) {
  if (!list || !list.length) return;
  const fig = ([k, cap, w, h]) => '<figure><a class="ph" data-k="' + esc(k) + '" style="aspect-ratio:' + w + "/" + h + '" href="#" title="Open full size"></a><figcaption>' + esc(cap) + "</figcaption></figure>";
  const loose = [];
  for (const e of list) {
    const li = e[4] && pageEl.querySelector("#src-" + e[4]) && pageEl.querySelector("#src-" + e[4]).parentNode;
    if (!li) { loose.push(e); continue; }
    let box = li.querySelector(":scope > .gallery.recs");
    if (!box) { box = document.createElement("div"); box.className = "gallery recs"; li.appendChild(box); }
    box.insertAdjacentHTML("beforeend", fig(e));
  }
  if (loose.length) {
    const box = document.createElement("section");
    box.className = "gallery recs";
    box.innerHTML = "<h2>Records</h2>" + loose.map(fig).join("");
    const at = [...pageEl.querySelectorAll("h2")].find((x) => x.textContent === "Sources");
    if (at) at.parentNode.insertBefore(box, at); else pageEl.appendChild(box);
  }
  const io = new IntersectionObserver((es) => {
    for (const e of es) {
      if (!e.isIntersecting) continue;
      io.unobserve(e.target);
      photoURL(e.target.dataset.k).then((u) => { e.target.style.backgroundImage = "url(" + u + ")"; e.target.href = u; e.target.target = "_blank"; })
        .catch(() => { e.target.textContent = "(scan unavailable)"; });
    }
  }, { rootMargin: "300px" });
  for (const a of pageEl.querySelectorAll(".recs a.ph")) { io.observe(a); a.addEventListener("click", (ev) => { if (a.getAttribute("href") === "#") ev.preventDefault(); }); }
}

// A saved password but no index yet (a refresh in flight, or a fetch that failed mid-publish): say so, try again
// once after a moment, and ask for the password only if it still opens nothing.
let waiting = false;
async function waitForKeys() {
  $("#login").hidden = true; $("#view").hidden = true; $("#opening").hidden = false;
  if (waiting) return;
  waiting = true;
  try {
    for (let n = 0; n < 2 && !Object.keys(state.idx).length; n++) {
      if (n) await new Promise((r) => setTimeout(r, 1500));
      await refreshIndex().catch(() => {});
    }
  } finally { waiting = false; }
  if (Object.keys(state.idx).length) return render();
  showLogin(false);
}

async function render() {
  if (!Object.keys(state.idx).length) return saved().length ? waitForKeys() : showLogin(false);
  $("#opening").hidden = true; $("#login").hidden = true; $("#view").hidden = false; $("#bar").hidden = false;
  $("#lock").hidden = !state.master; // only the master password is worth forgetting; a share link unlocks again anyway
  const h = location.hash.slice(1);
  if (h === "az") return renderAZ();
  if (h === "changelog") return renderLog();
  const want = h.startsWith("p=") ? h.slice(2) : "";
  const id = state.idx[want] ? want : homeId();
  skeleton();
  const moved = current !== id;
  current = id;
  if (moved) gaHit("/p/" + id);
  $("#intro").innerHTML = want ? "" : intro(id);
  wireShareStrip();
  drawPath(id);
  drawChart();
  document.title = state.idx[id].n + " - Family tree";
  const chartTop = $("#chart").getBoundingClientRect().top + window.scrollY - 60;
  if (moved && window.scrollY > chartTop) window.scrollTo({ top: Math.max(0, chartTop), behavior: "smooth" });
  const pageEl = $("#page");
  if (moved) pageEl.innerHTML = '<p class="note">Opening ' + esc(state.idx[id].n) + "…</p>";
  try {
    const p = await personPage(id);
    if (current !== id) return;
    pageEl.innerHTML = shareBox(id) + p.h;
    fillRelatives(pageEl);
    showPhotos(pageEl, p.ph);
    showRecords(pageEl, p.rc);
    const link = localStorage.getItem(HOME), rel = pageEl.querySelector("span.relto");
    if (rel && link && state.idx[link]) { const t = kinSentence(link, id); if (t !== undefined) rel.textContent = t; }
    wireShare();
    showNoteBox(pageEl, id);
  } catch (err) {
    if (current === id) pageEl.innerHTML = '<p class="note">This page could not be opened (' + esc(err.message) + ").</p>";
  }
}

// how the person a share link was made for is related to `to`: "<First>'s father.", "Wife of <First>'s son.";
// "" for themselves; undefined when no tie is found (the page keeps its own wording).
// With `you` set it is the reader's own phrase for `to`, no name and no full stop: "Your great-grandmother",
// "Your aunt's husband", "Your wife's father".
// How `from` and `to` are related, with the route that relation follows, so the label and the breadcrumb under it
// always describe the same tie: {r: [steps up from `from`, steps down to the blood relative], s: the spouse on the
// `to` end ("Your aunt's husband"), f: the spouse on the `from` end ("Your wife's father"), path: ids from..to}.
// null when no tie is found.
function kin(from, to) {
  const I = state.idx;
  if (!I[from] || !I[to]) return null;
  const up = (start) => { // each ancestor: [generations up, the child it was reached from]
    const d = new Map([[start, [0, null]]]), q = [start];
    while (q.length) {
      const x = q.shift();
      for (const p of [I[x].fa, I[x].mo]) if (p && p !== "?" && I[p] && !d.has(p)) { d.set(p, [d.get(x)[0] + 1, x]); q.push(p); }
    }
    return d;
  };
  const line = (A, x) => { const out = []; for (let y = x; y !== null; y = A.get(y)[1]) out.push(y); return out; }; // x down to the start
  const blood = (a0, b0) => {
    const A = up(a0), B = up(b0);
    let best = null;
    for (const [x, [a]] of A) if (B.has(x) && (!best || a + B.get(x)[0] < best.r[0] + best.r[1])) best = { r: [a, B.get(x)[0]], x };
    return best && { r: best.r, path: line(A, best.x).reverse().concat(line(B, best.x).slice(1)) };
  };
  const sps = (x) => I[x].fams.map((f) => f[0]).filter((s) => s && s !== "?" && I[s]);
  const r = blood(from, to);
  if (r) return r;
  if (sps(from).includes(to)) return { r: null, path: [from, to] };
  for (const s of sps(to)) { const r2 = blood(from, s); if (r2) return { r: r2.r, s, path: r2.path.concat([to]) }; }
  for (const f of sps(from)) { const r3 = blood(f, to); if (r3) return { r: r3.r, f, path: [from].concat(r3.path) }; }
  return null;
}
function kinSentence(from, to, you) {
  if (from === to) return "";
  const I = state.idx, H = you ? "Your" : first(I[from].n) + "'s", end = you ? "" : ".";
  const great = (n) => (n === 1 ? "great-" : n + "x great-");
  const term = (a, b, sex) => {
    const w = (m, f, n) => (sex === "M" ? m : sex === "F" ? f : n);
    if (b === 0) return (a === 1 ? "" : a === 2 ? "grand" : great(a - 2) + "grand") + w("father", "mother", "parent");
    if (a === 0) return b === 1 ? w("son", "daughter", "child") : (b === 2 ? "" : great(b - 2)) + w("grandson", "granddaughter", "grandchild");
    if (a === 1 && b === 1) return w("brother", "sister", "brother or sister");
    if (a === 1) return (b === 2 ? "" : b === 3 ? "grand-" : great(b - 3) + "grand-") + w("nephew", "niece", "nephew or niece");
    if (b === 1) return (a === 2 ? "" : great(a - 2)) + w("uncle", "aunt", "uncle or aunt");
    const deg = Math.min(a, b) - 1, rem = Math.abs(a - b);
    return (["", "first", "second", "third", "fourth", "fifth"][deg] || deg + "th") + " cousin" +
      (rem ? " " + (["", "once", "twice", "three times"][rem] || rem + " times") + " removed" : "");
  };
  const spouse = (x) => (x === "M" ? "husband" : x === "F" ? "wife" : "spouse");
  const k = kin(from, to);
  if (!k || (k.f && !you)) return undefined; // a spouse's own relatives are only worded for the reader
  if (!k.r) return H + " " + spouse(I[to].x) + end;
  if (k.s) {
    const w = spouse(I[to].x), t = term(k.r[0], k.r[1], I[k.s].x);
    return you ? H + " " + t + "'s " + w : w[0].toUpperCase() + w.slice(1) + " of " + H + " " + t + ".";
  }
  if (k.f) return H + " " + spouse(I[k.f].x) + "'s " + term(k.r[0], k.r[1], I[to].x); // "Your wife's father"
  return H + " " + term(k.r[0], k.r[1], I[to].x) + end;
}

const fold = (s) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
function surname(n) { const w = n.split(",")[0].trim().split(/\s+/); return w[w.length - 1]; }
function renderAZ() {
  current = null;
  document.title = "Everyone - Family tree";
  const all = Object.entries(state.idx).map(([id, c]) => [id, c, surname(c.n)])
    .sort((a, b) => fold(a[2] + " " + a[1].n).localeCompare(fold(b[2] + " " + b[1].n)));
  const groups = {};
  for (const x of all) { // a name that does not start with a letter goes under "?", never a digit heading
    const L = /^\p{L}/u.test(fold(x[2])) ? fold(x[2])[0] : "?";
    (groups[L.toUpperCase()] = groups[L.toUpperCase()] || []).push(x);
  }
  const letters = Object.keys(groups);
  $("#view").innerHTML = "<h1>Everyone (" + all.length + ")</h1><p class=\"jump\">" +
    letters.map((L) => '<a href="#az" data-l="' + L + '">' + L + "</a>").join(" ") + "</p>" +
    letters.map((L) => '<h2 id="az-' + L + '">' + L + '</h2><ul class="az">' + groups[L].map(([id, c]) =>
      '<li><a href="#p=' + id + '">' + esc(c.n) + '</a> <span class="d">' + esc(c.d) + "</span></li>").join("") + "</ul>").join("");
  for (const a of document.querySelectorAll(".jump a")) a.addEventListener("click", (e) => { e.preventDefault(); $("#az-" + a.dataset.l).scrollIntoView({ behavior: "smooth" }); });
  window.scrollTo(0, 0);
}

// Changelog: items come inside each reader index (the build keeps only items whose every named person that reader may see);
// a name is filled in from the index here, never stored in the item
const dayName = (y, m, d) => new Date(Date.UTC(y, m - 1, d)).toLocaleDateString("en-CA", { month: "long", day: "numeric", year: "numeric", timeZone: "UTC" });
const LOG_KINDS = {  // kind of changelog bullet -> [icon, legend label]
  people: ["\u{1F46A}", "new relatives"], record: ["\u{1F4DC}", "record found"], story: ["\u{1F4D6}", "life story"],
  photo: ["\u{1F4F7}", "photo"], fix: ["\u2696\uFE0F", "correction settled"], place: ["\u{1F9ED}", "place or migration"],
};
function logLine(text) {
  return esc(text).replace(/\[\[(\w+)\]\]/g, (_, id) => {
    const c = state.idx[id];
    if (!c || !c.n) return "a relative";
    const y = /\d/.test(c.d || "") ? " (" + c.d + ")" : "";
    return '<a href="#p=' + id + '">' + esc(c.n) + esc(y) + "</a>";
  });
}
function renderLog() {
  current = null;
  document.title = "Changelog - Family tree";
  const days = Object.keys(state.log || {}).sort().reverse();
  $("#view").innerHTML = "<h1>Changelog</h1><p class=\"note\">What was added to the family history, day by day.</p>" +
    '<p class="log-legend">' + Object.values(LOG_KINDS).map(([i, l]) => "<span>" + i + " " + l + "</span>").join(" ") + "</p>" +
    (days.length ? days.map((d) => {
      const [y, m, dd] = d.split("-").map(Number);
      return "<h2>" + dayName(y, m, dd) + '</h2><ul class="log">' +
        [...state.log[d]].map(([t, k]) => {
          const [i, l] = LOG_KINDS[k] || LOG_KINDS.record;
          return '<li><span class="log-ic" title="' + l + '" aria-label="' + l + '">' + i + "</span>" + logLine(t) + "</li>";
        }).join("") + "</ul>";
    }).join("") : "<p>Nothing to show yet.</p>");
  window.scrollTo(0, 0);
}

// search box in the header: everyone this device can see
$("#q").addEventListener("input", (e) => {
  const q = fold(e.target.value.trim());
  const aka = (c) => c.a && c.a.split("|").find((x) => fold(x).includes(q));
  const hits = !q ? [] : Object.entries(state.idx).filter(([, c]) => fold(c.n).includes(q) || aka(c))
    .sort((a, b) => a[1].n.localeCompare(b[1].n)).slice(0, 40);
  $("#hits").hidden = !hits.length;
  $("#hits").innerHTML = hits.map(([id, c]) => '<li><a href="#p=' + id + '">' + esc(c.n) + (fold(c.n).includes(q) ? "" : " (" + esc(aka(c)) + ")") + ' <span class="d">' + esc(c.d) + "</span></a></li>").join("");
});
// arrow keys move a highlight through the results, Enter opens it (the first one when none is highlighted), Escape closes
$("#q").addEventListener("keydown", (e) => {
  const links = [...document.querySelectorAll("#hits a")];
  if ($("#hits").hidden || !links.length) return;
  let i = links.findIndex((a) => a.classList.contains("on"));
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    if (i >= 0) links[i].classList.remove("on");
    i = e.key === "ArrowDown" ? (i + 1) % links.length : (i <= 0 ? links.length : i) - 1;
    links[i].classList.add("on");
    links[i].scrollIntoView({ block: "nearest" });
  } else if (e.key === "Enter") {
    e.preventDefault();
    location.hash = links[Math.max(i, 0)].getAttribute("href");
    $("#hits").hidden = true; $("#q").value = ""; $("#q").blur();
  } else if (e.key === "Escape") {
    $("#hits").hidden = true;
  }
});
$("#hits").addEventListener("click", () => { $("#hits").hidden = true; $("#q").value = ""; $("#q").blur(); });
document.addEventListener("click", (e) => { if (!e.target.closest(".find")) $("#hits").hidden = true; });
// a "How we know" item jumps to its numbered source on the same page (the hash stays #p=<id>, which routes the page)
document.addEventListener("click", (e) => {
  const a = e.target.closest("a.srcref");
  if (!a) return;
  e.preventDefault();
  const t = document.getElementById(a.dataset.src);
  if (t) { t.scrollIntoView({ behavior: "smooth", block: "center" }); const li = t.closest("li"); if (li) { li.classList.add("hit"); setTimeout(() => li.classList.remove("hit"), 2500); } }
});

async function sha16(s) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  return Array.from(d.slice(0, 8), (x) => x.toString(16).padStart(2, "0")).join("");
}
async function stubUrl(code) { return location.origin + location.pathname + "l/" + await sha16("familytree-stub:" + code) + ".html"; }

// master only: a personal link for this person (it opens their part of the tree, nothing else)
function shareBox(id) {
  const t = state.codes && state.codes[id];
  if (!t) return "";
  return '<div class=share><button type=button id=sharebtn data-code="' + esc(t) + '">Copy a link for ' + esc(first(state.idx[id].n)) + "</button>" +
    ' <span class=d id=sharemsg>It opens their part of the family tree for them, nothing else.</span></div>';
}
// copy (or, on a phone, share) the preview-stub link for a short code; `msg` is the element told "Link copied"
async function copyLink(code, name, msg) {
  const url = await stubUrl(code);  // name-only preview page that forwards to the #code link
  try {
    if (navigator.share && /Mobi|Android|iPhone|iPad/.test(navigator.userAgent)) await navigator.share({ url, title: name + " · Family tree" });
    else { await navigator.clipboard.writeText(url); msg.textContent = "Link copied. Paste it into a message."; }
  } catch (err) { if (!err || err.name !== "AbortError") window.prompt("Copy this link:", url); }
}
function wireShare() {
  const btn = $("#sharebtn");
  if (!btn) return;
  btn.addEventListener("click", () => copyLink(btn.dataset.code, first(state.idx[current].n), $("#sharemsg")));
}

// Share with family (a share-link reader): their close living relatives, nearest first, each with a copy-link button.
// Codes come only from the reader's own index, so only people in their set can be offered.
const KIN_RANK = [[/^(husband|wife|spouse)$/, 0], [/^(father|mother|parent)$/, 1], [/^(brother|sister|brother or sister|son|daughter|child)$/, 2],
  [/^(grandfather|grandmother|grandparent|grandson|granddaughter|grandchild)$/, 3], [/^(uncle|aunt|uncle or aunt|nephew|niece|nephew or niece)$/, 4],
  [/^first cousin$/, 5], [/^(great-|\d+x great-)?(uncle|aunt|uncle or aunt|nephew|niece|nephew or niece|grandfather|grandmother|grandparent)$/, 6],
  [/^first cousin .*removed$/, 7]];
function livingRelatives() {
  const home = homeId(), out = [];
  for (const [id, c] of Object.entries(state.idx)) {
    const code = state.codes && state.codes[id];
    const m = /^\s*(?:b\.?\s*)?(\d{4})\s*$/.exec(c.d || "");  // a birth year and no death year
    if (!code || id === home || !m || +m[1] < 1920) continue;
    const label = (kinSentence(home, id, true) || "").replace(/^Your /, "").toLowerCase();
    const hit = label && !label.includes("'s ") && KIN_RANK.find(([rx]) => rx.test(label));
    if (hit) out.push({ id, c, code, label, rank: hit[1] });
  }
  return out.sort((a, b) => a.rank - b.rank || (a.c.n < b.c.n ? -1 : 1));
}
// a short strip on a share reader's home page: the same buttons as on each person's page, for the nearest living relatives
function shareStrip() {
  if (state.master || !state.codes) return "";
  const list = livingRelatives().slice(0, 8);
  if (!list.length) return "";
  return '<div class="sharestrip"><h2>Share with family</h2><p class=d>Each link opens the tree centred on that person.</p>' + list.map((r) =>
    '<div><a href="#p=' + r.id + '">' + esc(r.c.n) + '</a> <span class=d>' + esc(r.label) + '</span> <button type="button" data-code="' + esc(r.code) +
    '" data-n="' + esc(first(r.c.n)) + '">Copy a link for ' + esc(first(r.c.n)) + '</button> <span class=d></span></div>').join("") + "</div>";
}
function wireShareStrip() {
  for (const b of document.querySelectorAll(".sharestrip button")) b.addEventListener("click", () => copyLink(b.dataset.code, b.dataset.n, b.nextElementSibling));
}

// "Know something about <first name>? Tell us": the note is sealed in the browser (AES-256-GCM under a fresh key, the key
// wrapped with RSA-OAEP under the public key in n.json) and only that ciphertext is POSTed to the receiver named in n.json.
// It carries who sent it ("master" or the page id behind the share link) and the person it is about.
let notesCfg = null;
async function sealNote(note) {
  if (!notesCfg) notesCfg = await (await fetch("n.json", { cache: "no-store" })).json();
  const pub = await crypto.subtle.importKey("spki", b64(notesCfg.k), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(note))));
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, await crypto.subtle.exportKey("raw", key)));
  const all = new Uint8Array(wrapped.length + 12 + ct.length);
  all.set(wrapped, 0); all.set(iv, wrapped.length); all.set(ct, wrapped.length + 12);
  let s = "";
  for (const x of all) s += String.fromCharCode(x);
  return { url: notesCfg.u, body: btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") };
}
function showNoteBox(pageEl, id) {
  const box = document.createElement("section");
  box.className = "notebox";
  box.innerHTML = "<h2>Know something about " + esc(first(state.idx[id].n)) + "? Tell us</h2>" +
    "<p class=d>A correction, a story, a date, a name, a place. It goes to the people researching this tree as a lead " +
    "(we check it against records). It is encrypted on your device before it is sent.</p>" +
    '<form><textarea maxlength="1200" rows="4" required aria-label="What you know"></textarea>' +
    '<input type="text" maxlength="80" placeholder="Your name (optional)" aria-label="Your name"> ' +
    '<button type="submit">Send</button> <span class=d></span></form>';
  pageEl.appendChild(box);
  const home = localStorage.getItem(HOME);
  box.querySelector("input").value = localStorage.getItem(NAME) || (!state.master && home && state.idx[home] ? state.idx[home].n : "");
  const form = box.querySelector("form"), msg = box.querySelector("span.d:last-child"), btn = form.querySelector("button");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const t = form.querySelector("textarea").value.trim();
    if (!t) return;
    const sender = state.master ? "master" : (localStorage.getItem(HOME) || "");
    const note = { a: id, s: sender, n: form.querySelector("input").value.trim(), t };
    if (enc.encode(JSON.stringify(note)).length > 2400) { msg.textContent = "That is too long; please shorten it a little."; return; }
    btn.disabled = true; msg.textContent = "Sending...";
    try {
      const { url, body } = await sealNote(note);
      const res = await fetch(url, { method: "POST", body });
      if (!res.ok) throw new Error("status " + res.status);
      form.querySelector("textarea").value = "";
      if (note.n) localStorage.setItem(NAME, note.n);
      msg.textContent = "Thank you. We will check it against records.";
    } catch (err) { msg.textContent = "Could not send (" + err.message + "). Please try again later."; }
    finally { btn.disabled = false; }
  });
}

$("#login").addEventListener("submit", async (e) => {
  e.preventDefault();
  let pw = $("#pw").value.trim();
  const m = pw.match(/[#&]k=([^&\s]+)/); // a pasted share link
  const sm = pw.match(/#([A-Za-z0-9_-]{16})$/);
  if (m) { try { pw = decodeURIComponent(m[1]); } catch (_) { pw = m[1]; } } else if (sm) pw = sm[1];
  if (!pw) return;
  $("#msg").textContent = "Checking the password (this takes a few seconds)...";
  $("#login button").disabled = true;
  try {
    const ok = await addPassword(pw, $("#remember").checked);
    $("#msg").textContent = ok ? "" : "That did not open anything. Check the spelling and try again.";
    if (ok) { $("#view").innerHTML = ""; render(); }
  } catch (err) {
    $("#msg").textContent = "Something went wrong: " + err.message;
  } finally { $("#login button").disabled = false; }
});
$("#lock").addEventListener("click", () => { localStorage.removeItem(STORE); localStorage.removeItem(HOME); location.hash = ""; location.reload(); });

// "#k=<token or password>&p=<id>": the part after "#" never leaves the browser; drop it from the address
// bar at once and remember it on this device
function takeLinkPassword() {
  const h = location.hash.slice(1);
  if (SHORT_RX.test(h)) { history.replaceState(null, "", location.pathname + location.search); return h; }
  if (!h.startsWith("k=")) return "";
  const [k, ...rest] = h.slice(2).split("&");
  const pp = rest.find((x) => x.startsWith("p="));
  if (pp && TOKEN_RX.test(k)) localStorage.setItem(HOME, pp.slice(2));
  history.replaceState(null, "", location.pathname + location.search);
  try { return decodeURIComponent(k).trim(); } catch (_) { return k.trim(); }
}
// Visit stats (Google Analytics 4). Off until the build is given a measurement id (private/site/analytics.json).
// Only a path is sent: "/" or "/share" (came through a share link) for the visit, "/p/<token>" for each person page
// opened (the site's opaque page token, never a name, never the hash or a password). No ad personalization.
let viaLink = false, gaOn = false;
function gaInit() {
  const id = (document.querySelector('meta[name="ga"]') || {}).content;
  if (!id || gaOn) return;
  gaOn = true;
  window.dataLayer = window.dataLayer || [];
  window.gtag = function () { window.dataLayer.push(arguments); };
  gtag("js", new Date());
  gtag("config", id, { send_page_view: false, allow_google_signals: false, allow_ad_personalization_signals: false });
  const s = document.createElement("script");
  s.async = true;
  s.src = "https://www.googletagmanager.com/gtag/js?id=" + encodeURIComponent(id);
  document.head.appendChild(s);
}
function gaHit(path) {
  if (!gaOn) return;
  gtag("event", "page_view", { page_location: "https://paultarjan.com/family-tree" + path, page_path: path, page_title: "Family tree", page_referrer: "" });
}
function countVisit() { gaInit(); gaHit(viaLink ? "/share" : "/"); }
async function openLinkPassword() {
  const pw = takeLinkPassword();
  if (pw && (SHORT_RX.test(pw) || TOKEN_RX.test(pw))) viaLink = true;
  if (!pw) return null;
  try { return await addPassword(pw, true); } catch (_) { return false; }
}

window.addEventListener("hashchange", async () => {
  const ok = await openLinkPassword();
  if (ok === false && !Object.keys(state.idx).length && !saved().length) { showLogin(false); $("#msg").textContent = "That link did not open anything."; return; }
  render();
});
let resizeTimer;
// redraw only when the chart's real width or the narrow/wide breakpoint changed: a pinch-zoom fires resize too
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    const s = sizeNow();
    if (s[0] === lastSize[0] && s[1] === lastSize[1]) return;
    lastSize = s;
    if (current) { const y = window.scrollY; drawChart(); if (window.scrollY !== y) window.scrollTo(0, y); }
  }, 200);
});


(async () => {
  const linkOk = await openLinkPassword();
  countVisit();
  const list = saved();
  if (!list.length && !Object.keys(state.idx).length) {
    showLogin(false);
    if (linkOk === false) $("#msg").textContent = "That link did not open anything. Type the password instead.";
    return;
  }
  for (const x of list) { try { const r = await unlock(x.pw, x.i); if (r) await openResult(r); } catch (_) {} }
  render();
})();

// Pull to refresh (touch): at the very top of the page, a vertical pull of about 70 px outside the chart, then release,
// re-reads the index and the open page from the server (every fetch is no-store); the saved keys stay. A status strip
// slides down over the top of the page with the finger (damped), holds there while refreshing, then slides back up.
// The strip is the only thing that moves: the header and page are never transformed, so no missed touch event, bfcache
// restore or Safari repaint of the sticky header can leave a blank band above them. One number, `shown`, is how far the
// strip is down; its position and visibility are derived from it and nothing else.
(() => {
  const NEED = 70, HOLD = 44, BAND = 100;
  let y0 = null, x0 = 0, pull = 0, busy = false, shown = 0;
  const bar = document.createElement("div");
  bar.id = "ptr"; bar.hidden = true;
  bar.style.height = BAND + "px"; bar.style.alignItems = "flex-end"; bar.style.paddingBottom = ".6rem"; bar.style.boxSizing = "border-box";
  document.body.appendChild(bar);
  const show = (px, animate) => {
    shown = px;
    if (px) bar.hidden = false;
    bar.style.transition = animate ? "transform .25s ease" : "none";
    bar.style.transform = "translateY(" + (px - BAND) + "px)";
    if (!px && !animate) bar.hidden = true;
  };
  bar.addEventListener("transitionend", () => { if (!shown) bar.hidden = true; });
  const reset = () => { y0 = null; pull = 0; show(0, !bar.hidden); };
  async function reload() {
    busy = true; bar.textContent = "Refreshing…"; show(HOLD, true);
    try {
      if (saved().length) await refreshIndex().catch(() => {}); else state.pages = {};
      try { // a newer shell: a plain reload fetches it
        const t = await (await fetch("index.html?r=" + Date.now(), { cache: "no-store" })).text();
        const cur = (document.querySelector("script[src*='app.js']") || {}).src || "";
        const m = t.match(/app\.js\?v=([0-9a-f]+)/);
        if (m && cur && !cur.includes(m[1])) return location.reload();
      } catch (_) {}
      await render();
    } finally { busy = false; reset(); }
  }
  // a pull is a one-finger gesture at the top of an unzoomed page outside the chart; anything else puts the strip away
  const zoomedIn = () => !!window.visualViewport && (visualViewport.scale > 1.01 || visualViewport.offsetTop > 1);
  const drop = () => { if (shown) reset(); else y0 = null; };
  addEventListener("touchstart", (e) => {
    if (busy) return;
    if (e.touches.length !== 1 || window.scrollY > 0 || zoomedIn() || e.target.closest("#chart")) { drop(); return; }
    if (shown) reset(); // a strip left from a gesture whose end never came
    y0 = e.touches[0].clientY; x0 = e.touches[0].clientX; pull = 0;
  }, { passive: true });
  addEventListener("touchmove", (e) => {
    if (y0 === null) return;
    if (e.touches.length !== 1) { drop(); return; }
    const dy = e.touches[0].clientY - y0, dx = e.touches[0].clientX - x0;
    if (window.scrollY > 0 || dy <= 0 || Math.abs(dx) > dy) { if (shown) reset(); y0 = null; return; }
    pull = dy;
    bar.textContent = dy >= NEED ? "Release to refresh" : "Pull to refresh";
    show(Math.round(Math.min(dy, 200) * 0.5), false);
  }, { passive: true });
  addEventListener("touchend", (e) => {
    if (busy || e.touches.length) return;
    const go = y0 !== null && pull >= NEED; y0 = null;
    if (go) reload(); else if (shown) reset();
  }, { passive: true });
  addEventListener("touchcancel", () => { if (!busy && shown) reset(); }, { passive: true });
  // whenever no pull is in progress the strip is away (back from another tab or the back-forward cache)
  const heal = () => { if (!busy && y0 === null && shown) reset(); };
  addEventListener("pageshow", heal);
  document.addEventListener("visibilitychange", heal);
})();
