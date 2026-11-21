// The family chart: the person in focus at the centre, parents and grandparents above, spouses beside,
// brothers and sisters on the same row, children below; boxes and elbow lines like the printed charts.
// Boxes are links (#p=<id>), so a tap re-centres and Back works; a box that stays on screen glides to
// its new place. The chart is a native horizontal scroll area (scrollLeft is the one position): scrollbar, trackpad, shift-wheel and touch work natively, and a mouse drag just sets scrollLeft. Exposes window.FamilyChart.
"use strict";
(function () {
  const SVGNS = "http://www.w3.org/2000/svg";
  const escH = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  let els = new Map(); // key -> box element, kept between draws so boxes can move
  let root = null;

  function dims() {
    const narrow = window.matchMedia("(max-width: 600px)").matches;
    return narrow ? { W: 116, H: 76, GX: 10, GY: 34 } : { W: 158, H: 84, GX: 16, GY: 42 };
  }

  // idx: {id: {n, d, pl, s, fa, mo, fams: [[spouse, [kids]]]}}; "?" = a relative the reader cannot see, "" = unknown
  // hOf(row) = that row's height (the tallest box in it, measured by draw)
  function layout(idx, F, opt, hOf) {
    const { W, H, GX, GY } = dims();
    const S = W + GX;
    const Y = (r) => { let y = 0; if (r > 0) for (let q = 0; q < r; q++) y += hOf(q) + GY; else for (let q = r; q < 0; q++) y -= hOf(q) + GY; return y; };
    const items = [], lines = [];
    const count = {};
    let hid = 0;
    const vis = (id) => id && id !== "?" && idx[id];
    const add = (id, x, r, cls, extra) => {
      const k = id ? id + "#" + (count[id] = (count[id] || 0) + 1) : "?" + hid++;
      const it = Object.assign({ key: k, id, x, r, y: Y(r), h: hOf(r), cls }, extra || {});
      items.push(it);
      return it;
    };
    const mid = (it) => it.y + it.h / 2;
    const drop = (fromX, fromY, kids, toY) => { // elbow lines from a couple (or a parent) to children
      const bar = toY - GY / 2;
      const xs = kids.map((k) => k.x);
      let d = "M" + fromX + " " + fromY + "V" + bar;
      d += "M" + Math.min(fromX, ...xs) + " " + bar + "H" + Math.max(fromX, ...xs);
      for (const x of xs) d += "M" + x + " " + bar + "V" + toY;
      lines.push(d);
    };
    const couple = (a, b, up) => { // a line joining two partners at mid height (or over the top when apart)
      const [l, r] = a.x < b.x ? [a, b] : [b, a];
      if (!up) { lines.push("M" + (l.x + W / 2) + " " + mid(l) + "H" + (r.x - W / 2)); return [(l.x + r.x) / 2, mid(l)]; }
      lines.push("M" + l.x + " " + l.y + "v-8H" + r.x + "v8");
      return [(l.x + r.x) / 2, l.y - 8];
    };
    const parentsOf = (id) => (vis(id) ? [idx[id].fa, idx[id].mo].filter((x) => x) : []);
    const width = (id, k) => {
      if (k >= opt.up) return S;
      const ps = parentsOf(id);
      return ps.length ? Math.max(S, ps.reduce((a, p) => a + width(p, k + 1), 0)) : S;
    };
    // ancestors, each couple centred over their child; returns the line start for the child below
    const placeUp = (id, k, cx) => {
      const ps = k < opt.up ? parentsOf(id) : [];
      if (!ps.length) return null;
      const ws = ps.map((p) => width(p, k + 1));
      let x = cx - ws.reduce((a, b) => a + b, 0) / 2;
      const boxes = ps.map((p, i) => {
        const bx = x + ws[i] / 2;
        x += ws[i];
        const b = add(vis(p) ? p : null, bx, -(k + 1), vis(p) ? "" : "faint");
        const from = placeUp(p, k + 1, bx);
        if (from) drop(from[0], from[1], [b], b.y);
        return b;
      });
      return boxes.length === 2 ? couple(boxes[0], boxes[1]) : [boxes[0].x, boxes[0].y + boxes[0].h];
    };

    const f = idx[F];
    const me = add(F, 0, 0, "focus");
    const from = placeUp(F, 0, 0);
    // brothers and sisters: the parents' family that holds F, in birth order, to the left; spouses to the right
    let sibs = [];
    for (const p of parentsOf(F)) {
      if (!vis(p)) continue;
      const fam = idx[p].fams.find((fm) => fm[1].includes(F));
      if (fam) { sibs = fam[1].filter((x) => x !== F); break; }
    }
    const row = [me];
    const fams = f.fams;
    let right = 1;
    const spBoxes = fams.map((fm) => (fm[0] ? add(vis(fm[0]) ? fm[0] : null, right++ * S, 0, (vis(fm[0]) ? "" : "faint") + " spouse") : null));
    if (sibs.length && !opt.sibs) {
      row.push(add(null, -S, 0, "chip", { act: "sibs", label: sibs.length === 1 ? "1 brother or sister" : sibs.length + " brothers and sisters" }));
    } else {
      sibs.forEach((s, i) => row.push(add(vis(s) ? s : null, (i - sibs.length) * S, 0, vis(s) ? "sib" : "faint sib")));
    }
    if (from) drop(from[0], from[1], row, 0);
    // children under each couple, families side by side
    let cursor = -Infinity;
    fams.forEach((fm, j) => {
      const kids = fm[1];
      if (!kids.length) return;
      const sb = spBoxes[j];
      const join = sb ? couple(me, sb, Math.abs(sb.x) > S) : [0, me.h];
      const shown = kids.filter((k) => vis(k));
      const hidden = kids.length - shown.length;
      const n = shown.length + (hidden ? 1 : 0);
      const start = Math.max(cursor, join[0] - (n * S) / 2);
      const boxes = shown.map((k, i) => add(k, start + S / 2 + i * S, 1, "kid"));
      if (hidden) boxes.push(add(null, start + S / 2 + shown.length * S, 1, "faint kid", { label: hidden === 1 ? "a relative" : hidden + " relatives" }));
      cursor = start + n * S;
      drop(join[0], join[1], boxes, Y(1));
    });
    spBoxes.forEach((sb, j) => { if (sb && !fams[j][1].length) couple(me, sb, Math.abs(sb.x) > S); });
    // the up arrow: one rule for every box, a visible parent of that person is not drawn on this chart
    const drawn = new Set(items.map((i) => i.id).filter((x) => x));
    for (const it of items) it.more = !!it.id && parentsOf(it.id).some((p) => vis(p) && !drawn.has(p));
    return { items, lines, W, H, S };
  }

  function boxHTML(idx, it) {
    if (it.act || it.label) return '<span class="nm">' + escH(it.label) + "</span>";
    if (!it.id) return '<span class="nm">a relative</span>';
    const c = idx[it.id];
    return '<span class="nm">' + escH(c.n) + '</span><span class="yr">' + escH(c.d) + "</span>" +
      (c.pl ? '<span class="pl">' + escH(c.pl) + "</span>" : "") + (it.more ? '<span class="up" aria-hidden="true"></span>' : "");
  }

  function draw(container, idx, F, opt) {
    if (root !== container || !container.querySelector(".stage")) {
      root = container;
      container.innerHTML = '<div class="stage"><svg class="lines" width="1" height="1"></svg></div>';
      els = new Map();
      wire(container);
    }
    const stage = container.querySelector(".stage");
    // first pass with the base height, then measure every label at the box width: rows grow, labels never cut
    const D = dims();
    let meas = stage.querySelector(".measure");
    if (!meas) { meas = document.createElement("div"); stage.appendChild(meas); }
    const rows = {};
    for (const it of layout(idx, F, opt, () => D.H).items) {
      meas.className = "box measure " + it.cls + (it.id && idx[it.id].s ? " st" : "") + (it.more ? " mr" : "");
      meas.style.width = D.W + "px";
      meas.innerHTML = boxHTML(idx, it);
      rows[it.r] = Math.max(rows[it.r] || D.H, Math.ceil(meas.getBoundingClientRect().height));
    }
    const L = layout(idx, F, opt, (r) => rows[r] || D.H);
    const svg = stage.querySelector("svg");
    const ys = L.items.map((i) => i.y), xs = L.items.map((i) => i.x);
    const top = Math.min(...ys) - 14, bottom = Math.max(...L.items.map((i) => i.y + i.h)) + 14;
    // the stage is as wide as the chart (so the container really scrolls); the focus person (x = 0) sits at
    // `off`, and the scroll position that centres them is off - width/2. A chart narrower than the view is centred.
    const cw = container.clientWidth, sOld = container.scrollLeft;
    const span = Math.max(...xs) - Math.min(...xs) + L.W + 16;
    const stageW = Math.max(span, cw);
    const off = (stageW - span) / 2 - Math.min(...xs) + L.W / 2 + 8;
    stage.style.width = stageW + "px";
    stage.style.height = (bottom - top) + "px";
    stage.style.transform = "translateY(" + (-top) + "px)";
    container.style.height = (bottom - top) + "px";
    if (stageW > cw + 1) container.style.height = (bottom - top + container.offsetHeight - container.clientHeight - 2) + "px";
    const sNew = Math.max(0, Math.min(stageW - cw, off - cw / 2));
    container.scrollTo({ left: sNew, behavior: "instant" });
    // a box that stays on screen starts from where the reader saw it (the scroll jumped), then glides
    const dScroll = sOld - container.scrollLeft;
    const keep = new Set();
    for (const it of L.items) {
      keep.add(it.key);
      let el = els.get(it.key);
      const fresh = !el;
      if (fresh) {
        el = document.createElement(it.id ? "a" : "div");
        el.style.opacity = "0";
        stage.appendChild(el);
        els.set(it.key, el);
      }
      if (!fresh && el._cx != null) {
        el.style.transition = "none";
        el.style.transform = "translate(" + (el._cx + dScroll) + "px," + el._cy + "px)";
        void el.offsetWidth;
        el.style.transition = "";
      }
      if (it.id) el.setAttribute("href", "#p=" + it.id);
      const isAnc = !!(it.id && opt.anc && opt.anc.has(it.id));
      el.className = "box " + it.cls + (it.id && idx[it.id].s ? " st" : "") + (it.more ? " mr" : "") + (isAnc ? " anc" : "");
      if (isAnc) el.title = opt.ancLabel || "Direct ancestor"; else el.removeAttribute("title");
      el.style.width = L.W + "px"; el.style.height = it.h + "px";
      if (it.act) el.dataset.act = it.act;
      el.innerHTML = boxHTML(idx, it);
      el._cx = it.x - L.W / 2 + off; el._cy = it.y;
      el.style.transform = "translate(" + el._cx + "px," + el._cy + "px)";
      if (fresh) requestAnimationFrame(() => requestAnimationFrame(() => { el.style.opacity = ""; }));
    }
    for (const [k, el] of els) {
      if (keep.has(k)) continue;
      els.delete(k);
      el.style.opacity = "0";
      el.style.pointerEvents = "none";
      setTimeout(() => el.remove(), 350);
    }
    svg.style.transform = "translateX(" + off + "px)";
    // the lines fade and rebuild only when they changed (a redraw with the same chart leaves them alone)
    const key = L.lines.join("|");
    if (svg.dataset.key === key) return;
    svg.dataset.key = key;
    svg.style.opacity = "0";
    clearTimeout(svg._t);
    svg._t = setTimeout(() => {
      svg.innerHTML = "";
      for (const d of L.lines) { const p = document.createElementNS(SVGNS, "path"); p.setAttribute("d", d); svg.appendChild(p); }
      svg.style.opacity = "";
    }, 260);
  }

  // A mouse drag sets scrollLeft (so the scrollbar thumb moves with it); touch and trackpad scroll natively.
  // A drag never counts as a tap on a box.
  function wire(container) {
    let start = null, moved = false;
    container.addEventListener("pointerdown", (e) => {
      if (e.button === 0 && e.pointerType === "mouse") { start = [e.clientX, container.scrollLeft, e.pointerId]; moved = false; }
    });
    container.addEventListener("pointermove", (e) => {
      if (!start) return;
      const dx = e.clientX - start[0];
      if (!moved && Math.abs(dx) > 6) { moved = true; try { container.setPointerCapture(start[2]); } catch (_) {} }
      if (moved) container.scrollLeft = start[1] - dx;
    });
    const end = () => { start = null; };
    container.addEventListener("pointerup", end);
    container.addEventListener("pointercancel", end);
    container.addEventListener("click", (e) => {
      if (moved) { e.preventDefault(); moved = false; return; }
      const b = e.target.closest(".box");
      if (b && b.dataset.act && container.onAction) { e.preventDefault(); container.onAction(b.dataset.act); }
    });
  }

  window.FamilyChart = { draw };
})();
