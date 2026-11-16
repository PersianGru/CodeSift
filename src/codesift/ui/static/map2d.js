/* CodeSift UI: the light 2D map. The same realm as the 3D view, seen from above and drawn on a plain
   canvas: no WebGL, no three.js, little memory - it suits old laptops and phones. It draws
   window.SiftWorld; everything that moves is one real event. The land is painted once per size
   into an off-screen canvas; a frame only draws the tokens on top, and when nothing moves the map
   redraws a few times a second. */
(function () {
  "use strict";

  var W = window.SiftWorld;
  var C = {
    night: "#070b16", sea: "#12304a", land: "#27452f", landHi: "#31563a", hill: "#3a5a45", wood: "#1c3a2c", woodHi: "#2c5a40",
    river: "#2b6a94", road: "#8a6f52", stone: "#9a9bb0", stoneLo: "#5f6078", roof: "#3d4f86", ash: "#3b3d47", grave: "#7f8192",
    text: "#eef0f4", dim: "#a7adba", gold: "#ffc861", amber: "#f5a524", scan: "#78e6c8", llm: "#b69cff", reply: "#ffd36e",
    vm: "#5abeff", ok: "#5ed68c", bad: "#ff5c5c", grey: "#8a8d98", ink: "rgba(7,10,18,0.82)"
  };
  var FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif";
  // the same places as the 3D realm, in its world units (x east, z south)
  var BOX = { x0: -54, x1: 54, z0: -24, z1: 52 };
  var P = { core: [0, 0], gate: [0, 10.5], junction: [0, 17], wildsGate: [0, 31], wilds: [0, 39.5, 17, 8], tower: [34, 2], dungeon: [-48, -4, 22, 14] };
  var RIVER = [[-58, 17], [-46, 21.5], [-22, 25], [0, 24], [22, 25], [46, 21.5], [58, 17]];
  var ROAD_TOWER = [[0, 17], [8, 18.2], [17, 16.4], [24, 12.6], [28.6, 9.2], [31.2, 6.9]];
  var ROAD_DUNGEON = [[0, 17], [-8, 18.2], [-15.5, 16.2], [-19.5, 11.5], [-21.2, 7], [-26, 5], [-37, 5]];
  var CAMP = [[-4.6, 6.4], [-7.2, 5.2], [-7.6, 2.4], [-5.8, 0.4], [-2.9, 0.9], [-1.7, 3.6], [3.3, 8.2], [-3.3, 8.6], [7.2, -1.4], [7.4, 3.2], [2.6, -6.2], [-2.6, -6.2], [7.2, -5.8], [-7.4, -4.6]];
  var CHAMP_AT = [[3.4, 1.4], [4.8, -2.0], [2.2, 4.4], [5.6, 4.0]];
  var MAX_BODIES = 40;

  function rng(seed) {
    var s = seed >>> 0;
    return function () {
      s = (s + 0x6D2B79F5) >>> 0;
      var t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function spotsIn(n, minD, seed, avoid) { // loose spots in the wilds, the same every time
    var r = rng(seed), out = [], w = P.wilds, tries, i, ok, x, z;
    for (tries = 0; out.length < n && tries < 5000; tries++) {
      x = w[0] + (r() * 2 - 1) * (w[2] - 1.5); z = w[1] + (r() * 2 - 1) * (w[3] - 1);
      if ((x - w[0]) * (x - w[0]) / ((w[2] - 1.5) * (w[2] - 1.5)) + (z - w[1]) * (z - w[1]) / ((w[3] - 1) * (w[3] - 1)) > 1) { continue; }
      for (ok = true, i = 0; i < out.length; i++) { if ((out[i][0] - x) * (out[i][0] - x) + (out[i][1] - z) * (out[i][1] - z) < minD * minD) { ok = false; break; } }
      for (i = 0; ok && avoid && i < avoid.length; i++) { if ((avoid[i][0] - x) * (avoid[i][0] - x) + (avoid[i][1] - z) * (avoid[i][1] - z) < 4) { ok = false; } }
      if (ok) { out.push([x, z]); }
    }
    return out;
  }
  var SLOTS = spotsIn(44, 3.2, 77), SPOTS = spotsIn(14, 4.6, 78, SLOTS);

  /* A token that walks a line of waypoints: `at` runs 0..1 along it. */
  function Walker(camp) { this.camp = camp; this.pts = [camp, camp]; this.len = [0, 0]; this.at = 0; this.want = 0; this.x = camp[0]; this.z = camp[1]; }
  Walker.prototype.route = function (target) {
    this.pts = [this.camp, [0, 8.8], P.junction, [0, 28], target];
    var total = 0, i; this.len = [0];
    for (i = 1; i < this.pts.length; i++) { total += Math.sqrt(Math.pow(this.pts[i][0] - this.pts[i - 1][0], 2) + Math.pow(this.pts[i][1] - this.pts[i - 1][1], 2)); this.len.push(total); }
    this.total = total;
  };
  Walker.prototype.step = function (dt, snap) {
    var moving = this.at !== this.want;
    if (snap) { this.at = this.want; }
    else if (moving) { var d = dt * 13 / (this.total || 1); this.at = this.want > this.at ? Math.min(this.want, this.at + d) : Math.max(this.want, this.at - d); }
    var dist = this.at * (this.total || 0), i = 1;
    while (i < this.len.length - 1 && this.len[i] < dist) { i++; }
    var seg = this.len[i] - this.len[i - 1], u = seg > 0 ? (dist - this.len[i - 1]) / seg : 0, a = this.pts[i - 1], b = this.pts[i];
    this.x = a[0] + (b[0] - a[0]) * u; this.z = a[1] + (b[1] - a[1]) * u;
    return moving;
  };

  function Map2D(container) {
    this.el = container;
    this.world = W.create();
    this.canvas = document.createElement("canvas");
    this.canvas.tabIndex = 0;
    this.canvas.className = "map2d";
    this.canvas.setAttribute("aria-label", "2D map of the run");
    container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext("2d");
    this.back = document.createElement("canvas");
    this.birds = []; this.runes = []; this.rings = []; this.hits = []; this.walkers = {}; this.slotOf = {}; this.slotUsed = [];
    this.time = 0; this.speed = 1; this.paused = false; this.last = performance.now(); this.snap = false; this.moving = false;
    this.reduced = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
    var self = this;
    this.pacer = new W.Pacer(this.world, function (fx, animate) { if (animate) { self.effects(fx); } else { self.snap = true; self.birds.length = 0; self.runes.length = 0; self.rings.length = 0; } });
    this.onResize = function () { self.resize(); };
    window.addEventListener("resize", this.onResize);
    this.onClick = function (e) { self.pick(e); };
    this.canvas.addEventListener("click", this.onClick);
    this.resize();
    this.loop();
  }

  Map2D.prototype.resize = function () {
    var r = this.el.getBoundingClientRect(), dpr = Math.min(2, window.devicePixelRatio || 1);
    this.w = Math.max(300, r.width); this.h = Math.max(220, r.height); this.dpr = dpr;
    this.canvas.width = Math.round(this.w * dpr); this.canvas.height = Math.round(this.h * dpr);
    this.canvas.style.width = this.w + "px"; this.canvas.style.height = this.h + "px";
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    // fit the realm: one scale on a wide screen; on a tall phone the map may stretch north-south to use the room
    var top = this.w >= 720 ? 74 : 10, bottom = this.w >= 720 ? 18 : 64, bw = BOX.x1 - BOX.x0, bh = BOX.z1 - BOX.z0;
    var sx = (this.w - 16) / bw, sz = (this.h - top - bottom) / bh;
    if (sz < sx) { sx = sz; } else { sz = Math.min(sz, sx * 1.9); }
    this.sx = sx; this.sz = sz; this.u = Math.min(sx, sz);
    this.ox = this.w / 2 - (BOX.x0 + bw / 2) * sx; this.oz = top + ((this.h - top - bottom) - bh * sz) / 2 - BOX.z0 * sz;
    this.small = this.w < 720;
    this.paint();
  };
  Map2D.prototype.X = function (x) { return this.ox + x * this.sx; };
  Map2D.prototype.Z = function (z) { return this.oz + z * this.sz; };

  function line(ctx, m, pts) {
    ctx.beginPath();
    for (var i = 0; i < pts.length; i++) {
      var x = m.X(pts[i][0]), y = m.Z(pts[i][1]);
      if (!i) { ctx.moveTo(x, y); } else {
        var px = m.X(pts[i - 1][0]), py = m.Z(pts[i - 1][1]);
        ctx.quadraticCurveTo(px, py, (px + x) / 2, (py + y) / 2);
        if (i === pts.length - 1) { ctx.lineTo(x, y); }
      }
    }
  }
  function blob(ctx, m, x, z, rx, rz, color) { ctx.beginPath(); ctx.ellipse(m.X(x), m.Z(z), rx * m.sx, rz * m.sz, 0, 0, Math.PI * 2); ctx.fillStyle = color; ctx.fill(); }
  function place(ctx, x, y, title, sub) {
    ctx.textAlign = "center";
    ctx.font = "800 11px " + FONT; var w1 = ctx.measureText(title.toUpperCase()).width * 1.18;
    ctx.font = "11px " + FONT; var w2 = sub ? ctx.measureText(sub).width : 0, w = Math.max(w1, w2) + 16, h = sub ? 32 : 19;
    ctx.fillStyle = C.ink; ctx.fillRect(x - w / 2, y - 13, w, h);
    ctx.fillStyle = C.gold; ctx.font = "800 11px " + FONT;
    if (ctx.letterSpacing !== undefined) { ctx.letterSpacing = "1.5px"; }
    ctx.fillText(title.toUpperCase(), x, y);
    if (ctx.letterSpacing !== undefined) { ctx.letterSpacing = "0px"; }
    if (sub) { ctx.fillStyle = C.dim; ctx.font = "11px " + FONT; ctx.fillText(sub, x, y + 14); }
    ctx.textAlign = "left";
  }

  /* The land: painted once per size. Nothing here depends on the run. */
  Map2D.prototype.paint = function () {
    var b = this.back, m = this, i, r = rng(5), u = this.u;
    b.width = this.canvas.width; b.height = this.canvas.height;
    var ctx = b.getContext("2d");
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    var g = ctx.createLinearGradient(0, 0, 0, this.h); g.addColorStop(0, C.night); g.addColorStop(1, C.sea);
    ctx.fillStyle = g; ctx.fillRect(0, 0, this.w, this.h);
    blob(ctx, m, 0, 13, 53, 37, "#1a3a52"); blob(ctx, m, 0, 13, 51, 35.5, C.land);
    [[-34, -12, 20, 9], [4, -15, 22, 8], [38, -12, 18, 9], [-46, 34, 10, 8], [44, 30, 10, 7]].forEach(function (h) { blob(ctx, m, h[0], h[1], h[2], h[3], C.hill); });
    blob(ctx, m, 0, 0, 20, 19, C.landHi); blob(ctx, m, P.tower[0], P.tower[1], 9, 9, C.landHi);
    for (i = 0; i < 230; i++) { // forest: small firs, thick behind and at the edges
      var x = BOX.x0 + 4 + r() * (BOX.x1 - BOX.x0 - 8), z = -22 + r() * 70, far = Math.sqrt(x * x / (50 * 50) + (z - 13) * (z - 13) / (34 * 34));
      if (far > 0.97 || Math.sqrt(x * x + z * z) < 23 || (Math.abs(z - 23) < 6) || (z > 27 && Math.abs(x) < 22) || (x > 23 && x < 44 && z > -6 && z < 14) || (x < -22 && z > -8 && z < 14) || (z > 8 && z < 22 && Math.abs(x) < 34)) { continue; }
      if (z > -4 && Math.abs(x) < 40 && r() < 0.6) { continue; }
      var s = (0.9 + r() * 0.8) * u, px = m.X(x), py = m.Z(z);
      ctx.beginPath(); ctx.moveTo(px, py - s * 1.5); ctx.lineTo(px + s, py + s * 0.7); ctx.lineTo(px - s, py + s * 0.7); ctx.closePath();
      ctx.fillStyle = r() < 0.5 ? C.wood : C.woodHi; ctx.fill();
    }
    ctx.lineCap = "round"; ctx.lineJoin = "round";
    line(ctx, m, RIVER); ctx.strokeStyle = "#1c4d70"; ctx.lineWidth = 7.2 * m.sz; ctx.stroke();
    line(ctx, m, RIVER); ctx.strokeStyle = C.river; ctx.lineWidth = 5.2 * m.sz; ctx.stroke();
    // roads: every one joins two places
    ctx.strokeStyle = C.road; ctx.lineWidth = Math.max(3, 2.6 * u);
    line(ctx, m, [P.gate, [0, 20]]); ctx.stroke(); line(ctx, m, [[0, 28], P.wildsGate, [0, 33]]); ctx.stroke();
    line(ctx, m, ROAD_TOWER); ctx.stroke(); line(ctx, m, ROAD_DUNGEON.slice(0, 6)); ctx.stroke();
    ctx.fillStyle = C.stone; ctx.fillRect(m.X(-2.6), m.Z(19.4), 5.2 * m.sx, 9.2 * m.sz);
    ctx.strokeStyle = C.stoneLo; ctx.lineWidth = 1.5; ctx.strokeRect(m.X(-2.6), m.Z(19.4), 5.2 * m.sx, 9.2 * m.sz);
    // the wilds: ashen ground and graves
    blob(ctx, m, P.wilds[0], P.wilds[1], P.wilds[2] + 2, P.wilds[3] + 2, "#2f3a3a"); blob(ctx, m, P.wilds[0], P.wilds[1], P.wilds[2], P.wilds[3], C.ash);
    ctx.strokeStyle = C.grave; ctx.lineWidth = 1.4;
    for (i = 0; i < 26; i++) {
      var a = r() * 6.283, k = 0.86 + r() * 0.16, gx = m.X(P.wilds[0] + Math.cos(a) * P.wilds[2] * k), gy = m.Z(P.wilds[1] + Math.sin(a) * P.wilds[3] * k);
      if (Math.abs(gx - m.X(0)) < 3 * m.sx && gy < m.Z(P.wilds[1])) { continue; }
      ctx.beginPath(); ctx.moveTo(gx, gy - 4); ctx.lineTo(gx, gy + 4); ctx.moveTo(gx - 3, gy - 1.5); ctx.lineTo(gx + 3, gy - 1.5); ctx.stroke();
    }
    // the castle: walls, corner towers, keep
    var cx = m.X(-10.5), cy = m.Z(-10.5), cw = 21 * m.sx, ch = 21 * m.sz;
    ctx.fillStyle = "#b9b4a8"; ctx.fillRect(cx, cy, cw, ch);
    ctx.strokeStyle = C.stoneLo; ctx.lineWidth = Math.max(3, 1.2 * u); ctx.strokeRect(cx, cy, cw, ch);
    ctx.fillStyle = "#b9b4a8"; ctx.fillRect(m.X(-2), m.Z(10.5) - 3, 4 * m.sx, 7); // the gate: a gap in the south wall
    [[-10.9, -10.9], [10.9, -10.9], [-10.9, 10.9], [10.9, 10.9]].forEach(function (t) { ctx.beginPath(); ctx.arc(m.X(t[0]), m.Z(t[1]), 2.7 * u, 0, 6.283); ctx.fillStyle = C.roof; ctx.fill(); ctx.strokeStyle = C.stone; ctx.lineWidth = 1.5; ctx.stroke(); });
    ctx.fillStyle = C.stone; ctx.fillRect(m.X(-4.2), m.Z(-15.6), 8.4 * m.sx, 7 * m.sz); ctx.strokeStyle = C.stoneLo; ctx.strokeRect(m.X(-4.2), m.Z(-15.6), 8.4 * m.sx, 7 * m.sz);
    // the wizard's tower
    ctx.beginPath(); ctx.arc(m.X(P.tower[0]), m.Z(P.tower[1]), 4.6 * u, 0, 6.283); ctx.fillStyle = C.stoneLo; ctx.fill();
    ctx.beginPath(); ctx.arc(m.X(P.tower[0]), m.Z(P.tower[1]), 3.6 * u, 0, 6.283); ctx.fillStyle = C.stone; ctx.fill();
    ctx.beginPath(); ctx.arc(m.X(P.tower[0]), m.Z(P.tower[1]), 2.3 * u, 0, 6.283); ctx.fillStyle = "#5b43b0"; ctx.fill();
    // the dungeon: a pit with a cell block, stairs in from the east
    var d = P.dungeon;
    ctx.fillStyle = C.stoneLo; ctx.fillRect(m.X(d[0]), m.Z(d[1]), d[2] * m.sx, d[3] * m.sz);
    ctx.fillStyle = "#2a2c3a"; ctx.fillRect(m.X(d[0] + 1), m.Z(d[1] + 1), (d[2] - 2) * m.sx, (d[3] - 2) * m.sz);
    ctx.fillStyle = C.stone; for (i = 0; i < 4; i++) { ctx.fillRect(m.X(d[0] + d[2] - 5 + i * 1.1), m.Z(d[1] + 6.6), 0.7 * m.sx, 4.8 * m.sz); }
    this.dirty = true;
  };

  // ------------------------------------------------------------------ the story on top

  Map2D.prototype.walker = function (key, champion) {
    if (!this.walkers[key]) {
      var n = 0, k;
      for (k in this.walkers) { if (this.walkers[k].champion === champion) { n++; } }
      var wk = new Walker(champion ? CHAMP_AT[n % CHAMP_AT.length] : CAMP[n % CAMP.length]);
      wk.champion = champion; wk.spot = SPOTS[n % SPOTS.length]; wk.goal = "";
      if (!champion) { wk.route(wk.spot); }
      this.walkers[key] = wk;
    }
    return this.walkers[key];
  };
  Map2D.prototype.slot = function (f) {
    if (this.slotOf[f.id] !== undefined) { return SLOTS[this.slotOf[f.id]]; }
    var wk = f.tool ? this.walkers["s:" + f.tool] : null, from = wk ? wk.spot : [0, 36], best = -1, bd = 1e9, i;
    for (i = 0; i < SLOTS.length; i++) {
      if (this.slotUsed[i]) { continue; }
      var dd = (SLOTS[i][0] - from[0]) * (SLOTS[i][0] - from[0]) + (SLOTS[i][1] - from[1]) * (SLOTS[i][1] - from[1]);
      if (dd < bd) { bd = dd; best = i; }
    }
    if (best < 0) { return null; }
    this.slotUsed[best] = true; this.slotOf[f.id] = best;
    return SLOTS[best];
  };

  Map2D.prototype.handle = function (ev) { this.pacer.push(ev); };

  Map2D.prototype.effects = function (fx) {
    for (var i = 0; i < fx.length; i++) {
      var e = fx[i], s;
      if (e.kind === "llm") { this.birds.push({ t: 0, back: false, model: e.to.slice(6), color: C.llm, size: 1 + (e.size || 0) * 0.8, fail: false }); }
      else if (e.kind === "reply") { this.birds.push({ t: 0, back: true, model: e.from.slice(6), color: C.reply, size: 1 + (e.size || 0) * 0.8, fail: false }); }
      else if (e.kind === "fail" && e.from.indexOf("model:") === 0) { this.birds.push({ t: 0, back: true, model: e.from.slice(6), color: C.reply, size: 1, fail: true }); }
      else if (e.kind === "vm" || (e.kind === "fail" && e.from === "vm")) { this.runes.push({ t: 0, back: e.from === "vm", color: e.kind === "fail" ? C.bad : e.from === "vm" ? C.ok : C.vm }); }
      else if (e.kind === "finding") { s = this.slot(e.finding); if (s) { this.rings.push({ x: s[0], z: s[1], t: 0, color: W.SEV_COLORS[e.finding.severity] || C.grey, big: 1 }); } }
      else if (e.kind === "gate" || e.kind === "policy") {
        s = this.slotOf[e.finding.id] !== undefined ? SLOTS[this.slotOf[e.finding.id]] : null;
        var good = e.kind === "policy" ? e.ok : e.status === "pass", bad = e.kind === "policy" ? !e.ok : e.status === "fail";
        if (s) { this.rings.push({ x: s[0], z: s[1], t: 0, color: good ? C.ok : bad ? C.bad : C.grey, big: 1 }); }
      }
      else if (e.kind === "outcome") { s = this.slotOf[e.finding.id] !== undefined ? SLOTS[this.slotOf[e.finding.id]] : null; if (s) { this.rings.push({ x: s[0], z: s[1], t: 0, color: e.won ? C.ok : C.bad, big: 2 }); } }
      else if (e.kind === "wards") { this.rings.push({ x: P.dungeon[0] + P.dungeon[2] / 2, z: P.dungeon[1] + P.dungeon[3] / 2, t: 0, color: e.ok ? "#59e0ff" : C.bad, big: 3 }); }
      else if (e.kind === "end") { this.rings.push({ x: 0, z: -12, t: 0, color: e.ok ? C.ok : C.bad, big: 5 }); }
    }
  };

  function shape(ctx, sev, x, y, s) { // one shape per severity, the same as the counters in the status strip
    ctx.beginPath();
    if (sev === "critical") { ctx.moveTo(x, y - s * 1.25); ctx.lineTo(x + s * 1.25, y); ctx.lineTo(x, y + s * 1.25); ctx.lineTo(x - s * 1.25, y); ctx.closePath(); }
    else if (sev === "high") { ctx.moveTo(x, y - s * 1.1); ctx.lineTo(x + s * 1.1, y + s * 0.9); ctx.lineTo(x - s * 1.1, y + s * 0.9); ctx.closePath(); }
    else if (sev === "medium") { ctx.rect(x - s * 0.85, y - s * 0.85, s * 1.7, s * 1.7); }
    else { ctx.arc(x, y, s * (sev === "low" ? 0.85 : 0.7), 0, 6.283); }
  }
  function tag(ctx, x, y, a, b, edge) {
    ctx.font = "600 11px " + FONT; var w1 = ctx.measureText(a).width;
    ctx.font = "10.5px " + FONT; var w2 = b ? ctx.measureText(b).width : 0, w = Math.max(w1, w2) + 12, h = b ? 29 : 17;
    ctx.fillStyle = C.ink; ctx.fillRect(x - w / 2, y - h, w, h);
    if (edge) { ctx.strokeStyle = edge; ctx.lineWidth = 1; ctx.strokeRect(x - w / 2 + 0.5, y - h + 0.5, w - 1, h - 1); }
    ctx.textAlign = "center"; ctx.fillStyle = C.text; ctx.font = "600 11px " + FONT; ctx.fillText(a, x, y - h + 12);
    if (b) { ctx.fillStyle = C.dim; ctx.font = "10.5px " + FONT; ctx.fillText(b, x, y - 5); }
    ctx.textAlign = "left";
  }
  function arc(m, t, toX, toZ, out) { // castle keep <-> a point, as a high curve
    var ax = m.X(0), ay = m.Z(-12), bx = m.X(toX), by = m.Z(toZ), mx = (ax + bx) / 2, my = Math.min(ay, by) - 46, u = 1 - t;
    out.x = u * u * ax + 2 * u * t * mx + t * t * bx; out.y = u * u * ay + 2 * u * t * my + t * t * by;
  }
  var Q = { x: 0, y: 0 }, Q2 = { x: 0, y: 0 };

  Map2D.prototype.draw = function () {
    var ctx = this.ctx, wd = this.world, m = this, t = this.time, u = this.u, i, k, f, s, x, y;
    ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.drawImage(this.back, 0, 0); ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    this.hits.length = 0;
    var R = Math.max(5, Math.min(9, 1.0 * u * 0.9 + 3));
    // ---- the dungeon: cells and wards
    var d = P.dungeon, st = wd.selftest, n = wd.jobOrder.length;
    ctx.lineWidth = 2; ctx.setLineDash(st ? [] : [5, 5]);
    ctx.strokeStyle = !st ? "#3a4566" : st.passed ? "#59e0ff" : (Math.sin(t * 10) > 0 ? C.bad : "#5a1f1f");
    ctx.strokeRect(m.X(d[0] - 1.2), m.Z(d[1] - 1.2), (d[2] + 2.4) * m.sx, (d[3] + 2.4) * m.sz); ctx.setLineDash([]);
    for (i = 0; i < 5; i++) {
      var job = null;
      for (k = n - 1; k >= 0; k--) { if (k % 5 === i) { job = wd.jobs[wd.jobOrder[k]]; break; } }
      x = m.X(d[0] + 1.4 + i * 3.4); y = m.Z(d[1] + 1.4);
      ctx.fillStyle = !job ? "#1d2230" : job.state === "running" ? C.vm : job.state === "done" ? C.ok : C.bad;
      ctx.globalAlpha = job && job.state === "running" ? 0.7 + 0.3 * Math.sin(t * 9) : job ? 0.55 : 1;
      ctx.fillRect(x, y, 2.8 * m.sx, 4 * m.sz); ctx.globalAlpha = 1;
      ctx.strokeStyle = C.stone; ctx.lineWidth = 1; ctx.strokeRect(x + 0.5, y + 0.5, 2.8 * m.sx - 1, 4 * m.sz - 1);
    }
    this.hits.push({ x: m.X(d[0]), y: m.Z(d[1]), w: d[2] * m.sx, h: d[3] * m.sz, pick: { kind: "vm" } });
    place(ctx, m.X(d[0] + d[2] / 2), m.Z(d[1]) - 22, "The dungeon", this.small ? "" : "sandbox VM · " + ((wd.topology.vm || {}).host || "not set up") + (wd.kind === "scan" ? " · scans never enter" : ""));
    // ---- the tower and its oracles
    var tx = m.X(P.tower[0]), ty = m.Z(P.tower[1]), busyAny = wd.llmInflight > 0;
    ctx.beginPath(); ctx.arc(tx, ty, 2.9 * u, t * (busyAny ? 2 : 0.3), t * (busyAny ? 2 : 0.3) + 4.6); ctx.strokeStyle = "#cdbdff"; ctx.lineWidth = 2; ctx.stroke();
    this.hits.push({ x: tx - 4.6 * u, y: ty - 4.6 * u, w: 9.2 * u, h: 9.2 * u, pick: { kind: "llm" } });
    place(ctx, tx, ty - 6.5 * u - 20, "Oracle tower", this.small ? "" : "LLM gateway · " + ((wd.topology.llm || {}).host || "not set up"));
    for (i = 0; i < wd.modelOrder.length; i++) {
      var md = wd.models[wd.modelOrder[i]], ox = tx + (i % 2 ? -1 : 1) * (3.2 * u + 10) * (1 + Math.floor(i / 2) * 0.6), oy = ty + 6.2 * u + Math.floor(i / 2) * 12, busy = md.inflight > 0, or = md.role === "fallback" ? R * 0.8 : R;
      if (busy) { ctx.beginPath(); ctx.arc(ox, oy, or + 4 + 2 * Math.sin(t * 7), 0, 6.283); ctx.strokeStyle = C.reply; ctx.lineWidth = 2; ctx.stroke(); }
      ctx.beginPath(); ctx.arc(ox, oy, or, 0, 6.283); ctx.fillStyle = md.role === "fallback" ? "#7b9cff" : C.llm; ctx.fill(); ctx.strokeStyle = "#fff"; ctx.lineWidth = 1; ctx.stroke();
      if (!this.small || busy) { tag(ctx, ox + (i % 2 ? -34 : 34), oy + or + 33 + i * 31, md.name.length > 22 ? md.name.slice(0, 21) + "…" : md.name, (md.role === "fallback" ? "fallback · " : "") + (busy ? "answering" : md.calls + (md.calls === 1 ? " call" : " calls")) + (md.failed ? " · " + md.failed + " lost" : ""), md.failed ? "rgba(255,110,110,0.7)" : "rgba(182,156,255,0.5)"); }
      this.hits.push({ x: ox - 14, y: oy - 14, w: 28, h: 28, pick: { kind: "model", key: md.id } });
    }
    // ---- the castle: the beacon tells how the run ended
    var bx = m.X(0), by = m.Z(-12), bc = wd.ended ? (wd.exitCode === 0 ? C.ok : C.bad) : C.amber;
    ctx.beginPath(); ctx.arc(bx, by, (wd.ended ? 4.5 : 2.6) * u + (wd.ended ? 0 : Math.sin(t * 3) * 1.5), 0, 6.283); ctx.fillStyle = bc; ctx.globalAlpha = 0.28; ctx.fill(); ctx.globalAlpha = 1;
    ctx.beginPath(); ctx.arc(bx, by, 1.5 * u, 0, 6.283); ctx.fillStyle = bc; ctx.fill();
    ctx.save(); ctx.translate(m.X(0), m.Z(0)); ctx.rotate(Math.PI / 4); ctx.fillStyle = C.gold; ctx.fillRect(-0.9 * u, -0.9 * u, 1.8 * u, 1.8 * u); ctx.restore();
    this.hits.push({ x: m.X(-10.5), y: m.Z(-16), w: 21 * m.sx, h: 27 * m.sz, pick: { kind: "core" } });
    place(ctx, bx, m.Z(-16) - 22, "CodeSift castle", !wd.kind ? "this machine · waiting for a run" : wd.ended ? wd.kind + " finished · exit " + wd.exitCode : wd.kind + " · " + wd.project);
    place(ctx, m.X(P.wilds[0]), m.Z(P.wilds[1] + P.wilds[3]) + 22, "The wilds", this.small ? "" : "your project · findings rise here");
    // ---- skeletons: one shape per finding; the rest of a horde is counted
    var moving = false, over = null, duel = wd.duel ? wd.byId[wd.duel] : null, duelSlot = null;
    for (i = 0; i < wd.findings.length; i++) {
      f = wd.findings[i];
      s = (f.index < MAX_BODIES || f.backend || wd.duel === f.id) ? this.slot(f) : null;
      if (!s) { over = over || {}; over[f.severity] = (over[f.severity] || 0) + 1; continue; }
      x = m.X(s[0]); y = m.Z(s[1]);
      var fate = W.fate(f), col = W.SEV_COLORS[f.severity] || C.grey, sz = R * (f.severity === "critical" ? 1.15 : f.severity === "info" ? 0.8 : 1);
      if (duel === f && !f.outcome) { duelSlot = s; ctx.beginPath(); ctx.arc(x, y, sz + 6 + 2 * Math.sin(t * 6), 0, 6.283); ctx.strokeStyle = C.gold; ctx.lineWidth = 2; ctx.stroke(); }
      if (fate === "fog") { ctx.beginPath(); ctx.arc(x, y, sz + 7, 0, 6.283); ctx.fillStyle = "rgba(185,194,207,0.35)"; ctx.fill(); }
      shape(ctx, f.severity, x, y, sz);
      if (fate === "slain") { ctx.fillStyle = "#26302c"; ctx.fill(); ctx.strokeStyle = "#4d6156"; ctx.lineWidth = 1.5; ctx.stroke(); ctx.beginPath(); ctx.moveTo(x - sz * 0.6, y - sz * 0.6); ctx.lineTo(x + sz * 0.6, y + sz * 0.6); ctx.moveTo(x + sz * 0.6, y - sz * 0.6); ctx.lineTo(x - sz * 0.6, y + sz * 0.6); ctx.stroke(); }
      else if (f.severity === "info") { ctx.strokeStyle = col; ctx.lineWidth = 2.5; ctx.globalAlpha = fate === "wounded" ? 0.5 : 1; ctx.stroke(); ctx.globalAlpha = 1; }
      else { ctx.globalAlpha = fate === "wounded" ? 0.45 : 1; ctx.fillStyle = col; ctx.fill(); ctx.globalAlpha = 1; ctx.strokeStyle = "#0a0d16"; ctx.lineWidth = 1; ctx.stroke(); }
      this.hits.push({ x: x - 11, y: y - 11, w: 22, h: 22, pick: { kind: "finding", key: f.id } });
    }
    if (over) { x = m.X(P.wilds[0] - 12); y = m.Z(P.wilds[1] + P.wilds[3]) + 6; for (i = 0; i < W.SEVERITIES.length; i++) { k = W.SEVERITIES[i]; if (over[k]) { shape(ctx, k, x, y, 5); ctx.fillStyle = W.SEV_COLORS[k]; ctx.fill(); ctx.fillStyle = C.text; ctx.font = "600 11px " + FONT; ctx.fillText("+" + over[k], x + 9, y + 4); x += 22 + ctx.measureText("+" + over[k]).width; } } }
    // ---- heroes (scanners) and champions (fix backends)
    for (i = 0; i < wd.scannerOrder.length; i++) {
      var name = wd.scannerOrder[i], sc = wd.scanners[name], wk = this.walker("s:" + name, false);
      wk.want = sc.status === "running" ? 1 : 0;
      if (wk.step(this.dt, this.snap)) { moving = true; }
      x = m.X(wk.x); y = m.Z(wk.z);
      var hc = sc.status === "running" ? C.scan : sc.status === "error" ? C.bad : sc.status === "skipped" ? "#59607a" : "#d9dceb";
      if (sc.status === "running" && wk.at === 1) { var ph = (t * 0.7 + i * 0.3) % 1; ctx.beginPath(); ctx.arc(x, y, R + ph * 16, 0, 6.283); ctx.strokeStyle = C.scan; ctx.globalAlpha = 1 - ph; ctx.lineWidth = 2; ctx.stroke(); ctx.globalAlpha = 1; }
      ctx.beginPath(); ctx.arc(x, y, R * 0.82, 0, 6.283); ctx.fillStyle = hc; ctx.fill(); ctx.strokeStyle = "#0a0d16"; ctx.lineWidth = 1.2; ctx.stroke();
      ctx.fillStyle = "#0a0d16"; ctx.font = "700 " + Math.round(R * 1.05) + "px " + FONT; ctx.textAlign = "center"; ctx.fillText(sc.cls.charAt(0), x, y + R * 0.36); ctx.textAlign = "left";
      if (wk.at > 0.02) { tag(ctx, x, y - R - 4, name, this.small ? "" : sc.status === "running" ? sc.cls + " · searching" : sc.cls + " · " + sc.findings + " found"); }
      this.hits.push({ x: x - 11, y: y - 11, w: 22, h: 22, pick: { kind: "scanner", key: name } });
    }
    for (k in wd.backends) {
      var cw = this.walker("b:" + k, true), fighting = duel && duel.backend === k && !duel.outcome && duelSlot;
      if (fighting) { var goal = duel.id; if (cw.goal !== goal) { cw.goal = goal; cw.route([duelSlot[0] - 1.6, duelSlot[1] - 1.6]); } }
      cw.want = fighting ? 1 : 0;
      if (cw.step(this.dt, this.snap)) { moving = true; }
      x = m.X(cw.x); y = m.Z(cw.z);
      ctx.beginPath(); ctx.arc(x, y, R * 0.95, 0, 6.283); ctx.fillStyle = "#f4eedd"; ctx.fill(); ctx.strokeStyle = C.gold; ctx.lineWidth = 2.5; ctx.stroke();
      ctx.strokeStyle = "#0a0d16"; ctx.lineWidth = 1.6; ctx.beginPath(); ctx.moveTo(x - R * 0.45, y + R * 0.45); ctx.lineTo(x + R * 0.45, y - R * 0.45); ctx.moveTo(x - R * 0.1, y - R * 0.45); ctx.lineTo(x + R * 0.45, y + R * 0.1); ctx.stroke(); // a sword
      if (cw.at > 0.02) { tag(ctx, x - (fighting && cw.at === 1 ? 26 : 0), y + R + (fighting && cw.at === 1 ? 36 : -5 - R * 2) + R, k, fighting ? duel.stage + " " + duel.id : "champion", "rgba(255,211,110,0.75)"); }
      this.hits.push({ x: x - 12, y: y - 12, w: 24, h: 24, pick: { kind: "backend", key: k } });
    }
    this.snap = false;
    // ---- ravens (LLM calls), runes (VM commands), rings (results)
    for (i = 0; i < this.birds.length; i++) {
      var b = this.birds[i], idx = Math.max(0, wd.modelOrder.indexOf(b.model)), tw = b.back ? 1 - b.t : b.t;
      if (b.fail && b.t > 0.46) { arc(m, 1 - 0.46, P.tower[0], P.tower[1], Q); Q.y += (b.t - 0.46) * (b.t - 0.46) * 520; ctx.globalAlpha = Math.max(0, 1 - (b.t - 0.46) * 2.2); }
      else { arc(m, tw, P.tower[0] + (idx % 2 ? -1 : 1), P.tower[1], Q); }
      arc(m, Math.max(0, Math.min(1, tw + (b.back ? 0.03 : -0.03))), P.tower[0], P.tower[1], Q2);
      var flap = Math.sin(t * 16) * 4 * b.size, wing = 7 * b.size, dead = b.fail && b.t > 0.46;
      ctx.beginPath(); ctx.arc(Q.x, Q.y, 3.4 * b.size, 0, 6.283); ctx.fillStyle = dead ? C.grey : b.color; ctx.fill();
      ctx.beginPath(); ctx.moveTo(Q.x - wing, Q.y - flap); ctx.lineTo(Q.x, Q.y); ctx.lineTo(Q.x + wing, Q.y - flap); ctx.strokeStyle = dead ? C.grey : "#f4eedd"; ctx.lineWidth = 2; ctx.stroke();
      ctx.globalAlpha = 1;
    }
    for (i = 0; i < this.runes.length; i++) {
      var rn = this.runes[i], rt = rn.back ? 1 - rn.t : rn.t, segs = ROAD_DUNGEON.length, fp = rt * (segs - 1), si = Math.min(segs - 2, Math.floor(fp)), fr = fp - si;
      x = m.X(ROAD_DUNGEON[si][0] + (ROAD_DUNGEON[si + 1][0] - ROAD_DUNGEON[si][0]) * fr); y = m.Z(ROAD_DUNGEON[si][1] + (ROAD_DUNGEON[si + 1][1] - ROAD_DUNGEON[si][1]) * fr);
      ctx.beginPath(); ctx.arc(x, y, 7, 0, 6.283); ctx.fillStyle = rn.color; ctx.globalAlpha = 0.3; ctx.fill(); ctx.globalAlpha = 1;
      ctx.save(); ctx.translate(x, y); ctx.rotate(t * 4); ctx.fillStyle = rn.color; ctx.fillRect(-3.5, -3.5, 7, 7); ctx.restore();
    }
    for (i = 0; i < this.rings.length; i++) {
      var rg = this.rings[i];
      ctx.beginPath(); ctx.arc(m.X(rg.x), m.Z(rg.z), 6 + rg.t * 26 * rg.big, 0, 6.283); ctx.strokeStyle = rg.color; ctx.globalAlpha = Math.max(0, 1 - rg.t); ctx.lineWidth = 2.5; ctx.stroke(); ctx.globalAlpha = 1;
    }
    if (duel && duelSlot && !duel.outcome) { tag(ctx, m.X(duelSlot[0]) + 14, m.Z(duelSlot[1]) - R - 8, duel.id + " · " + duel.severity, duel.monster + " · " + duel.stage, "#ff6e6e"); }
    this.moving = moving;
  };

  Map2D.prototype.loop = function () {
    var self = this;
    var frame = function (now) {
      if (self.disposed) { return; }
      var raw = Math.min(0.25, (now - self.last) / 1000), i;
      self.last = now; self.dt = 0;
      if (!self.paused && !document.hidden) {
        var dt = raw * self.speed;
        self.time += dt; self.dt = dt;
        self.pacer.step(dt);
        for (i = self.birds.length - 1; i >= 0; i--) { self.birds[i].t += dt / 1.9; if (self.birds[i].t >= 1) { self.birds.splice(i, 1); } }
        for (i = self.runes.length - 1; i >= 0; i--) { self.runes[i].t += dt / 1.2; if (self.runes[i].t >= 1) { self.runes.splice(i, 1); } }
        for (i = self.rings.length - 1; i >= 0; i--) { self.rings[i].t += dt * 1.1; if (self.rings[i].t >= 1) { self.rings.splice(i, 1); } }
      }
      if (!document.hidden) { self.draw(); }
      // busy: smooth frames. idle: four frames a second keep the pulses alive at almost no cost
      var busy = self.birds.length || self.runes.length || self.rings.length || self.pacer.queue.length || self.moving;
      if (busy && !self.reduced) { self.timer = requestAnimationFrame(frame); }
      else { self.timeout = setTimeout(function () { self.timer = requestAnimationFrame(frame); }, busy ? 60 : 250); }
    };
    this.timer = requestAnimationFrame(frame);
  };

  Map2D.prototype.pick = function (e) {
    var r = this.canvas.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    for (var i = this.hits.length - 1; i >= 0; i--) {
      var h = this.hits[i];
      if (x >= h.x && x <= h.x + h.w && y >= h.y && y <= h.y + h.h) {
        if (this.selectCb) { this.selectCb(h.pick, this.world.info(h.pick)); }
        return;
      }
    }
    if (this.selectCb) { this.selectCb(null, []); }
  };

  Map2D.prototype.info = function (pick) { return this.world.info(pick); };
  Map2D.prototype.describe = function () { return this.world.describe("2D map. Click a place, a hero or a skeleton for details"); };
  Map2D.prototype.onSelect = function (cb) { this.selectCb = cb; };
  Map2D.prototype.setPaused = function (p) { this.paused = p; };
  Map2D.prototype.setSpeed = function (s) { this.speed = s; };
  Map2D.prototype.dispose = function () {
    this.disposed = true;
    cancelAnimationFrame(this.timer); clearTimeout(this.timeout);
    window.removeEventListener("resize", this.onResize);
    this.canvas.removeEventListener("click", this.onClick);
    if (this.canvas.parentNode) { this.canvas.parentNode.removeChild(this.canvas); }
  };

  window.SiftMap2D = {
    available: function () { var c = document.createElement("canvas"); return !!(c.getContext && c.getContext("2d")); },
    create: function (el) { return new Map2D(el); }
  };
})();
