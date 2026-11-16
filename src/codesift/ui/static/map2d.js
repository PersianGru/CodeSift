/* CodeSift UI: the light 2D system map. Plain canvas, no WebGL and no three.js, so it suits old
   laptops and low memory. It draws window.SiftWorld; every moving dot is one real event. */
(function () {
  "use strict";

  var W = window.SiftWorld;
  var COLORS = {
    bg: "#0b0e14", zone: "#121722", zoneEdge: "#243048", text: "#d6dce8", dim: "#6e7687", gold: "#ffc457",
    scan: "#78e6c8", llm: "#aa8cff", reply: "#ffd36e", vm: "#5abeff", fail: "#ff5c5c", ok: "#5ed68c"
  };
  var KIND = { scan: COLORS.scan, llm: COLORS.llm, reply: COLORS.reply, vm: COLORS.vm, fail: COLORS.fail };
  var FONT = "system-ui, -apple-system, Segoe UI, sans-serif";

  function Map2D(container) {
    this.el = container;
    this.world = W.create();
    this.canvas = document.createElement("canvas");
    this.canvas.tabIndex = 0;
    this.canvas.className = "map2d";
    container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext("2d");
    this.packets = []; this.flashes = []; this.nodes = {}; this.hits = [];
    this.time = 0; this.speed = 1; this.paused = false; this.last = performance.now();
    this.reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var self = this;
    this.pacer = new W.Pacer(this.world, function (fx, animate) { if (animate) { self.effects(fx); } });
    this.onResize = function () { self.resize(); };
    window.addEventListener("resize", this.onResize);
    this.canvas.addEventListener("click", function (e) { self.pick(e); });
    this.resize();
    this.loop();
  }

  Map2D.prototype.resize = function () {
    var r = this.el.getBoundingClientRect();
    var dpr = Math.min(2, window.devicePixelRatio || 1);
    this.w = Math.max(320, r.width); this.h = Math.max(240, r.height);
    this.canvas.width = Math.round(this.w * dpr); this.canvas.height = Math.round(this.h * dpr);
    this.canvas.style.width = this.w + "px"; this.canvas.style.height = this.h + "px";
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };

  Map2D.prototype.handle = function (ev) { this.pacer.push(ev); };

  Map2D.prototype.effects = function (fx) {
    var self = this;
    fx.forEach(function (e) {
      if (e.from && e.to) {
        var n = e.count || 1;
        for (var i = 0; i < n; i++) {
          self.packets.push({ from: e.from, to: e.to, color: KIND[e.kind] || COLORS.gold, t: -i * 0.12, size: 3 + (e.size || 0) * 4 });
        }
      }
      if (e.kind === "finding") { self.flashes.push({ at: "core", color: W.SEV_COLORS[e.finding.severity] || COLORS.dim, t: 0 }); }
      if (e.kind === "end") { self.flashes.push({ at: "core", color: e.ok ? COLORS.ok : COLORS.fail, t: 0, big: true }); }
    });
  };

  // -------------------------------------------------------------- layout

  Map2D.prototype.layout = function () {
    var w = this.w, h = this.h, wd = this.world, nodes = {};
    var narrow = w < 760;
    var pad = 16;
    var local = narrow ? { x: pad, y: pad, w: w - 2 * pad, h: h * 0.52 - pad * 1.5 } : { x: pad, y: pad, w: w * 0.5 - pad * 1.5, h: h - 2 * pad };
    var llm = narrow ? { x: pad, y: h * 0.52 + pad * 0.5, w: (w - 3 * pad) / 2, h: h * 0.48 - pad * 1.5 }
      : { x: w * 0.5 + pad * 0.5, y: pad, w: w * 0.5 - pad * 1.5, h: h * 0.5 - pad * 1.5 };
    var vm = narrow ? { x: llm.x + llm.w + pad, y: llm.y, w: llm.w, h: llm.h }
      : { x: llm.x, y: h * 0.5 + pad * 0.5, w: llm.w, h: llm.h };
    this.zones = [
      { box: local, title: "This machine", sub: "CodeSift + scanners", pick: { kind: "core" } },
      { box: llm, title: "LLM gateway", sub: (wd.topology.llm || {}).host || "not set up", pick: { kind: "llm" } },
      { box: vm, title: "Sandbox VM", sub: (wd.topology.vm || {}).host ? (wd.topology.vm.host + " · " + (wd.topology.vm.runtime || "")) : "not set up", pick: { kind: "vm" } }
    ];
    nodes.core = { x: local.x + local.w / 2, y: local.y + Math.min(92, local.h * 0.26), r: 24, pick: { kind: "core" } };
    var names = wd.scannerOrder, cols = local.w > 420 ? 3 : 2;
    var top = nodes.core.y + 104, rowH = Math.min(78, (local.y + local.h - top - 40) / Math.max(1, Math.ceil(names.length / cols)));
    names.forEach(function (n, i) {
      var c = i % cols, r = Math.floor(i / cols);
      nodes["scanner:" + n] = { x: local.x + local.w * (c + 0.5) / cols, y: top + r * rowH + rowH / 2, r: 9, pick: { kind: "scanner", key: n } };
    });
    var ids = wd.modelOrder;
    ids.forEach(function (id, i) {
      nodes["model:" + id] = { x: llm.x + llm.w * (i + 0.5) / ids.length, y: llm.y + llm.h * 0.58, r: 16, pick: { kind: "model", key: id } };
    });
    nodes.vm = { x: vm.x + vm.w * 0.18, y: vm.y + vm.h * 0.52, r: 18, pick: { kind: "vm" } };
    var jobs = wd.jobOrder.slice(-12);
    jobs.forEach(function (id, i) {
      var c = i % 4, r = Math.floor(i / 4);
      nodes["job:" + id] = { x: vm.x + vm.w * (0.36 + c * 0.1), y: vm.y + vm.h * (0.36 + r * 0.17), r: 7, pick: { kind: "vm" } };
    });
    this.nodes = nodes;
    this.findingRow = { x: local.x + local.w * 0.18, y: nodes.core.y + 66, w: local.w * 0.64 };
  };

  // -------------------------------------------------------------- drawing

  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }

  function curve(a, b) {
    var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - Math.abs(a.x - b.x) * 0.12 - 10;
    return function (t) { var u = 1 - t; return { x: u * u * a.x + 2 * u * t * mx + t * t * b.x, y: u * u * a.y + 2 * u * t * my + t * t * b.y }; };
  }

  Map2D.prototype.draw = function () {
    var ctx = this.ctx, wd = this.world, self = this, t = this.time;
    this.layout();
    ctx.fillStyle = COLORS.bg; ctx.fillRect(0, 0, this.w, this.h);
    this.hits = [];
    this.zones.forEach(function (z) {
      var b = z.box;
      roundRect(ctx, b.x, b.y, b.w, b.h, 12);
      ctx.fillStyle = COLORS.zone; ctx.fill();
      ctx.strokeStyle = COLORS.zoneEdge; ctx.lineWidth = 1; ctx.stroke();
      ctx.fillStyle = COLORS.text; ctx.font = "600 14px " + FONT; ctx.fillText(z.title, b.x + 14, b.y + 24);
      ctx.fillStyle = COLORS.dim; ctx.font = "12px " + FONT; ctx.fillText(z.sub, b.x + 14, b.y + 42);
      self.hits.push({ x: b.x, y: b.y, w: b.w, h: 48, pick: z.pick });
    });
    var core = this.nodes.core;
    // links
    Object.keys(this.nodes).forEach(function (k) {
      if (k === "core" || k.indexOf("job:") === 0) { return; }
      var n = self.nodes[k], c = curve(core, n);
      ctx.beginPath();
      for (var i = 0; i <= 24; i++) { var p = c(i / 24); if (i) { ctx.lineTo(p.x, p.y); } else { ctx.moveTo(p.x, p.y); } }
      ctx.strokeStyle = "rgba(120,140,180,0.18)"; ctx.lineWidth = 1; ctx.stroke();
    });
    // scanners
    wd.scannerOrder.forEach(function (name) {
      var s = wd.scanners[name], n = self.nodes["scanner:" + name];
      var col = s.status === "running" ? COLORS.gold : s.status === "ok" ? COLORS.scan : s.status === "error" ? COLORS.fail : COLORS.dim;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + (s.status === "running" ? 2 * Math.sin(t * 8) + 2 : 0), 0, Math.PI * 2);
      ctx.fillStyle = s.status === "skipped" || s.status === "ready" ? "#1b2130" : col; ctx.fill();
      ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.stroke();
      ctx.fillStyle = s.status === "skipped" ? COLORS.dim : COLORS.text; ctx.font = "12px " + FONT; ctx.textAlign = "left";
      ctx.fillText(name, n.x + 15, n.y - 1);
      ctx.fillStyle = COLORS.dim; ctx.font = "11px " + FONT;
      ctx.fillText(s.status === "ok" ? s.findings + " found · " + W.fmtS(s.duration) : s.status === "running" ? "scanning" : s.status, n.x + 15, n.y + 13);
      self.hits.push({ x: n.x - 12, y: n.y - 14, w: 120, h: 30, pick: n.pick });
    });
    // models
    wd.modelOrder.forEach(function (id) {
      var m = wd.models[id], n = self.nodes["model:" + id];
      var busy = m.inflight > 0;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      var g = ctx.createRadialGradient(n.x - 5, n.y - 5, 2, n.x, n.y, n.r);
      g.addColorStop(0, busy ? "#fff3c4" : "#d9ccff"); g.addColorStop(1, busy ? COLORS.reply : COLORS.llm);
      ctx.fillStyle = g; ctx.fill();
      if (busy) { ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 5 + 3 * Math.sin(t * 6), 0, Math.PI * 2); ctx.strokeStyle = "rgba(255,211,110,0.5)"; ctx.lineWidth = 2; ctx.stroke(); }
      ctx.textAlign = "center"; ctx.fillStyle = COLORS.text; ctx.font = "12px " + FONT;
      ctx.fillText(m.name.length > 26 ? m.name.slice(0, 25) + "…" : m.name, n.x, n.y + n.r + 18);
      ctx.fillStyle = COLORS.dim; ctx.font = "11px " + FONT;
      ctx.fillText((m.role === "fallback" ? "fallback · " : "") + m.calls + " calls · " + W.fmtTokens(m.tokensIn + m.tokensOut) + " tok", n.x, n.y + n.r + 33);
      ctx.textAlign = "left";
      self.hits.push({ x: n.x - 60, y: n.y - n.r, w: 120, h: n.r * 2 + 40, pick: n.pick });
    });
    // vm host + jobs
    var vmn = this.nodes.vm, busyVm = wd.vm.inflight > 0;
    roundRect(ctx, vmn.x - 20, vmn.y - 26, 40, 52, 6);
    ctx.fillStyle = "#1a2232"; ctx.fill(); ctx.strokeStyle = busyVm ? COLORS.vm : COLORS.zoneEdge; ctx.lineWidth = 2; ctx.stroke();
    for (var k = 0; k < 4; k++) {
      ctx.fillStyle = busyVm && Math.sin(t * 20 + k * 2) > 0 ? COLORS.ok : "#2a2e35";
      ctx.fillRect(vmn.x - 12, vmn.y - 18 + k * 11, 6, 4);
    }
    self.hits.push({ x: vmn.x - 20, y: vmn.y - 26, w: 40, h: 52, pick: vmn.pick });
    ctx.fillStyle = COLORS.dim; ctx.font = "11px " + FONT; ctx.textAlign = "center";
    ctx.fillText(wd.vm.jobs + " jobs · " + wd.vm.commands + " cmds" + (wd.vm.failed ? " · " + wd.vm.failed + " failed" : ""), vmn.x, vmn.y + 44);
    ctx.textAlign = "left";
    wd.jobOrder.slice(-12).forEach(function (id) {
      var j = wd.jobs[id], n = self.nodes["job:" + id];
      roundRect(ctx, n.x - 9, n.y - 9, 18, 18, 4);
      ctx.fillStyle = j.state === "running" ? COLORS.vm : j.state === "done" ? "rgba(94,214,140,0.35)" : "rgba(255,92,92,0.45)";
      ctx.fill();
    });
    if (wd.kind === "scan") { ctx.fillStyle = COLORS.dim; ctx.font = "11px " + FONT; ctx.fillText("scans never use the VM", this.zones[2].box.x + 14, this.zones[2].box.y + this.zones[2].box.h - 14); }
    // core
    var pulse = wd.ended ? 0 : 0.5 + 0.5 * Math.sin(t * 3);
    ctx.beginPath(); ctx.arc(core.x, core.y, core.r + 6 + pulse * 4, 0, Math.PI * 2); ctx.fillStyle = "rgba(255,196,87,0.12)"; ctx.fill();
    ctx.beginPath(); ctx.arc(core.x, core.y, core.r, 0, Math.PI * 2);
    var cg = ctx.createRadialGradient(core.x - 6, core.y - 6, 3, core.x, core.y, core.r);
    cg.addColorStop(0, "#fff0c2"); cg.addColorStop(1, COLORS.gold); ctx.fillStyle = cg; ctx.fill();
    ctx.textAlign = "center"; ctx.fillStyle = COLORS.text; ctx.font = "600 13px " + FONT;
    ctx.fillText("CodeSift", core.x, core.y + core.r + 18);
    ctx.fillStyle = COLORS.dim; ctx.font = "11px " + FONT;
    ctx.fillText(wd.ended ? (wd.kind + " finished · exit " + wd.exitCode) : wd.kind ? (wd.kind + " · " + wd.project) : "waiting for a run", core.x, core.y + core.r + 33);
    ctx.textAlign = "left";
    this.hits.push({ x: core.x - core.r, y: core.y - core.r, w: core.r * 2, h: core.r * 2, pick: core.pick });
    // findings strip
    var fr = this.findingRow, size = 14, gap = 4, fit = Math.max(1, Math.floor(fr.w / (size + gap)) - 1);
    var shown = Math.min(fit, wd.findings.length);
    fr = { x: fr.x + (fr.w - shown * (size + gap)) / 2, y: fr.y, w: fr.w };
    wd.findings.slice(0, fit).forEach(function (f, i) {
      var x = fr.x + i * (size + gap);
      ctx.save(); ctx.translate(x + size / 2, fr.y + size / 2); ctx.rotate(Math.PI / 4);
      ctx.fillStyle = f.outcome && f.outcome.indexOf("fixed") === 0 ? "#2a3a30" : (W.SEV_COLORS[f.severity] || COLORS.dim);
      ctx.fillRect(-size / 2.8, -size / 2.8, size / 1.4, size / 1.4); ctx.restore();
      self.hits.push({ x: x, y: fr.y, w: size, h: size, pick: { kind: "finding", key: f.id } });
    });
    if (wd.findings.length > fit) { ctx.fillStyle = COLORS.dim; ctx.font = "11px " + FONT; ctx.fillText("+" + (wd.findings.length - fit), fr.x + fit * (size + gap), fr.y + 11); }
    if (!wd.findings.length) { ctx.fillStyle = COLORS.dim; ctx.font = "11px " + FONT; ctx.textAlign = "center"; ctx.fillText("no findings yet", core.x, fr.y + 11); ctx.textAlign = "left"; }
    // packets
    this.packets.forEach(function (p) {
      if (p.t < 0) { return; }
      var a = self.nodes[p.from], b = self.nodes[p.to];
      if (!a || !b) { p.t = 2; return; }
      var c = curve(a, b);
      for (var i = 4; i >= 0; i--) {
        var q = c(Math.max(0, Math.min(1, p.t - i * 0.025)));
        ctx.beginPath(); ctx.arc(q.x, q.y, p.size * (1 - i * 0.16), 0, Math.PI * 2);
        ctx.globalAlpha = 1 - i * 0.2; ctx.fillStyle = p.color; ctx.fill();
      }
      ctx.globalAlpha = 1;
    });
    this.flashes.forEach(function (f) {
      var n = self.nodes[f.at]; if (!n) { return; }
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + f.t * (f.big ? 160 : 60), 0, Math.PI * 2);
      ctx.strokeStyle = f.color; ctx.globalAlpha = Math.max(0, 1 - f.t); ctx.lineWidth = 2; ctx.stroke(); ctx.globalAlpha = 1;
    });
  };

  Map2D.prototype.loop = function () {
    var self = this;
    var frame = function (now) {
      if (self.disposed) { return; }
      var raw = Math.min(0.1, (now - self.last) / 1000);
      self.last = now;
      var busy = self.packets.length || self.flashes.length || self.pacer.queue.length;
      if (!self.paused) {
        var dt = raw * self.speed;
        self.time += dt;
        self.pacer.step(dt);
        self.packets.forEach(function (p) { p.t += dt * 1.1; });
        self.packets = self.packets.filter(function (p) { return p.t <= 1; });
        self.flashes.forEach(function (f) { f.t += dt * 1.2; });
        self.flashes = self.flashes.filter(function (f) { return f.t < 1; });
      }
      self.draw();
      // busy: smooth frames; idle: a few frames a second, enough for the pulses and almost no CPU
      if (busy || self.reduced) { self.timer = requestAnimationFrame(frame); } else { self.timeout = setTimeout(function () { self.timer = requestAnimationFrame(frame); }, 200); }
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
  };

  Map2D.prototype.info = function (pick) { return this.world.info(pick); };
  Map2D.prototype.describe = function () { return this.world.describe("2D system map"); };
  Map2D.prototype.onSelect = function (cb) { this.selectCb = cb; };
  Map2D.prototype.setPaused = function (p) { this.paused = p; };
  Map2D.prototype.setSpeed = function (s) { this.speed = s; };
  Map2D.prototype.dispose = function () {
    this.disposed = true;
    cancelAnimationFrame(this.timer); clearTimeout(this.timeout);
    window.removeEventListener("resize", this.onResize);
    if (this.canvas.parentNode) { this.canvas.parentNode.removeChild(this.canvas); }
  };

  window.SiftMap2D = {
    available: function () { var c = document.createElement("canvas"); return !!(c.getContext && c.getContext("2d")); },
    create: function (el) { return new Map2D(el); }
  };
})();
