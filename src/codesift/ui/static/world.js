/* CodeSift UI: the run as a small world model, built only from the run's events. The 2D map and the
   3D realm both draw this model; neither invents anything. apply(ev) returns the "effects" a view
   may animate (a message travelling from one place to another), each caused by that one event. */
(function () {
  "use strict";

  var CLASSES = { gitleaks: "Rogue", opengrep: "Mage", trivy: "Ranger", bandit: "Knight", ruff: "Barbarian",
    "osv-scanner": "Scout", zizmor: "Cleric", "pip-audit": "Alchemist", "composer-audit": "Bard", govulncheck: "Monk" };
  var MONSTERS = { critical: "Skeleton Lord", high: "Skeleton Warrior", medium: "Skeleton Rogue", low: "Skeleton Minion", info: "Bones" };
  var SEVERITIES = ["critical", "high", "medium", "low", "info"];

  function fmtTokens(n) { return n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + "k" : String(n); }
  function fmtS(s) { return s >= 60 ? Math.floor(s / 60) + "m" + Math.round(s % 60) + "s" : (s || 0).toFixed(1) + "s"; }
  function short(model) { var i = (model || "").indexOf("/"); return i >= 0 ? model.slice(i + 1) : (model || ""); }

  function World() {
    this.topology = {};
    this.kind = ""; this.project = ""; this.ended = false; this.exitCode = null;
    this.scanners = {}; this.scannerOrder = [];
    this.models = {}; this.modelOrder = [];
    this.jobs = {}; this.jobOrder = [];
    this.vm = { commands: 0, jobs: 0, failed: 0, inflight: 0, last: "" };
    this.findings = []; this.byId = {};
    this.backends = {};
    this.stats = { findings: 0, scanners: 0, llmCalls: 0, llmFailed: 0, tokensIn: 0, tokensOut: 0, vmJobs: 0, vmCommands: 0 };
  }

  World.prototype.scanner = function (name) {
    if (!this.scanners[name]) {
      this.scanners[name] = { name: name, cls: CLASSES[name] || "Squire", status: "ready", findings: 0, duration: 0, reason: "", version: "", changed: 0 };
      this.scannerOrder.push(name);
    }
    return this.scanners[name];
  };

  World.prototype.model = function (id, role) {
    if (!this.models[id]) {
      this.models[id] = { id: id, name: short(id), role: role || "primary", calls: 0, failed: 0, inflight: 0, tokensIn: 0, tokensOut: 0, latency: 0, lastError: "" };
      this.modelOrder.push(id);
    }
    return this.models[id];
  };

  World.prototype.roleOf = function (model) {
    var llm = this.topology.llm || {};
    return llm.fallback && model === llm.fallback ? "fallback" : "primary";
  };

  World.prototype.apply = function (ev) {
    var d = ev.data || {}, fx = [], self = this;
    switch (ev.type) {
      case "run.start":
        this.kind = d.kind || "fix"; this.project = d.project || ""; this.mode = d.mode || "";
        this.topology = d.topology || {};
        (this.topology.scanners || []).forEach(function (n) { self.scanner(n); });
        if (this.topology.llm && this.topology.llm.model) {
          this.model(this.topology.llm.model, "primary");
          if (this.topology.llm.fallback) { this.model(this.topology.llm.fallback, "fallback"); }
        }
        fx.push({ kind: "start" });
        break;
      case "run.end":
        this.ended = true; this.exitCode = d.exit_code;
        fx.push({ kind: "end", ok: d.exit_code === 0 });
        break;
      case "scanner.start": {
        var s = this.scanner(d.name);
        s.status = "running";
        fx.push({ kind: "scan", from: "core", to: "scanner:" + d.name });
        break;
      }
      case "scanner.result": {
        var r = this.scanner(d.name);
        r.status = d.status || "ok"; r.findings = d.findings || 0; r.duration = d.duration_s || 0;
        r.version = d.version || ""; r.reason = d.reason || "";
        if (r.status !== "skipped") {
          this.stats.scanners += 1;
          fx.push({ kind: r.status === "error" ? "fail" : "scan", from: "scanner:" + d.name, to: "core", count: Math.max(1, Math.min(8, r.findings)) });
        } else {
          fx.push({ kind: "skip", at: "scanner:" + d.name });
        }
        break;
      }
      case "finding.detected": {
        if (!ev.finding) { break; }
        var f = this.byId[ev.finding];
        if (!f) { f = { id: ev.finding, outcome: "", stage: "" }; this.byId[ev.finding] = f; this.findings.push(f); }
        f.severity = d.severity || "info"; f.path = d.path || ""; f.line = d.line || 0; f.tool = d.tool || "";
        f.monster = MONSTERS[f.severity] || "Bones";
        this.stats.findings = this.findings.length;
        fx.push({ kind: "finding", finding: f, from: f.tool ? "scanner:" + f.tool : "core" });
        break;
      }
      case "llm.request": {
        var m = this.model(d.model, this.roleOf(d.model));
        m.inflight += 1;
        fx.push({ kind: "llm", from: "core", to: "model:" + d.model, size: Math.min(1, (d.prompt_chars || 0) / 12000) });
        break;
      }
      case "llm.response": {
        var mm = this.model(d.model, this.roleOf(d.model));
        mm.inflight = Math.max(0, mm.inflight - 1); mm.calls += 1;
        if (!d.ok) { mm.failed += 1; mm.lastError = d.error || "failed"; this.stats.llmFailed += 1; } else { mm.latency += d.latency_s || 0; }
        mm.tokensIn += d.tokens_in || 0; mm.tokensOut += d.tokens_out || 0;
        this.stats.llmCalls += 1; this.stats.tokensIn += d.tokens_in || 0; this.stats.tokensOut += d.tokens_out || 0;
        fx.push({ kind: d.ok ? "reply" : "fail", from: "model:" + d.model, to: "core", size: Math.min(1, (d.tokens_out || 0) / 1500) });
        break;
      }
      case "vm.command":
        this.vm.commands += 1; this.vm.inflight += 1; this.stats.vmCommands += 1;
        this.vm.last = d.op + (d.job ? " sift-" + d.job : "");
        if (d.op === "job" && d.job) {
          this.vm.jobs += 1; this.stats.vmJobs += 1;
          this.jobs[d.job] = { id: d.job, state: "running", rc: null, duration: 0 };
          this.jobOrder.push(d.job);
          fx.push({ kind: "vm", from: "core", to: "vm", job: d.job, start: true });
        } else {
          fx.push({ kind: "vm", from: "core", to: "vm" });
        }
        break;
      case "vm.result":
        this.vm.inflight = Math.max(0, this.vm.inflight - 1);
        if (d.rc !== 0) { this.vm.failed += 1; }
        if (d.op === "job" && d.job && this.jobs[d.job]) {
          var j = this.jobs[d.job];
          j.state = d.rc === 0 ? "done" : "failed"; j.rc = d.rc; j.duration = d.duration_s || 0;
          fx.push({ kind: d.rc === 0 ? "vm" : "fail", from: "vm", to: "core", job: d.job, end: true });
        } else {
          fx.push({ kind: d.rc === 0 ? "vm" : "fail", from: "vm", to: "core" });
        }
        break;
      case "stage.enter":
        if (ev.finding && this.byId[ev.finding]) { this.byId[ev.finding].stage = d.stage; }
        break;
      case "fix.attempt":
        this.backends[d.backend || "fixer"] = (this.backends[d.backend || "fixer"] || 0) + 1;
        if (ev.finding && this.byId[ev.finding]) { this.byId[ev.finding].stage = "fix"; fx.push({ kind: "attack", finding: this.byId[ev.finding] }); }
        break;
      case "finding.outcome":
        if (ev.finding && this.byId[ev.finding]) {
          var o = this.byId[ev.finding];
          o.outcome = d.outcome || ""; o.stage = "done";
          fx.push({ kind: "outcome", finding: o, won: o.outcome.indexOf("fixed") === 0 });
        }
        break;
      default:
        break;
    }
    return fx;
  };

  World.prototype.info = function (pick) {
    var lines = [];
    if (pick.kind === "scanner") {
      var s = this.scanners[pick.key];
      if (!s) { return lines; }
      lines.push(s.cls + " · scanner " + s.name + (s.version ? " " + s.version : ""));
      lines.push("Status: " + s.status + (s.reason ? " (" + s.reason + ")" : ""));
      lines.push("Findings: " + s.findings + " · time " + fmtS(s.duration));
    } else if (pick.kind === "model") {
      var m = this.models[pick.key];
      if (!m) { return lines; }
      lines.push("Oracle · model " + m.id + (m.role === "fallback" ? " (fallback)" : ""));
      lines.push("Calls: " + m.calls + (m.failed ? " (" + m.failed + " failed" + (m.lastError ? ": " + m.lastError : "") + ")" : "") + " · in flight " + m.inflight);
      lines.push("Tokens: " + fmtTokens(m.tokensIn) + " in, " + fmtTokens(m.tokensOut) + " out");
      if (m.calls - m.failed > 0) { lines.push("Average answer time: " + fmtS(m.latency / (m.calls - m.failed))); }
    } else if (pick.kind === "vm") {
      var vm = this.topology.vm || {};
      lines.push("Dungeon · sandbox VM " + (vm.host || "(not configured)"));
      if (vm.runtime) { lines.push(vm.runtime + " · image " + vm.image); }
      lines.push("Commands: " + this.vm.commands + " · jobs " + this.vm.jobs + " · failed " + this.vm.failed + (this.vm.last ? " · last: " + this.vm.last : ""));
      if (this.kind === "scan") { lines.push("A scan never uses the VM; only sift fix / validate do."); }
    } else if (pick.kind === "llm") {
      var llm = this.topology.llm || {};
      lines.push("Oracle tower · LLM gateway " + (llm.host || "(not configured)"));
      lines.push("Calls: " + this.stats.llmCalls + " · tokens " + fmtTokens(this.stats.tokensIn) + " in, " + fmtTokens(this.stats.tokensOut) + " out");
    } else if (pick.kind === "finding") {
      var f = this.byId[pick.key];
      if (!f) { return lines; }
      lines.push(f.id + " · " + f.monster + " (" + f.severity + ")");
      lines.push(f.path + (f.line ? ":" + f.line : "") + (f.tool ? " · found by " + f.tool : ""));
      if (f.outcome) { lines.push("Outcome: " + f.outcome.replace(/_/g, " ")); } else if (f.stage) { lines.push("Stage: " + f.stage); }
    } else {
      var by = {};
      this.findings.forEach(function (x) { by[x.severity] = (by[x.severity] || 0) + 1; });
      lines.push("CodeSift castle · this machine");
      lines.push("Findings: " + this.findings.length + (this.findings.length ? " (" + SEVERITIES.filter(function (k) { return by[k]; }).map(function (k) { return by[k] + " " + k; }).join(", ") + ")" : ""));
      lines.push("Scanners finished: " + this.stats.scanners);
    }
    return lines;
  };

  World.prototype.describe = function (what) {
    var s = this.stats;
    return (what || "System map") + ". " + this.scannerOrder.length + " scanner(s), " + s.findings + " finding(s), " +
      s.llmCalls + " LLM call(s), " + s.vmJobs + " sandbox job(s)" + (this.ended ? ". Run finished." : ".");
  };

  /* Feed events at a readable pace: a burst (a run opened after the fact) is applied at once. */
  function Pacer(world, onEffects) { this.world = world; this.onEffects = onEffects; this.queue = []; this.gap = 0; }
  Pacer.prototype.push = function (ev) { this.queue.push(ev); };
  Pacer.prototype.step = function (dt) {
    var w = this.world, self = this;
    if (this.queue.length > 24) {
      while (this.queue.length) { w.apply(this.queue.shift()); }
      this.onEffects([], false);
      return;
    }
    this.gap -= dt;
    while (this.queue.length && this.gap <= 0) {
      self.onEffects(w.apply(this.queue.shift()), true);
      this.gap += 0.09;
    }
    if (this.gap < 0) { this.gap = 0; }
  };

  window.SiftWorld = {
    create: function () { return new World(); },
    Pacer: Pacer,
    CLASSES: CLASSES, MONSTERS: MONSTERS, SEVERITIES: SEVERITIES,
    fmtTokens: fmtTokens, fmtS: fmtS, short: short,
    SEV_COLORS: { critical: "#ff4d4d", high: "#ff8a6e", medium: "#f5a524", low: "#7aa2ff", info: "#9aa0aa" }
  };
})();
