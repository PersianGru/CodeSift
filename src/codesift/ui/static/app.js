/* CodeSift UI: lists runs (scans and fixes), follows the live one, streams its events into the system
   map and the dashboard. Everything shown comes from the run's own events.jsonl and report. */
(function () {
  "use strict";

  var SEVERITIES = ["critical", "high", "medium", "low", "info"];
  var SEV_COLORS = { critical: "#ff5c5c", high: "#ff8a8a", medium: "#f5a524", low: "#7aa2ff", info: "#9aa0aa" };
  var POLL_MS = 3000;

  var THREE_SCRIPTS = ["three.min.js", "three-GLTFLoader.js", "three-SkeletonUtils.js"];
  var VIEW_KEY = "codesift.view";
  var state = { run: null, runs: [], pinned: false, config: {}, findings: {}, order: [], history: [], map: null, source: null, view: "3d",
    stats: { findings: 0, llmCalls: 0, llmFailed: 0, tokensIn: 0, tokensOut: 0, vmJobs: 0, scanners: 0 }, started: null, ended: null };
  var $ = function (id) { return document.getElementById(id); };

  function text(node, value) { node.textContent = String(value); }

  function getJSON(url) {
    return fetch(url, { credentials: "same-origin" }).then(function (r) {
      if (!r.ok) { throw new Error("HTTP " + r.status); }
      return r.json();
    });
  }

  var dashboard = new window.SiftDashboard(function (f) { review.open(f); });
  var review = new window.SiftReview(function () { return state.run; });

  function finding(id) {
    if (!state.findings[id]) { state.findings[id] = { id: id, gates: {} }; state.order.push(id); }
    return state.findings[id];
  }

  function fmtTokens(n) { return n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + "k" : String(n); }

  function elapsed() {
    if (!state.started) { return "-"; }
    var end = state.ended ? Date.parse(state.ended) : Date.now();
    var s = Math.max(0, Math.round((end - Date.parse(state.started)) / 1000));
    return s >= 60 ? Math.floor(s / 60) + "m " + (s % 60) + "s" : s + "s";
  }

  function render() {
    var list = state.order.map(function (id) { return state.findings[id]; });
    dashboard.render(list, state.stats);
    var st = state.stats;
    text($("stat-findings"), st.findings);
    text($("stat-scanners"), st.scanners);
    text($("stat-llm"), st.llmCalls + (st.llmFailed ? " (" + st.llmFailed + " failed)" : ""));
    text($("stat-tokens"), fmtTokens(st.tokensIn) + " / " + fmtTokens(st.tokensOut));
    text($("stat-jobs"), st.vmJobs);
    text($("stat-time"), elapsed());
    renderSeverities();
    if (state.map) { text($("city-alt"), state.map.describe()); }
  }

  var renderQueued = false;
  function scheduleRender() {
    if (renderQueued) { return; }
    renderQueued = true;
    setTimeout(function () { renderQueued = false; render(); }, 150);
  }

  function renderSeverities() {
    var ul = $("legend");
    while (ul.firstChild) { ul.removeChild(ul.firstChild); }
    SEVERITIES.forEach(function (sev) {
      var n = state.order.filter(function (id) { return state.findings[id].severity === sev; }).length;
      var li = document.createElement("li");
      var sw = document.createElement("span");
      sw.className = "swatch";
      sw.style.background = SEV_COLORS[sev];
      li.appendChild(sw);
      li.appendChild(document.createTextNode(sev));
      var count = document.createElement("span");
      count.className = "count";
      count.textContent = String(n);
      li.appendChild(count);
      ul.appendChild(li);
    });
  }

  function describe(ev) {
    var d = ev.data || {};
    switch (ev.type) {
      case "run.start": return "run started · " + (d.kind || d.mode || "") + " · " + (d.project || "");
      case "run.end": return "run finished · exit " + d.exit_code;
      case "scanner.start": return d.name + " started";
      case "scanner.result": return d.name + " " + d.status + (d.status === "ok" ? " · " + d.findings + " found · " + (d.duration_s || 0).toFixed(1) + "s" : d.reason ? " · " + d.reason : "");
      case "llm.request": return "→ " + d.model + (d.purpose ? " · " + d.purpose : "") + (ev.finding ? " " + ev.finding : "") + " · " + fmtTokens(Math.round((d.prompt_chars || 0) / 4)) + " tok (est)";
      case "llm.response": return "← " + d.model + (d.ok ? " · " + (d.tokens_out || 0) + " tok · " + (d.latency_s || 0).toFixed(1) + "s" : " · failed: " + (d.error || "?"));
      case "vm.command": return "VM: " + d.op + (d.job ? " sift-" + d.job : "");
      case "vm.result": return "VM: " + d.op + (d.job ? " sift-" + d.job : "") + " · rc " + d.rc + " · " + (d.duration_s || 0).toFixed(1) + "s";
      case "finding.detected": return (ev.finding || "") + " " + d.severity + " · " + d.path + (d.line ? ":" + d.line : "");
      default: {
        var detail = d.outcome || d.stage || d.backend || d.gate || (d.rc !== undefined ? "rc " + d.rc : "") || "";
        return (ev.finding ? ev.finding + " " : "") + ev.type + (detail ? " · " + detail : "") + (d.status ? " " + d.status : "");
      }
    }
  }

  var LOG_CLASS = { "llm.request": "k-llm", "llm.response": "k-reply", "vm.command": "k-vm", "vm.result": "k-vm",
    "scanner.start": "k-scan", "scanner.result": "k-scan", "finding.outcome": "important", "error": "k-fail", "run.end": "important", "run.start": "important" };

  function log(ev) {
    var ol = $("event-log");
    var li = document.createElement("li");
    var ts = (ev.ts || "").slice(11, 19);
    li.textContent = (ts ? ts + "  " : "") + describe(ev);
    var d = ev.data || {};
    li.className = (d.ok === false || (ev.type === "vm.result" && d.rc !== 0) || d.status === "error") ? "k-fail" : (LOG_CLASS[ev.type] || "");
    ol.insertBefore(li, ol.firstChild);
    while (ol.childNodes.length > 300) { ol.removeChild(ol.lastChild); }
  }

  function apply(ev) {
    var d = ev.data || {};
    if (ev.finding) {
      var f = finding(ev.finding);
      if (ev.type === "finding.detected") {
        f.path = d.path; f.line = d.line; f.severity = d.severity; f.bug_type = d.bug_type; f.district = d.district; f.tool = d.tool;
      }
      if (ev.type === "stage.enter") { f.stage = d.stage; }
      if (ev.type === "fix.attempt") { f.backend = d.backend; f.stage = "fix"; }
      if (ev.type === "policy.verdict") { f.gates.policy = d.ok ? "pass" : "fail"; }
      if (ev.type === "verify.result") { f.gates[d.gate] = d.status; }
      if (ev.type === "finding.outcome") { f.outcome = d.outcome; f.stage = "done"; }
      if (ev.type === "llm.request" && d.purpose === "triage") { f.stage = "triage"; }
    }
    if (ev.type === "run.start") { state.started = ev.ts; }
    if (ev.type === "run.end") { state.ended = ev.ts; }
    if (state.history.length < 50000) { state.history.push(ev); }
    if (state.map) { state.map.handle(ev); }
    countStats(ev);
    log(ev);
    scheduleRender();
  }

  // The footer counts come from the events themselves, whichever view is showing.
  function countStats(ev) {
    var d = ev.data || {}, st = state.stats;
    if (ev.type === "finding.detected") { st.findings += 1; }
    if (ev.type === "scanner.result" && d.status !== "skipped") { st.scanners += 1; }
    if (ev.type === "llm.response") { st.llmCalls += 1; if (!d.ok) { st.llmFailed += 1; } st.tokensIn += d.tokens_in || 0; st.tokensOut += d.tokens_out || 0; }
    if (ev.type === "vm.command" && d.op === "job") { st.vmJobs += 1; }
  }

  function seedFromReport(report) {
    (report.findings || []).forEach(function (r) {
      if (!r.id) { return; }
      var f = finding(r.id);
      f.path = f.path || r.path; f.line = f.line || r.line; f.severity = f.severity || r.severity;
      f.bug_type = f.bug_type || r.bug_type; f.tool = f.tool || r.tool;
      if (r.outcome) { f.outcome = r.outcome; }
      if (r.verdict && !f.stage) { f.stage = "triaged: " + r.verdict.replace(/_/g, " "); }
      Object.keys(r.gates || {}).forEach(function (g) { f.gates[g] = r.gates[g].status; });
    });
  }

  function showInfo(pick, lines) {
    var box = $("info");
    while (box.firstChild) { box.removeChild(box.firstChild); }
    (lines || []).forEach(function (t) { var p = document.createElement("p"); p.textContent = t; box.appendChild(p); });
  }

  function webgl() {
    try { var c = document.createElement("canvas"); return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl"))); }
    catch (e) { return false; }
  }

  // three.js and the 3D view load only when the 3D view is chosen: the 2D view and the table stay light.
  var scriptsLoaded = {};
  function loadScripts(names) {
    return names.reduce(function (p, name) {
      return p.then(function () {
        if (scriptsLoaded[name]) { return scriptsLoaded[name]; }
        scriptsLoaded[name] = new Promise(function (resolve, reject) {
          var s = document.createElement("script");
          s.src = "/static/" + (name.indexOf("three") === 0 ? "vendor/" : "") + name;
          s.onload = resolve; s.onerror = function () { reject(new Error("could not load " + name)); };
          document.body.appendChild(s);
        });
        return scriptsLoaded[name];
      });
    }, Promise.resolve());
  }

  function remember(view) { try { window.localStorage.setItem(VIEW_KEY, view); } catch (e) { /* private window: fine */ } }
  function remembered() { try { return window.localStorage.getItem(VIEW_KEY); } catch (e) { return null; } }

  function setView(view) {
    if (view === "3d" && !webgl()) { view = "2d"; $("webgl-note").classList.remove("hidden"); }
    state.view = view;
    remember(view);
    ["3d", "2d", "table"].forEach(function (v) { $("view-" + v).setAttribute("aria-pressed", v === view ? "true" : "false"); });
    document.body.classList.toggle("dash", view === "table");
    if (state.map) { state.map.dispose(); state.map = null; }
    if (view !== "table") { startMap(view); }
  }

  function startMap(view) {
    var create;
    if (view === "2d") {
      create = Promise.resolve(function (el) { return window.SiftMap2D.create(el); });
    } else {
      text($("city-alt"), "Loading the 3D view.");
      create = loadScripts(THREE_SCRIPTS.concat(["realm.js"])).then(function () {
        if (!window.SiftRealm || !window.SiftRealm.available()) { throw new Error("no WebGL"); }
        return function (el) { return window.SiftRealm.create(el); };
      });
    }
    create.then(function (make) {
      if (state.view !== view || state.map) { return; } // the user switched again meanwhile
      state.map = make($("city-canvas"));
      state.map.onSelect(showInfo);
      var map = state.map;
      state.history.forEach(function (ev) { map.handle(ev); }); // a view opened mid-run catches up
      text($("city-alt"), map.describe());
    }).catch(function () {
      $("webgl-note").classList.remove("hidden");
      if (state.view === "3d") { setView("2d"); }
    });
  }

  function resetStats() {
    state.stats = { findings: 0, llmCalls: 0, llmFailed: 0, tokensIn: 0, tokensOut: 0, vmJobs: 0, scanners: 0 };
    state.started = null; state.ended = null;
  }

  function loadRun(id) {
    if (state.source) { state.source.close(); state.source = null; }
    state.run = id;
    state.findings = {}; state.order = []; state.history = [];
    resetStats();
    var ol = $("event-log");
    while (ol.firstChild) { ol.removeChild(ol.firstChild); }
    showInfo(null, ["Click the CodeSift core, a scanner, a model or the VM."]);
    if (state.map) { state.map.dispose(); state.map = null; }
    $("run-select").value = id;
    getJSON("/api/run/" + encodeURIComponent(id) + "/report").then(function (report) {
      state.report = report;
      if (state.view !== "table") { startMap(state.view); }
      var src = new EventSource("/api/stream/" + encodeURIComponent(id));
      state.source = src;
      var finished = false;
      src.onmessage = function (m) {
        var ev;
        try { ev = JSON.parse(m.data); } catch (e) { return; }
        apply(ev);
        if (ev.type === "run.end") {
          finished = true; src.close();
          getJSON("/api/run/" + encodeURIComponent(id) + "/report").then(function (r) { seedFromReport(r); scheduleRender(); })
            .catch(function () { seedFromReport(report); scheduleRender(); });
        }
      };
      src.onerror = function () { src.close(); if (!finished) { seedFromReport(report); scheduleRender(); } };
    }).catch(function () { text($("city-alt"), "Could not load the run."); });
  }

  function label(r) {
    var what = !r.mode || r.mode === r.kind ? (r.kind || r.mode || "") : (r.kind ? r.kind + " " : "") + r.mode; // "fix", not "fix fix"
    return (r.live ? "● live · " : "") + r.project + " · " + what + " · " + String(r.started).replace("T", " ").replace("Z", "");
  }

  function fillRuns(runs) {
    var select = $("run-select");
    var keep = select.value;
    while (select.firstChild) { select.removeChild(select.firstChild); }
    runs.forEach(function (r) {
      var opt = document.createElement("option");
      opt.value = r.id;
      opt.textContent = label(r);
      select.appendChild(opt);
    });
    if (keep) { select.value = keep; }
  }

  // Follow the newest run: when a new scan or fix starts, switch to it unless the user picked a run.
  function poll() {
    getJSON("/api/runs").then(function (data) {
      var runs = (data.runs || []).filter(function (r) { return r.id !== "demo"; });
      var newest = runs[0];
      var known = state.runs.map(function (r) { return r.id; });
      state.runs = data.runs || [];
      fillRuns(state.runs);
      if (newest && known.indexOf(newest.id) === -1 && !state.pinned && newest.id !== state.run) { loadRun(newest.id); }
    }).catch(function () { /* server stopped: the page keeps what it has */ });
  }

  function init() {
    getJSON("/api/config").then(function (cfg) {
      state.config = cfg;
      var small = window.innerWidth < 720;
      var pick = remembered();
      var view = cfg.ci ? "table" : (pick === "3d" || pick === "2d" || pick === "table") ? pick : (small || !webgl()) ? "2d" : "3d";
      state.view = view;
      ["3d", "2d", "table"].forEach(function (v) { $("view-" + v).setAttribute("aria-pressed", v === view ? "true" : "false"); });
      document.body.classList.toggle("dash", view === "table");
      return getJSON("/api/runs");
    }).then(function (data) {
      state.runs = data.runs || [];
      fillRuns(state.runs);
      $("run-select").addEventListener("change", function () {
        state.pinned = $("run-select").value !== (state.runs[0] && state.runs[0].id);
        loadRun($("run-select").value);
      });
      if (state.runs.length) { loadRun(state.runs[0].id); } else {
        text($("dash-summary"), "No runs yet. Start `sift scan` or `sift fix` in a project - this page picks it up live.");
        if (state.view !== "table") { startMap(state.view); }
      }
      setInterval(poll, POLL_MS);
      setInterval(function () { if (state.started && !state.ended) { text($("stat-time"), elapsed()); } }, 1000);
    }).catch(function () { text($("dash-summary"), "Could not reach the CodeSift UI server."); });

    ["3d", "2d", "table"].forEach(function (v) {
      $("view-" + v).addEventListener("click", function () { if (state.view !== v || (!state.map && v !== "table")) { setView(v); } });
    });
    $("follow").addEventListener("click", function () {
      state.pinned = false;
      if (state.runs[0]) { loadRun(state.runs[0].id); }
    });
    $("pause").addEventListener("click", function () {
      var p = $("pause").getAttribute("aria-pressed") !== "true";
      $("pause").setAttribute("aria-pressed", p ? "true" : "false");
      text($("pause"), p ? "Resume" : "Pause");
      if (state.map) { state.map.setPaused(p); }
    });
    $("speed").addEventListener("change", function () { if (state.map) { state.map.setSpeed(parseFloat($("speed").value)); } });
  }

  init();
})();
