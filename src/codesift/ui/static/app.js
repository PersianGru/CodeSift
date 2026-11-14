/* CodeSift UI: loads runs, streams events, keeps the finding store, drives city + dashboard. */
(function () {
  "use strict";

  var NAMES = {
    sqli: "Syringe leech (SQL injection)", xss: "Mask imp (XSS)", cmdi: "Shell wraith (command injection)",
    traversal: "Tunnel worm (path traversal)", secret: "Key thief (secret)", dependency: "Rotten crate (dependency)",
    glitch: "Glitch (other)"
  };
  var COLORS = { sqli: "#ff8a8a", xss: "#e879f9", cmdi: "#f5a524", traversal: "#a78bfa", secret: "#7dd3fc", dependency: "#bef264", glitch: "#5eead4" };

  var state = { run: null, config: {}, findings: {}, order: [], history: [], city: null, source: null, stats: { health: 100, repaired: 0, landfill: 0, limbo: 0, tokens: 0 }, hatch: 100 };
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

  function render() {
    var list = state.order.map(function (id) { return state.findings[id]; });
    dashboard.render(list, state.stats);
    text($("stat-health"), state.stats.health + "%");
    text($("stat-repaired"), state.stats.repaired);
    text($("stat-landfill"), state.stats.landfill);
    text($("stat-limbo"), state.stats.limbo);
    text($("stat-tokens"), state.stats.tokens);
    renderLegend();
    if (state.city) { text($("city-alt"), state.city.describe()); }
  }

  var renderQueued = false;
  function scheduleRender() {
    if (renderQueued) { return; }
    renderQueued = true;
    setTimeout(function () { renderQueued = false; render(); }, 150);
  }

  function renderLegend() {
    var ul = $("legend");
    while (ul.firstChild) { ul.removeChild(ul.firstChild); }
    Object.keys(NAMES).forEach(function (type) {
      var li = document.createElement("li");
      var sw = document.createElement("span");
      sw.className = "swatch";
      sw.style.background = COLORS[type];
      li.appendChild(sw);
      li.appendChild(document.createTextNode(NAMES[type]));
      var count = document.createElement("span");
      count.className = "count";
      count.textContent = String(state.order.filter(function (id) { return state.findings[id].bug_type === type; }).length);
      li.appendChild(count);
      if (state.config.demo && state.run === "demo") {
        var b = document.createElement("button");
        b.type = "button";
        b.textContent = "hatch";
        b.setAttribute("aria-label", "Hatch a demo " + NAMES[type]);
        b.addEventListener("click", function () { hatch(type); });
        li.appendChild(b);
      }
      ul.appendChild(li);
    });
  }

  function log(ev) {
    var ol = $("event-log");
    var li = document.createElement("li");
    var d = ev.data || {};
    var detail = d.outcome || d.stage || d.backend || d.gate || (d.rc !== undefined ? "rc " + d.rc : "") || "";
    li.textContent = (ev.finding ? ev.finding + " " : "") + ev.type + (detail ? " · " + detail : "") + (d.status ? " " + d.status : "");
    if (ev.type === "finding.outcome" || ev.type === "error" || ev.type === "run.end") { li.className = "important"; }
    ol.insertBefore(li, ol.firstChild);
    while (ol.childNodes.length > 200) { ol.removeChild(ol.lastChild); }
  }

  function apply(ev) {
    var d = ev.data || {};
    if (ev.finding) {
      var f = finding(ev.finding);
      if (ev.type === "finding.detected") {
        f.path = d.path; f.line = d.line; f.severity = d.severity; f.bug_type = d.bug_type; f.district = d.district;
      }
      if (ev.type === "stage.enter") { f.stage = d.stage; }
      if (ev.type === "fix.attempt") { f.backend = d.backend; f.stage = "fix"; }
      if (ev.type === "policy.verdict") { f.gates.policy = d.ok ? "pass" : "fail"; }
      if (ev.type === "verify.result") { f.gates[d.gate] = d.status; }
      if (ev.type === "finding.outcome") { f.outcome = d.outcome; f.stage = "done"; }
    }
    if (ev.type === "budget.update") { state.stats.tokens = d.tokens_used || 0; }
    if (state.history.length < 20000) { state.history.push(ev); }
    if (state.city) { state.city.handle(ev); }
    log(ev);
    scheduleRender();
  }

  function seedFromReport(report) {
    (report.findings || []).forEach(function (r) {
      var f = finding(r.id);
      f.path = f.path || r.path; f.line = f.line || r.line; f.severity = f.severity || r.severity;
      f.bug_type = f.bug_type || r.bug_type;
      if (r.outcome) { f.outcome = r.outcome; }
      Object.keys(r.gates || {}).forEach(function (g) { f.gates[g] = r.gates[g].status; });
    });
  }

  function hatch(type) {
    state.hatch += 1;
    var id = "D" + state.hatch;
    var paths = { sqli: "app/db/orders.py", xss: "web/static/app.js", cmdi: "tools/backup.sh", traversal: "uploads/files.py",
      secret: "config/keys.py", dependency: "package.json", glitch: "src/misc.py" };
    var district = { sqli: "db", xss: "web", cmdi: "tools", traversal: "uploads", secret: "config", dependency: "vendor", glitch: "annex" }[type];
    var outcomes = ["fixed_verified", "fixed_unproven", "rejected_tests", "inconclusive"];
    var seq = [
      { type: "finding.detected", finding: id, data: { path: paths[type], line: 7, severity: "high", bug_type: type, district: district } },
      { type: "stage.enter", finding: id, data: { stage: "triage" } },
      { type: "fix.attempt", finding: id, data: { backend: Math.random() > 0.5 ? "gateway" : "claude-cli", attempt: 1 } },
      { type: "policy.verdict", finding: id, data: { ok: true } },
      { type: "stage.enter", finding: id, data: { stage: "sandbox" } },
      { type: "stage.enter", finding: id, data: { stage: "verify" } },
      { type: "finding.outcome", finding: id, data: { outcome: outcomes[state.hatch % outcomes.length] } }
    ];
    seq.forEach(function (ev, i) { setTimeout(function () { apply(ev); }, i * 900); });
  }

  function showInfo(info) {
    var box = $("info");
    while (box.firstChild) { box.removeChild(box.firstChild); }
    function line(t) { var p = document.createElement("p"); p.textContent = t; box.appendChild(p); }
    if (info.kind === "building") {
      var b = info.building;
      line(b.path || (b.aggregate ? "aggregated files" : "another file (no findings)"));
      line("State: " + b.state);
      if (b.findings.length) { line("Findings: " + b.findings.join(", ")); }
    } else if (info.kind === "station") {
      line(info.title);
      var station = state.city && state.city.stations[info.key];
      line("Visits: " + (station ? station.visits : 0));
    } else if (info.kind === "bug") {
      var f = state.findings[info.bug.f.id] || {};
      line(info.bug.f.id + " · " + (NAMES[info.bug.type] || info.bug.type));
      line((f.severity || "") + " · " + (f.path || ""));
      line("Stage: " + (f.stage || "waiting") + (f.backend ? " · " + f.backend : ""));
      line("Outcome: " + (f.outcome || "in progress"));
      if (f.outcome) {
        var btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = "Review patch";
        btn.addEventListener("click", function () { review.open(f); });
        box.appendChild(btn);
      }
    }
  }

  function setDashboard(on) {
    document.body.classList.toggle("dash", on);
    $("view-toggle").setAttribute("aria-pressed", on ? "true" : "false");
    text($("view-toggle"), on ? "Living city" : "Plain dashboard");
    if (!on && !state.city) { startCity(); }
  }

  function startCity() {
    if (!window.SiftCity || !window.SiftCity.available()) {
      $("webgl-note").classList.remove("hidden");
      setDashboard(true);
      $("view-toggle").disabled = true;
      return;
    }
    var report = state.report || {};
    state.city = window.SiftCity.create($("city-canvas"), {
      districtNames: report.districts,
      onStats: function (s) {
        state.stats.health = s.health; state.stats.repaired = s.repaired;
        state.stats.landfill = s.landfill; state.stats.limbo = s.limbo;
        scheduleRender();
      }
    });
    state.city.onSelect(showInfo);
    var city = state.city;
    state.history.forEach(function (ev) { city.handle(ev); }); // a city opened mid-run catches up
  }

  function loadRun(id) {
    if (state.source) { state.source.close(); state.source = null; }
    state.run = id;
    state.findings = {}; state.order = []; state.history = [];
    var ol = $("event-log");
    while (ol.firstChild) { ol.removeChild(ol.firstChild); }
    if (state.city) {
      var holder = $("city-canvas");
      while (holder.firstChild) { holder.removeChild(holder.firstChild); }
      state.city = null;
    }
    getJSON("/api/run/" + encodeURIComponent(id) + "/report").then(function (report) {
      state.report = report;
      if (!document.body.classList.contains("dash")) { startCity(); }
      var src = new EventSource("/api/stream/" + encodeURIComponent(id));
      state.source = src;
      var finished = false;
      src.onmessage = function (m) {
        var ev;
        try { ev = JSON.parse(m.data); } catch (e) { return; }
        apply(ev);
        if (ev.type === "run.end") { finished = true; src.close(); seedFromReport(report); scheduleRender(); }
      };
      src.onerror = function () { src.close(); if (!finished) { seedFromReport(report); scheduleRender(); } };
    }).catch(function () { text($("city-alt"), "Could not load the run."); });
  }

  function init() {
    getJSON("/api/config").then(function (cfg) {
      state.config = cfg;
      var small = window.innerWidth < 720;
      var wantDash = cfg.ci || small || !(window.SiftCity && window.SiftCity.available());
      document.body.classList.toggle("dash", wantDash);
      $("view-toggle").setAttribute("aria-pressed", wantDash ? "true" : "false");
      text($("view-toggle"), wantDash ? "Living city" : "Plain dashboard");
      return getJSON("/api/runs");
    }).then(function (data) {
      var select = $("run-select");
      (data.runs || []).forEach(function (r) {
        var opt = document.createElement("option");
        opt.value = r.id;
        opt.textContent = r.project + " · " + r.mode + " · " + r.started;
        select.appendChild(opt);
      });
      select.addEventListener("change", function () { loadRun(select.value); });
      if (data.runs && data.runs.length) { loadRun(data.runs[0].id); } else { text($("dash-summary"), "No runs yet - run `sift fix` or `sift validate`, or start `sift ui --demo`."); }
    }).catch(function () { text($("dash-summary"), "Could not reach the CodeSift UI server."); });

    $("view-toggle").addEventListener("click", function () { setDashboard(!document.body.classList.contains("dash")); });
    $("pause").addEventListener("click", function () {
      var p = $("pause").getAttribute("aria-pressed") !== "true";
      $("pause").setAttribute("aria-pressed", p ? "true" : "false");
      text($("pause"), p ? "Resume" : "Pause");
      if (state.city) { state.city.setPaused(p); }
    });
    $("speed").addEventListener("change", function () { if (state.city) { state.city.setSpeed(parseFloat($("speed").value)); } });
  }

  init();
})();
