/* CodeSift plain dashboard + patch review card. Text is only ever set with textContent. */
(function () {
  "use strict";

  var GATES = ["policy", "poc", "tests", "rescan"];
  var MARK = { pass: "✓ pass", fail: "✗ fail", unavailable: "unavailable", skipped: "— skipped" };
  var TYPE_NAMES = {
    sqli: "SQL injection", xss: "XSS", cmdi: "command injection", traversal: "path traversal",
    secret: "secret", dependency: "vulnerable dependency", glitch: "other"
  };

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function Dashboard(onReview) {
    this.rows = document.getElementById("dash-rows");
    this.summary = document.getElementById("dash-summary");
    this.onReview = onReview;
  }

  Dashboard.prototype.render = function (findings, stats) {
    var rows = this.rows;
    while (rows.firstChild) { rows.removeChild(rows.firstChild); }
    var self = this;
    findings.forEach(function (f) {
      var tr = el("tr");
      var id = el("td"); id.appendChild(el("code", null, f.id)); tr.appendChild(id);
      tr.appendChild(el("td", null, f.path + (f.line ? ":" + f.line : "")));
      tr.appendChild(el("td", null, f.severity || ""));
      tr.appendChild(el("td", null, TYPE_NAMES[f.bug_type] || f.bug_type || ""));
      tr.appendChild(el("td", null, f.stage || "waiting"));
      tr.appendChild(el("td", null, f.backend || "—"));
      tr.appendChild(el("td", "outcome o-" + (f.outcome || "none"), f.outcome ? f.outcome.replace(/_/g, " ") : "in progress"));
      var gates = el("td");
      GATES.forEach(function (g) {
        var status = (f.gates && f.gates[g]) || "skipped";
        gates.appendChild(el("span", "gate g-" + status, g + ": " + (MARK[status] || status)));
      });
      tr.appendChild(gates);
      var act = el("td");
      if (f.outcome) {
        var b = el("button", null, "Review");
        b.type = "button";
        b.setAttribute("aria-label", "Review the patch for " + f.id);
        b.addEventListener("click", function () { self.onReview(f); });
        act.appendChild(b);
      }
      tr.appendChild(act);
      rows.appendChild(tr);
    });
    this.summary.textContent = findings.length + " finding(s) · " + (stats.llmCalls || 0) + " LLM call(s) · " +
      (stats.vmJobs || 0) + " sandbox job(s)";
  };

  function Review(getRun) {
    this.box = document.getElementById("review");
    this.meta = document.getElementById("review-meta");
    this.gates = document.getElementById("review-gates");
    this.diff = document.getElementById("review-diff");
    this.note = document.getElementById("review-note");
    this.status = document.getElementById("review-status");
    this.getRun = getRun;
    this.finding = null;
    var self = this;
    document.getElementById("review-close").addEventListener("click", function () { self.close(); });
    Array.prototype.forEach.call(this.box.querySelectorAll("button[data-action]"), function (b) {
      b.addEventListener("click", function () { self.decide(b.getAttribute("data-action")); });
    });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") { self.close(); } });
  }

  Review.prototype.open = function (f) {
    this.finding = f;
    this.box.classList.remove("hidden");
    this.meta.textContent = f.id + " · " + f.path + " · " + (f.outcome || "in progress");
    while (this.gates.firstChild) { this.gates.removeChild(this.gates.firstChild); }
    var gates = this.gates;
    GATES.forEach(function (g) {
      var status = (f.gates && f.gates[g]) || "skipped";
      gates.appendChild(el("li", "g-" + status, g + ": " + (MARK[status] || status)));
    });
    this.status.textContent = "";
    this.diff.textContent = "loading the patch…";
    var diff = this.diff;
    fetch("/api/patch/" + encodeURIComponent(this.getRun()) + "/" + encodeURIComponent(f.id), { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.text() : "(no patch for this finding)"; })
      .then(function (t) { diff.textContent = t || "(no patch for this finding)"; })
      .catch(function () { diff.textContent = "(could not load the patch)"; });
    this.diff.focus();
  };

  Review.prototype.close = function () {
    this.box.classList.add("hidden");
    this.finding = null;
  };

  Review.prototype.decide = function (action) {
    if (!this.finding) { return; }
    var status = this.status;
    fetch("/api/decision", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CodeSift-CSRF": "1" },
      body: JSON.stringify({ run: this.getRun(), finding: this.finding.id, action: action, note: this.note.value })
    }).then(function (r) {
      status.textContent = r.ok ? "Recorded: " + action + " (nothing was applied)." : "Not recorded (HTTP " + r.status + ").";
    }).catch(function () { status.textContent = "Not recorded (connection error)."; });
  };

  window.SiftDashboard = Dashboard;
  window.SiftReview = Review;
})();
