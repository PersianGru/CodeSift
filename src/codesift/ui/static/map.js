/* CodeSift live system map: the machines and services that really take part in a run, and the real
   traffic between them. Nothing here is invented: every node comes from the run's topology, and every
   packet is one event from events.jsonl (a scanner starting or reporting, one LLM request or answer,
   one command on the sandbox VM). With no events, nothing moves except the camera.
   Palette after 21cel.com: near-black glass, amber accent, soft green/red. */
(function () {
  "use strict";
  var THREE = window.THREE;
  if (!THREE) { window.SiftMap = { available: function () { return false; } }; return; }

  var C = {
    bg: 0x07080a, floor: 0x0a0b0e, glass: 0x12151a, edge: 0xf5a524, text: "#edeef0", dim: "#9aa0aa",
    amber: 0xf5a524, amber2: 0xffc861, ok: 0x6ee7a0, bad: 0xff8a8a, idle: 0x3a404a, sky: 0x7aa2ff, violet: 0xa78bfa
  };
  var SEV = { critical: 0xff5c5c, high: 0xff8a8a, medium: 0xf5a524, low: 0x7aa2ff, info: 0x9aa0aa };
  var FONT = "\"Segoe UI Variable Display\", \"Segoe UI\", system-ui, -apple-system, sans-serif";
  var MONO = "ui-monospace, \"Cascadia Code\", Consolas, Menlo, monospace";

  var LOCAL = new THREE.Vector3(-12, 0, 4);
  var CORE = new THREE.Vector3(-6, 0, 4);
  var LLM = new THREE.Vector3(34, 0, -4);
  var VM = new THREE.Vector3(8, 0, -34);

  function available() {
    if (!THREE) { return false; }
    try {
      var c = document.createElement("canvas");
      return !!(window.WebGLRenderingContext && (c.getContext("webgl") || c.getContext("experimental-webgl")));
    } catch (e) { return false; }
  }

  function fmtTokens(n) { return n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + "k" : String(n); }
  function fmtS(s) { return s >= 60 ? Math.floor(s / 60) + "m" + Math.round(s % 60) + "s" : (s || 0).toFixed(1) + "s"; }

  // ------------------------------------------------------------------ labels (canvas sprites)

  function Label(lines, opts) {
    opts = opts || {};
    this.canvas = document.createElement("canvas");
    this.canvas.width = 512; this.canvas.height = 160;
    this.tex = new THREE.CanvasTexture(this.canvas);
    this.tex.anisotropy = 4;
    var mat = new THREE.SpriteMaterial({ map: this.tex, transparent: true, depthWrite: false, depthTest: opts.depthTest !== false });
    this.sprite = new THREE.Sprite(mat);
    this.sprite.scale.set((opts.scale || 1) * 12, (opts.scale || 1) * 3.75, 1);
    this.sprite.userData.noPick = true;
    this.accent = opts.accent || "#f5a524";
    this.set(lines);
  }
  Label.prototype.set = function (lines) {
    var key = JSON.stringify(lines);
    if (key === this.key) { return; }
    this.key = key;
    var g = this.canvas.getContext("2d");
    g.clearRect(0, 0, 512, 160);
    g.textAlign = "center";
    g.shadowColor = "rgba(0,0,0,0.9)"; g.shadowBlur = 10;
    g.fillStyle = C.text;
    g.font = "600 46px " + FONT;
    g.fillText(lines[0] || "", 256, 58);
    if (lines[1]) { g.fillStyle = this.accent; g.font = "500 34px " + MONO; g.fillText(lines[1], 256, 106); }
    if (lines[2]) { g.fillStyle = C.dim; g.font = "400 28px " + MONO; g.fillText(lines[2], 256, 146); }
    this.tex.needsUpdate = true;
  };

  // ------------------------------------------------------------------ the map

  function SystemMap(container, opts) {
    this.container = container;
    this.opts = opts || {};
    this.reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    this.speed = 1; this.paused = false; this.time = 0;
    this.queue = []; this.packets = []; this.animated = []; this.pickables = [];
    this.scanners = {}; this.models = {}; this.backends = {}; this.jobs = {}; this.findings = [];
    this.links = {};
    this.stats = { llmCalls: 0, llmFailed: 0, tokensIn: 0, tokensOut: 0, vmCommands: 0, vmJobs: 0, findings: 0, scanners: 0 };
    this.topology = null;
    this.init();
  }

  SystemMap.prototype.init = function () {
    var w = this.container.clientWidth || 800, h = this.container.clientHeight || 500;
    var r = this.renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
    r.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    r.setSize(w, h);
    // Colours are authored as screen colours (the 21cel hex values) and shown as such: no extra
    // gamma or tone mapping on top, so the near-black stays near-black and amber stays amber.
    r.shadowMap.enabled = true;
    r.shadowMap.type = THREE.PCFSoftShadowMap;
    r.domElement.tabIndex = 0;
    r.domElement.setAttribute("aria-label", "3D system map. Drag to rotate, scroll to zoom, arrow keys to turn.");
    this.container.appendChild(r.domElement);

    var scene = this.scene = new THREE.Scene();
    scene.background = new THREE.Color(C.bg);
    scene.fog = new THREE.FogExp2(C.bg, 0.0085);
    this.camera = new THREE.PerspectiveCamera(42, w / h, 0.5, 600);
    this.target = new THREE.Vector3(8, 2, -8);
    this.orbit = { azimuth: 1.25, polar: 0.95, dist: 84, dragging: false, moved: 0, lastX: 0, lastY: 0 };
    this.raycaster = new THREE.Raycaster();
    this.clock = new THREE.Clock();

    if (THREE.RoomEnvironment) {
      var pmrem = new THREE.PMREMGenerator(r);
      this.env = pmrem.fromScene(new THREE.RoomEnvironment(), 0.04).texture; // reflections on glass only
    }
    this.buildLights();
    this.buildFloor();
    this.buildLocal();
    this.buildLLM();
    this.buildVM();
    this.buildPost(w, h);
    this.bindInput();
    var self = this;
    this.onResize = function () { self.resize(); };
    window.addEventListener("resize", this.onResize);
    this.loop();
  };

  SystemMap.prototype.buildPost = function (w, h) {
    if (!(THREE.EffectComposer && THREE.RenderPass && THREE.UnrealBloomPass)) { return; }
    var comp = this.composer = new THREE.EffectComposer(this.renderer);
    comp.addPass(new THREE.RenderPass(this.scene, this.camera));
    this.bloom = new THREE.UnrealBloomPass(new THREE.Vector2(w, h), 1.1, 0.6, 0.55); // only bright, emissive parts glow
    comp.addPass(this.bloom);
  };

  SystemMap.prototype.resize = function () {
    var w = this.container.clientWidth || 800, h = this.container.clientHeight || 500;
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(w, h);
    if (this.composer) { this.composer.setSize(w, h); }
  };

  SystemMap.prototype.buildLights = function () {
    var s = this.scene;
    s.add(new THREE.HemisphereLight(0x6f7c96, 0x080604, 0.28));
    var key = new THREE.DirectionalLight(0xfff1dc, 0.75);
    key.position.set(-40, 70, 50);
    key.castShadow = true;
    key.shadow.mapSize.set(2048, 2048);
    var sc = key.shadow.camera; sc.left = -80; sc.right = 80; sc.top = 80; sc.bottom = -80; sc.far = 220;
    key.shadow.bias = -0.0004;
    s.add(key);
    var rim = new THREE.DirectionalLight(0x7aa2ff, 0.35);
    rim.position.set(60, 30, -70);
    s.add(rim);
    this.coreLight = new THREE.PointLight(C.amber, 1.2, 40, 2);
    this.coreLight.position.copy(CORE).setY(14);
    s.add(this.coreLight);
  };

  SystemMap.prototype.buildFloor = function () {
    var floor = new THREE.Mesh(new THREE.CircleGeometry(220, 96),
      new THREE.MeshStandardMaterial({ color: C.floor, roughness: 0.55, metalness: 0.3 }));
    floor.rotation.x = -Math.PI / 2;
    floor.receiveShadow = true;
    floor.userData.noPick = true;
    this.scene.add(floor);
    var grid = new THREE.GridHelper(300, 75, 0x3a2c12, 0x16181c);
    grid.material.transparent = true; grid.material.opacity = 0.7; grid.position.y = 0.02;
    this.scene.add(grid);
  };

  SystemMap.prototype.platform = function (center, w, d, title, sub, pick) {
    var g = new THREE.Group();
    g.position.copy(center);
    var slab = new THREE.Mesh(new THREE.BoxGeometry(w, 0.8, d),
      new THREE.MeshPhysicalMaterial({ color: C.glass, roughness: 0.55, metalness: 0.45, clearcoat: 0.6, clearcoatRoughness: 0.5,
        envMap: this.env || null, envMapIntensity: 0.18 }));
    slab.position.y = 0.4; slab.castShadow = true; slab.receiveShadow = true;
    g.add(slab);
    var edges = new THREE.LineSegments(new THREE.EdgesGeometry(slab.geometry),
      new THREE.LineBasicMaterial({ color: C.edge, transparent: true, opacity: 0.55 }));
    edges.position.copy(slab.position);
    g.add(edges);
    var strip = new THREE.Mesh(new THREE.BoxGeometry(w * 0.96, 0.06, 0.18), new THREE.MeshBasicMaterial({ color: C.amber }));
    strip.position.set(0, 0.84, d / 2 - 0.4);
    g.add(strip);
    var label = new Label([title, sub || ""], { scale: 1.35 });
    label.sprite.position.set(0, 3.2, d / 2 + 1.5);
    g.add(label.sprite);
    g.traverse(function (o) { if (!o.userData.noPick) { o.userData.pick = pick; } });
    this.pickables.push(g);
    this.scene.add(g);
    return { group: g, label: label, edges: edges, strip: strip };
  };

  // ------------------------------------------------------------------ this machine: CodeSift + scanners

  SystemMap.prototype.buildLocal = function () {
    this.local = this.platform(LOCAL, 44, 36, "This machine", "CodeSift + scanners", { kind: "local" });
    var core = new THREE.Group();
    core.position.copy(CORE).setY(0.8);
    var base = new THREE.Mesh(new THREE.CylinderGeometry(3.2, 3.8, 1.2, 6),
      new THREE.MeshStandardMaterial({ color: 0x1d2128, roughness: 0.3, metalness: 0.8 }));
    base.position.y = 0.6; base.castShadow = true;
    core.add(base);
    var gem = new THREE.Mesh(new THREE.IcosahedronGeometry(2.1, 0),
      new THREE.MeshStandardMaterial({ color: C.amber, emissive: C.amber, emissiveIntensity: 0.9, roughness: 0.25, metalness: 0.4, flatShading: true }));
    gem.position.y = 4.2; gem.castShadow = true;
    core.add(gem);
    var ring = new THREE.Mesh(new THREE.TorusGeometry(3.4, 0.07, 8, 96), new THREE.MeshBasicMaterial({ color: C.amber2 }));
    ring.position.y = 4.2; ring.rotation.x = Math.PI / 2.4;
    core.add(ring);
    this.coreLabel = new Label(["CodeSift", "waiting for a run"], { scale: 1.1 });
    this.coreLabel.sprite.position.y = 8.6;
    core.add(this.coreLabel.sprite);
    core.traverse(function (o) { if (!o.userData.noPick) { o.userData.pick = { kind: "core" }; } });
    this.pickables.push(core);
    this.scene.add(core);
    this.core = { group: core, gem: gem, ring: ring, activity: 0 };
    var self = this;
    this.animated.push({ update: function (dt, t) {
      var a = self.core.activity = Math.max(0, self.core.activity - dt * 0.6);
      gem.rotation.y += dt * (0.25 + a * 2);
      gem.rotation.x = Math.sin(t * 0.3) * 0.2;
      ring.rotation.z += dt * (0.15 + a);
      gem.material.emissiveIntensity = 0.55 + a * 1.4 + Math.sin(t * 2) * 0.05;
      self.coreLight.intensity = 0.9 + a * 1.6;
    } });

    // findings: one small crystal per finding, coloured by severity, orbiting the core
    var max = 400;
    var inst = new THREE.InstancedMesh(new THREE.OctahedronGeometry(0.32, 0), new THREE.MeshBasicMaterial({ color: 0xffffff }), max);
    var white = new THREE.Color(0xffffff);
    for (var k = 0; k < max; k++) { inst.setColorAt(k, white); }
    inst.count = 0;
    inst.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    inst.userData.noPick = true;
    this.scene.add(inst);
    this.findingMesh = inst;
  };

  SystemMap.prototype.scannerSlot = function (i, n) {
    var spread = Math.min(Math.PI * 1.1, 0.42 * Math.max(n - 1, 1));
    var a = Math.PI - spread / 2 + (n > 1 ? spread * i / (n - 1) : spread / 2);
    return new THREE.Vector3(CORE.x + Math.cos(a) * 15, 0.8, CORE.z + Math.sin(a) * 13);
  };

  SystemMap.prototype.ensureScanner = function (name) {
    if (this.scanners[name]) { return this.scanners[name]; }
    var names = Object.keys(this.scanners).concat([name]);
    var g = new THREE.Group();
    var mat = new THREE.MeshStandardMaterial({ color: 0x20252d, emissive: C.idle, emissiveIntensity: 0.5, roughness: 0.35, metalness: 0.6 });
    var column = new THREE.Mesh(new THREE.CylinderGeometry(1.05, 1.25, 1, 6), mat);
    column.castShadow = true;
    g.add(column);
    var cap = new THREE.Mesh(new THREE.CylinderGeometry(1.15, 1.15, 0.16, 6), new THREE.MeshBasicMaterial({ color: C.idle }));
    g.add(cap);
    var label = new Label([name, "queued"], { scale: 0.7 });
    g.add(label.sprite);
    var s = { name: name, group: g, column: column, cap: cap, label: label, status: "queued", findings: 0,
      duration: 0, version: "", reason: "", height: 1.2, pulse: 0 };
    g.traverse(function (o) { if (!o.userData.noPick) { o.userData.pick = { kind: "scanner", key: name }; } });
    this.pickables.push(g);
    this.scene.add(g);
    this.scanners[name] = s;
    var self = this;
    names.forEach(function (n, i) { self.scanners[n].group.position.copy(self.scannerSlot(i, names.length)); });
    this.setScanner(s);
    this.animated.push({ update: function (dt, t) {
      var target = s.height;
      var cur = column.scale.y + (target - column.scale.y) * Math.min(1, dt * 4);
      column.scale.y = cur; column.position.y = cur / 2;
      cap.position.y = cur + 0.1;
      label.sprite.position.y = cur + 2.6;
      s.pulse = Math.max(0, s.pulse - dt);
      var running = s.status === "running";
      mat.emissiveIntensity = running ? 0.6 + Math.abs(Math.sin(t * 5)) * 0.9 : 0.45 + s.pulse;
    } });
    return s;
  };

  SystemMap.prototype.setScanner = function (s) {
    var color = { queued: C.idle, running: C.amber, ok: C.ok, error: C.bad, skipped: 0x2a2e35 }[s.status] || C.idle;
    s.column.material.emissive.setHex(color);
    s.cap.material.color.setHex(color);
    s.height = s.status === "skipped" ? 0.5 : 1.4 + Math.log2(1 + s.findings) * 1.6;
    var sub = s.status === "running" ? "running…" : s.status === "ok" ? s.findings + " found · " + fmtS(s.duration)
      : s.status === "error" ? "error" : s.status === "skipped" ? "skipped" : "queued";
    s.label.set([s.name, sub]);
  };

  // ------------------------------------------------------------------ LLM gateway

  SystemMap.prototype.buildLLM = function () {
    this.llm = this.platform(LLM, 26, 24, "LLM gateway", "not configured", { kind: "llm" });
  };

  SystemMap.prototype.ensureModel = function (id, role) {
    if (this.models[id]) { return this.models[id]; }
    var n = Object.keys(this.models).length;
    var pos = LLM.clone().add(new THREE.Vector3(n === 0 ? -4 : 5, 0, n === 0 ? -2 : 4 + (n - 1) * 5));
    var g = new THREE.Group();
    g.position.copy(pos).setY(0.8);
    var pedestal = new THREE.Mesh(new THREE.CylinderGeometry(1.6, 2, 0.8, 32),
      new THREE.MeshStandardMaterial({ color: 0x1d2128, roughness: 0.3, metalness: 0.8 }));
    pedestal.position.y = 0.4; pedestal.castShadow = true;
    g.add(pedestal);
    var heart = new THREE.Mesh(new THREE.SphereGeometry(1.1, 32, 24),
      new THREE.MeshBasicMaterial({ color: role === "fallback" ? C.violet : C.amber2 }));
    heart.position.y = 4;
    g.add(heart);
    var shell = new THREE.Mesh(new THREE.SphereGeometry(2.1, 48, 32), new THREE.MeshPhysicalMaterial({
      color: 0x9fb0c8, roughness: 0.05, metalness: 0.1, transparent: true, opacity: 0.16, clearcoat: 1,
      envMap: this.env || null, envMapIntensity: 0.6, depthWrite: false }));
    shell.position.y = 4; shell.castShadow = true;
    g.add(shell);
    var halo = new THREE.Mesh(new THREE.TorusGeometry(2.7, 0.06, 8, 96), new THREE.MeshBasicMaterial({ color: C.amber, transparent: true, opacity: 0 }));
    halo.position.y = 4; halo.rotation.x = Math.PI / 2;
    g.add(halo);
    var label = new Label([id, role === "fallback" ? "fallback · idle" : "idle"], { scale: 0.85, accent: role === "fallback" ? "#a78bfa" : "#f5a524" });
    label.sprite.position.y = 8;
    g.add(label.sprite);
    var m = { id: id, role: role, group: g, heart: heart, halo: halo, label: label, inflight: 0, calls: 0, failed: 0,
      tokensIn: 0, tokensOut: 0, latency: 0, lastError: "" };
    g.traverse(function (o) { if (!o.userData.noPick) { o.userData.pick = { kind: "model", key: id }; } });
    this.pickables.push(g);
    this.scene.add(g);
    this.models[id] = m;
    this.animated.push({ update: function (dt, t) {
      var busy = m.inflight > 0;
      halo.material.opacity += ((busy ? 0.9 : 0) - halo.material.opacity) * Math.min(1, dt * 5);
      halo.rotation.z += dt * (busy ? 3 : 0.2);
      halo.scale.setScalar(1 + (busy ? Math.sin(t * 6) * 0.05 : 0));
      heart.scale.setScalar(busy ? 1 + Math.abs(Math.sin(t * 4)) * 0.25 : 0.85);
    } });
    this.refreshModel(m);
    return m;
  };

  SystemMap.prototype.refreshModel = function (m) {
    var state = m.inflight > 0 ? "thinking…" : m.calls ? m.calls + " calls" : "idle";
    var detail = m.calls ? fmtTokens(m.tokensIn) + " in · " + fmtTokens(m.tokensOut) + " out · avg " + fmtS(m.latency / Math.max(1, m.calls - m.failed)) : "";
    m.label.set([m.id, (m.role === "fallback" ? "fallback · " : "") + state, detail]);
  };

  // ------------------------------------------------------------------ sandbox VM

  SystemMap.prototype.buildVM = function () {
    this.vm = this.platform(VM, 36, 22, "Sandbox VM", "not configured", { kind: "vm" });
    var host = new THREE.Group();
    host.position.copy(VM).add(new THREE.Vector3(-12, 0.8, 0));
    var rack = new THREE.Mesh(new THREE.BoxGeometry(5, 6, 4), new THREE.MeshStandardMaterial({ color: 0x1b1f26, roughness: 0.35, metalness: 0.75 }));
    rack.position.y = 3; rack.castShadow = true;
    host.add(rack);
    var leds = [];
    for (var i = 0; i < 5; i++) {
      var led = new THREE.Mesh(new THREE.BoxGeometry(3.6, 0.12, 0.05), new THREE.MeshBasicMaterial({ color: 0x2a2e35 }));
      led.position.set(0, 1 + i * 1.05, 2.03);
      host.add(led); leds.push(led);
    }
    host.traverse(function (o) { if (!o.userData.noPick) { o.userData.pick = { kind: "vm" }; } });
    this.pickables.push(host);
    this.scene.add(host);
    this.vmHost = { group: host, leds: leds, blink: 0, commands: 0, last: "" };
    var self = this;
    this.animated.push({ update: function (dt, t) {
      var b = self.vmHost.blink = Math.max(0, self.vmHost.blink - dt);
      leds.forEach(function (l, k) { l.material.color.setHex(b > 0 && Math.sin(t * 30 + k * 2) > 0 ? C.ok : 0x2a2e35); });
    } });
  };

  SystemMap.prototype.jobSlot = function (n) {
    var col = n % 6, row = Math.floor(n / 6) % 3;
    return VM.clone().add(new THREE.Vector3(-4 + col * 3.6, 0.8, -5 + row * 4.5));
  };

  SystemMap.prototype.startJob = function (id) {
    var n = this.stats.vmJobs;
    var g = new THREE.Group();
    g.position.copy(this.jobSlot(n));
    var box = new THREE.Mesh(new THREE.BoxGeometry(2.6, 2.6, 2.6), new THREE.MeshStandardMaterial({
      color: 0x20252d, emissive: C.amber, emissiveIntensity: 0.9, roughness: 0.4, metalness: 0.3, transparent: true, opacity: 0.95 }));
    box.position.y = 1.3; box.castShadow = true;
    g.add(box);
    var wire = new THREE.LineSegments(new THREE.EdgesGeometry(box.geometry), new THREE.LineBasicMaterial({ color: C.amber2 }));
    wire.position.y = 1.3;
    g.add(wire);
    var label = new Label(["sift-" + id, "running"], { scale: 0.55 });
    label.sprite.position.y = 4.3;
    g.add(label.sprite);
    g.scale.setScalar(0.01);
    this.scene.add(g);
    var job = { id: id, group: g, box: box, wire: wire, label: label, state: "running", age: 0 };
    this.jobs[id] = job;
    var self = this;
    var item = { update: function (dt, t) {
      job.age += dt;
      var s = Math.min(1, g.scale.x + dt * 4);
      if (job.state === "running") { box.rotation.y += dt * 0.6; box.material.emissiveIntensity = 0.5 + Math.abs(Math.sin(t * 4)) * 0.7; }
      if (job.state !== "running") {
        job.done = (job.done || 0) + dt;
        if (job.done > 30) { s = Math.max(0, 1 - (job.done - 30)); }
        if (job.done > 31) { self.scene.remove(g); item.dead = true; delete self.jobs[id]; }
      }
      g.scale.setScalar(Math.max(0.01, s));
    } };
    this.animated.push(item);
    return job;
  };

  SystemMap.prototype.endJob = function (id, rc, duration) {
    var job = this.jobs[id];
    if (!job) { return; }
    job.state = rc === 0 ? "ok" : "fail";
    var color = rc === 0 ? C.ok : C.bad;
    job.box.material.emissive.setHex(color);
    job.box.material.emissiveIntensity = 0.7;
    job.wire.material.color.setHex(color);
    job.label.set(["sift-" + id, "rc " + rc + " · " + fmtS(duration)]);
  };

  // ------------------------------------------------------------------ links and packets (real events only)

  SystemMap.prototype.anchor = function (x) {
    if (x === "core") { return CORE.clone().setY(5); }
    if (x === "vm") { return VM.clone().add(new THREE.Vector3(-12, 6.5, 0)); }
    if (x.indexOf("scanner:") === 0) {
      var s = this.scanners[x.slice(8)];
      return s ? s.group.position.clone().setY(s.height + 1) : CORE.clone();
    }
    if (x.indexOf("model:") === 0) {
      var m = this.models[x.slice(6)];
      return m ? m.group.position.clone().setY(4.8) : LLM.clone().setY(4);
    }
    if (x.indexOf("job:") === 0) {
      var j = this.jobs[x.slice(4)];
      return j ? j.group.position.clone().setY(3) : VM.clone().setY(3);
    }
    return CORE.clone();
  };

  SystemMap.prototype.link = function (a, b) {
    var key = a + ">" + b;
    if (this.links[key]) { return this.links[key]; }
    var from = this.anchor(a), to = this.anchor(b);
    var mid = from.clone().lerp(to, 0.5);
    mid.y += 4 + from.distanceTo(to) * 0.18;
    var curve = new THREE.QuadraticBezierCurve3(from, mid, to);
    var tube = new THREE.Mesh(new THREE.TubeGeometry(curve, 48, 0.07, 6, false),
      new THREE.MeshBasicMaterial({ color: 0x3a3426, transparent: true, opacity: 0.55 }));
    tube.userData.noPick = true;
    this.scene.add(tube);
    var l = this.links[key] = { curve: curve, tube: tube, heat: 0, length: curve.getLength() };
    return l;
  };

  var KIND = { scan: C.sky, llm: C.amber, reply: C.amber2, vm: C.ok, fail: C.bad, finding: 0xedeef0 };

  SystemMap.prototype.send = function (a, b, kind, size, count) {
    if (this.reduced) { this.link(a, b).heat = 1; return; }
    var self = this;
    for (var i = 0; i < (count || 1); i++) {
      (function (delay) { self.later(delay, function () { self.packet(self.link(a, b), KIND[kind] || C.amber, size || 0.4); }); })(i * 0.12);
    }
  };

  SystemMap.prototype.packet = function (l, color, size) {
    if (this.packets.length > 240) { return; }
    var head = new THREE.Mesh(new THREE.SphereGeometry(size, 16, 12), new THREE.MeshBasicMaterial({ color: color }));
    head.userData.noPick = true;
    var trail = [];
    for (var i = 0; i < 6; i++) {
      var s = new THREE.Mesh(new THREE.SphereGeometry(size * (0.8 - i * 0.11), 10, 8),
        new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.55 - i * 0.08 }));
      s.userData.noPick = true;
      trail.push(s); this.scene.add(s);
    }
    this.scene.add(head);
    l.heat = 1;
    this.packets.push({ link: l, head: head, trail: trail, u: 0, dur: 0.7 + l.length / 55 });
  };

  SystemMap.prototype.updatePackets = function (dt) {
    var self = this;
    this.packets = this.packets.filter(function (p) {
      p.u += dt / p.dur;
      var e = Math.min(1, p.u);
      e = e < 0.5 ? 2 * e * e : 1 - Math.pow(-2 * e + 2, 2) / 2;
      p.head.position.copy(p.link.curve.getPoint(e));
      p.trail.forEach(function (s, i) { s.position.copy(p.link.curve.getPoint(Math.max(0, e - 0.03 * (i + 1)))); });
      if (p.u < 1) { return true; }
      self.scene.remove(p.head);
      p.trail.forEach(function (s) { self.scene.remove(s); });
      p.head.geometry.dispose(); p.head.material.dispose();
      p.trail.forEach(function (s) { s.geometry.dispose(); s.material.dispose(); });
      return false;
    });
    Object.keys(this.links).forEach(function (k) {
      var l = self.links[k];
      l.heat = Math.max(0, l.heat - dt * 0.5);
      l.tube.material.color.setHex(0x3a3426).lerp(new THREE.Color(C.amber), l.heat * 0.8);
      l.tube.material.opacity = 0.35 + l.heat * 0.6;
    });
  };

  SystemMap.prototype.later = function (delay, fn) { (this.scheduled = this.scheduled || []).push({ at: this.time + delay, fn: fn }); };
  SystemMap.prototype.runScheduled = function () {
    if (!this.scheduled || !this.scheduled.length) { return; }
    var now = this.time, due = [];
    this.scheduled = this.scheduled.filter(function (s) { if (s.at <= now) { due.push(s); return false; } return true; });
    due.forEach(function (s) { s.fn(); });
  };

  SystemMap.prototype.placeFindings = function () {
    var inst = this.findingMesh, m = new THREE.Matrix4(), q = new THREE.Quaternion(), sc = new THREE.Vector3(1, 1, 1);
    var n = Math.min(this.findings.length, 400), t = this.time;
    for (var i = 0; i < n; i++) {
      var ring = Math.floor(i / 40), k = i % 40;
      var a = k / 40 * Math.PI * 2 + t * (0.12 + ring * 0.03) * (ring % 2 ? -1 : 1);
      var r = 5.4 + ring * 0.9;
      m.compose(new THREE.Vector3(CORE.x + Math.cos(a) * r, 4.2 + Math.sin(a * 3 + ring) * 0.35 + ring * 0.25, CORE.z + Math.sin(a) * r), q, sc);
      inst.setMatrixAt(i, m);
    }
    inst.count = n;
    inst.instanceMatrix.needsUpdate = true;
  };

  // ------------------------------------------------------------------ events

  SystemMap.prototype.handle = function (ev) { this.queue.push(ev); };

  SystemMap.prototype.drain = function (dt) {
    // A run opened after the fact (or a burst) is applied at once without packets; live events play.
    if (this.queue.length > 24) {
      while (this.queue.length) { this.apply(this.queue.shift(), false); }
      return;
    }
    this.gap = (this.gap || 0) - dt;
    while (this.queue.length && this.gap <= 0) {
      this.apply(this.queue.shift(), true);
      this.gap += 0.09;
    }
    if (this.gap < 0) { this.gap = 0; }
  };

  SystemMap.prototype.setTopology = function (topo) {
    this.topology = topo || {};
    var self = this;
    (this.topology.scanners || []).forEach(function (n) { self.ensureScanner(n); });
    var llm = this.topology.llm;
    if (llm && llm.model) {
      this.llm.label.set(["LLM gateway", llm.host || ""]);
      this.ensureModel(llm.model, "primary");
      if (llm.fallback) { this.ensureModel(llm.fallback, "fallback"); }
    }
    var vm = this.topology.vm;
    if (vm && vm.host) { this.vm.label.set(["Sandbox VM", (vm.user ? vm.user + "@" : "") + vm.host + " · " + vm.runtime, vm.image || ""]); }
  };

  SystemMap.prototype.apply = function (ev, animate) {
    var d = ev.data || {};
    var send = animate ? this.send.bind(this) : function (a, b) { var l = this.link(a, b); l.heat = Math.max(l.heat, 0.3); }.bind(this);
    switch (ev.type) {
      case "run.start":
        this.runKind = d.kind || "fix";
        this.setTopology(d.topology);
        this.coreLabel.set(["CodeSift", (d.kind || d.mode || "run") + " · " + (d.project || ""), "running"]);
        this.core.activity = 1;
        break;
      case "run.end":
        this.coreLabel.set(["CodeSift", (this.runKind || "run") + " finished", "exit " + d.exit_code + " · " + this.stats.findings + " findings"]);
        this.ended = true;
        break;
      case "scanner.start": {
        var s = this.ensureScanner(d.name);
        s.status = "running"; this.setScanner(s);
        send("core", "scanner:" + d.name, "scan", 0.45, 1);
        this.core.activity = Math.min(1, this.core.activity + 0.3);
        break;
      }
      case "scanner.result": {
        var r = this.ensureScanner(d.name);
        r.status = d.status === "ok" ? "ok" : d.status === "error" ? "error" : d.status === "skipped" ? "skipped" : d.status;
        r.findings = d.findings || 0; r.duration = d.duration_s || 0; r.version = d.version || ""; r.reason = d.reason || "";
        r.pulse = 1;
        this.setScanner(r);
        if (r.status !== "skipped") {
          this.stats.scanners += 1;
          send("scanner:" + d.name, "core", r.status === "error" ? "fail" : "scan", 0.4, Math.max(1, Math.min(10, Math.ceil(r.findings / 3))));
        }
        break;
      }
      case "finding.detected":
        this.findings.push({ id: ev.finding, severity: d.severity, path: d.path, tool: d.tool });
        this.stats.findings = this.findings.length;
        if (this.findings.length <= 400) {
          this.findingMesh.setColorAt(this.findings.length - 1, new THREE.Color(SEV[d.severity] || SEV.info));
          if (this.findingMesh.instanceColor) { this.findingMesh.instanceColor.needsUpdate = true; }
        }
        break;
      case "llm.request": {
        var m = this.ensureModel(d.model, this.topology && this.topology.llm && d.model === this.topology.llm.fallback ? "fallback" : "primary");
        m.inflight += 1;
        this.refreshModel(m);
        send("core", "model:" + d.model, "llm", 0.35 + Math.min(0.6, (d.prompt_chars || 0) / 12000), 1);
        this.core.activity = Math.min(1, this.core.activity + 0.25);
        break;
      }
      case "llm.response": {
        var mm = this.ensureModel(d.model, "primary");
        mm.inflight = Math.max(0, mm.inflight - 1);
        mm.calls += 1;
        if (!d.ok) { mm.failed += 1; mm.lastError = d.error || "failed"; this.stats.llmFailed += 1; }
        mm.tokensIn += d.tokens_in || 0; mm.tokensOut += d.tokens_out || 0;
        if (d.ok) { mm.latency += d.latency_s || 0; }
        this.stats.llmCalls += 1; this.stats.tokensIn += d.tokens_in || 0; this.stats.tokensOut += d.tokens_out || 0;
        this.refreshModel(mm);
        send("model:" + d.model, "core", d.ok ? "reply" : "fail", 0.35 + Math.min(0.6, (d.tokens_out || 0) / 1500), 1);
        break;
      }
      case "vm.command":
        this.stats.vmCommands += 1;
        this.vmHost.blink = 1.2; this.vmHost.last = d.op;
        if (d.op === "job" && d.job) {
          this.startJob(d.job);
          this.stats.vmJobs += 1;
          send("core", "vm", "vm", 0.45 + Math.min(0.5, (d.bytes_in || 0) / 400000), 1);
          var self = this;
          if (animate) { this.later(1.1, function () { self.send("vm", "job:" + d.job, "vm", 0.35, 1); }); }
        } else {
          send("core", "vm", "vm", 0.3, 1);
        }
        break;
      case "vm.result":
        this.vmHost.blink = 0.6;
        if (d.op === "job" && d.job) {
          this.endJob(d.job, d.rc, d.duration_s || 0);
          send("job:" + d.job, "vm", d.rc === 0 ? "vm" : "fail", 0.35, 1);
        }
        send("vm", "core", d.rc === 0 ? "vm" : "fail", 0.3, 1);
        break;
      case "fix.attempt": {
        var b = d.backend || "fixer";
        this.backends[b] = (this.backends[b] || 0) + 1;
        if (b !== "gateway") { this.ensureScanner(b === "claude-cli" ? "claude-cli" : b); }
        break;
      }
      case "error":
        this.coreLabel.set(["CodeSift", "error", (d.message || "").slice(0, 40)]);
        break;
      default:
        break;
    }
    if (this.opts.onStats) { this.opts.onStats(this.stats); }
  };

  SystemMap.prototype.info = function (pick) {
    var lines = [];
    if (pick.kind === "scanner") {
      var s = this.scanners[pick.key];
      lines.push("Scanner " + s.name + (s.version ? " " + s.version : ""));
      lines.push("Status: " + s.status + (s.reason ? " (" + s.reason + ")" : ""));
      lines.push("Findings: " + s.findings + " · time " + fmtS(s.duration));
    } else if (pick.kind === "model") {
      var m = this.models[pick.key];
      lines.push("Model " + m.id + (m.role === "fallback" ? " (fallback)" : ""));
      lines.push("Calls: " + m.calls + (m.failed ? " (" + m.failed + " failed" + (m.lastError ? ": " + m.lastError : "") + ")" : "") + " · in flight " + m.inflight);
      lines.push("Tokens: " + m.tokensIn + " in, " + m.tokensOut + " out");
      if (m.calls - m.failed > 0) { lines.push("Average answer time: " + fmtS(m.latency / (m.calls - m.failed))); }
    } else if (pick.kind === "vm") {
      var vm = (this.topology && this.topology.vm) || {};
      lines.push("Sandbox VM " + (vm.host || "(not configured)"));
      if (vm.runtime) { lines.push(vm.runtime + " · image " + vm.image); }
      lines.push("Commands: " + this.stats.vmCommands + " · jobs " + this.stats.vmJobs + (this.vmHost.last ? " · last: " + this.vmHost.last : ""));
    } else if (pick.kind === "llm") {
      var llm = (this.topology && this.topology.llm) || {};
      lines.push("LLM gateway " + (llm.host || "(not configured)"));
      lines.push("Calls: " + this.stats.llmCalls + " · tokens " + this.stats.tokensIn + " in, " + this.stats.tokensOut + " out");
    } else {
      var by = {};
      this.findings.forEach(function (f) { by[f.severity] = (by[f.severity] || 0) + 1; });
      lines.push("CodeSift on this machine");
      lines.push("Findings: " + this.findings.length + (this.findings.length ? " (" + Object.keys(by).map(function (k) { return by[k] + " " + k; }).join(", ") + ")" : ""));
      lines.push("Scanners finished: " + this.stats.scanners);
    }
    return lines;
  };

  SystemMap.prototype.describe = function () {
    var s = this.stats;
    return "System map. " + Object.keys(this.scanners).length + " scanner(s), " + s.findings + " finding(s), " +
      s.llmCalls + " LLM call(s), " + s.vmJobs + " sandbox job(s)" + (this.ended ? ". Run finished." : ".");
  };

  // ------------------------------------------------------------------ input, loop

  SystemMap.prototype.bindInput = function () {
    var el = this.renderer.domElement, o = this.orbit, self = this;
    el.addEventListener("pointerdown", function (e) { o.dragging = true; o.moved = 0; o.lastX = e.clientX; o.lastY = e.clientY; });
    this.onUp = function (e) { if (o.dragging && o.moved < 4) { self.pick(e); } o.dragging = false; };
    this.onMove = function (e) {
      if (!o.dragging) { return; }
      var dx = e.clientX - o.lastX, dy = e.clientY - o.lastY;
      o.moved += Math.abs(dx) + Math.abs(dy);
      o.azimuth -= dx * 0.005;
      o.polar = Math.min(1.35, Math.max(0.2, o.polar - dy * 0.003));
      o.lastX = e.clientX; o.lastY = e.clientY;
    };
    window.addEventListener("pointerup", this.onUp);
    window.addEventListener("pointermove", this.onMove);
    el.addEventListener("wheel", function (e) {
      e.preventDefault();
      o.dist = Math.min(220, Math.max(35, o.dist * (e.deltaY > 0 ? 1.1 : 0.9)));
    }, { passive: false });
    el.addEventListener("keydown", function (e) {
      if (e.key === "ArrowLeft") { o.azimuth += 0.1; }
      if (e.key === "ArrowRight") { o.azimuth -= 0.1; }
      if (e.key === "ArrowUp") { o.polar = Math.max(0.2, o.polar - 0.05); }
      if (e.key === "ArrowDown") { o.polar = Math.min(1.35, o.polar + 0.05); }
      if (e.key === "+" || e.key === "=") { o.dist = Math.max(35, o.dist * 0.9); }
      if (e.key === "-") { o.dist = Math.min(220, o.dist * 1.1); }
    });
  };

  SystemMap.prototype.pick = function (e) {
    var rect = this.renderer.domElement.getBoundingClientRect();
    var mouse = new THREE.Vector2(((e.clientX - rect.left) / rect.width) * 2 - 1, -((e.clientY - rect.top) / rect.height) * 2 + 1);
    this.raycaster.setFromCamera(mouse, this.camera);
    var hits = this.raycaster.intersectObjects(this.pickables, true);
    for (var i = 0; i < hits.length; i++) {
      var p = hits[i].object.userData.pick;
      if (p && this.selectCb) { this.selectCb(p, this.info(p)); return; }
    }
  };

  SystemMap.prototype.onSelect = function (cb) { this.selectCb = cb; };
  SystemMap.prototype.setPaused = function (p) { this.paused = p; };
  SystemMap.prototype.setSpeed = function (s) { this.speed = s; };

  SystemMap.prototype.dispose = function () {
    this.disposed = true;
    window.removeEventListener("resize", this.onResize);
    window.removeEventListener("pointerup", this.onUp);
    window.removeEventListener("pointermove", this.onMove);
    this.renderer.dispose();
    if (this.renderer.domElement.parentNode) { this.renderer.domElement.parentNode.removeChild(this.renderer.domElement); }
  };

  SystemMap.prototype.loop = function () {
    var self = this;
    var frame = function () {
      if (self.disposed) { return; }
      requestAnimationFrame(frame);
      var raw = Math.min(self.clock.getDelta(), 0.1);
      if (!self.paused) {
        var dt = raw * self.speed;
        self.time += dt;
        self.drain(dt);
        self.runScheduled();
        self.animated = self.animated.filter(function (a) { return !a.dead; });
        self.animated.forEach(function (a) { a.update(dt, self.time); });
        self.updatePackets(dt);
        self.placeFindings();
        if (!self.orbit.dragging && !self.reduced) { self.orbit.azimuth += raw * 0.025; }
      }
      var o = self.orbit, tg = self.target;
      self.camera.position.set(tg.x + Math.sin(o.polar) * Math.cos(o.azimuth) * o.dist, tg.y + Math.cos(o.polar) * o.dist,
        tg.z + Math.sin(o.polar) * Math.sin(o.azimuth) * o.dist);
      self.camera.lookAt(tg);
      if (self.composer) { self.composer.render(); } else { self.renderer.render(self.scene, self.camera); }
    };
    frame();
  };

  window.SiftMap = { available: available, create: function (el, opts) { return new SystemMap(el, opts); } };
})();
