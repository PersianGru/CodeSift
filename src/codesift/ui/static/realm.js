/* CodeSift UI: the fantasy 3D view. The run is a small realm drawn from window.SiftWorld:
   - the CodeSift castle is this machine; each scanner is a hero who rides out when it starts and comes
     back when it reports; skeletons rise in the wilds for each finding (bigger and meaner by severity);
   - the oracle tower is the LLM gateway, one oracle per model; a raven of light is one real call;
   - the dungeon is the sandbox VM; a lit cell is one real job.
   Nothing moves without a real event. Models: KayKit by Kay Lousberg (CC0). */
(function () {
  "use strict";

  var THREE = window.THREE;
  var W = window.SiftWorld;
  if (!THREE || !THREE.GLTFLoader || !THREE.SkeletonUtils) { window.SiftRealm = { available: function () { return false; } }; return; }

  var ASSET = "/static/vendor/kaykit-";
  var HERO_MODEL = { Rogue: "rogue", Mage: "mage", Ranger: "ranger", Knight: "knight", Barbarian: "barbarian", Scout: "rogue_hooded",
    Cleric: "mage", Alchemist: "mage", Bard: "rogue", Monk: "barbarian", Squire: "knight", Champion: "knight" };
  var LOADOUT = {
    Rogue: { r: "dagger", l: "dagger" }, Mage: { r: "staff" }, Ranger: { l: "bow_withString" }, Knight: { r: "sword_1handed", l: "shield_badge_color" },
    Barbarian: { r: "axe_2handed" }, Scout: { r: "crossbow_1handed" }, Cleric: { r: "wand", l: "spellbook_open" }, Alchemist: { r: "mug_full" },
    Bard: { r: "dagger" }, Monk: {}, Squire: { r: "sword_1handed" }, Champion: { r: "sword_1handed", l: "shield_badge_color" }
  };
  var ATTACK = { Rogue: "Lockpicking", Mage: "Ranged_Magic_Spellcasting", Ranger: "Ranged_Bow_Draw", Knight: "Melee_1H_Attack_Chop",
    Barbarian: "Melee_2H_Attack_Spin", Scout: "Interact", Cleric: "Ranged_Magic_Spellcasting", Alchemist: "Use_Item", Bard: "Melee_1H_Attack_Chop",
    Monk: "Melee_2H_Attack_Spin", Squire: "Melee_1H_Attack_Chop", Champion: "Melee_1H_Attack_Chop" };
  var FOE = {
    critical: { model: "skeleton_mage", scale: 1.35, r: "Skeleton_Staff", glow: 0xff3b3b },
    high: { model: "skeleton_warrior", scale: 1.1, r: "Skeleton_Blade", l: "Skeleton_Shield_Small_A", glow: 0xff7a5c },
    medium: { model: "skeleton_rogue", scale: 1.0, r: "Skeleton_Axe", glow: 0xf5a524 },
    low: { model: "skeleton_minion", scale: 0.9, glow: 0x7aa2ff },
    info: { model: "skeleton_minion", scale: 0.75, glow: 0x9aa0aa }
  };
  var SPARK = { scan: 0x78e6c8, llm: 0xb69cff, reply: 0xffd36e, vm: 0x5abeff, fail: 0xff4d4d };
  var PLACES = { core: new THREE.Vector3(0, 0, 0), tower: new THREE.Vector3(34, 0, -10), dungeon: new THREE.Vector3(-34, 0, -10), wilds: new THREE.Vector3(0, 0, 24) };
  var MAX_FOES = 60;

  function available() {
    try { var c = document.createElement("canvas"); return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl"))); }
    catch (e) { return false; }
  }

  // ------------------------------------------------------------------ assets (shared across views)

  var assets = null;
  function loadAssets() {
    if (assets) { return assets; }
    var loader = new THREE.GLTFLoader();
    function glb(name) { return new Promise(function (ok, fail) { loader.load(ASSET + name + ".glb", ok, undefined, fail); }); }
    var names = ["knight", "barbarian", "mage", "ranger", "rogue", "rogue_hooded", "skeleton_warrior", "skeleton_mage", "skeleton_rogue", "skeleton_minion"];
    assets = Promise.all([glb("anims"), glb("props")].concat(names.map(glb))).then(function (all) {
      var out = { clips: {}, props: {}, models: {} };
      all[0].animations.forEach(function (c) { out.clips[c.name] = c; });
      all[1].scene.children.forEach(function (n) { out.props[n.name] = n; });
      names.forEach(function (n, i) {
        var scene = all[i + 2].scene;
        scene.traverse(function (o) { if (o.isMesh) { o.castShadow = true; o.receiveShadow = true; } });
        out.models[n] = scene;
      });
      Object.keys(out.props).forEach(function (k) {
        out.props[k].traverse(function (o) { if (o.isMesh) { o.castShadow = true; o.receiveShadow = true; } });
      });
      return out;
    });
    return assets;
  }

  var glowTex = null;
  function glowTexture() {
    if (glowTex) { return glowTex; }
    var c = document.createElement("canvas"); c.width = c.height = 64;
    var g = c.getContext("2d"), grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
    grad.addColorStop(0, "rgba(255,255,255,1)"); grad.addColorStop(0.25, "rgba(255,255,255,0.75)");
    grad.addColorStop(0.6, "rgba(255,255,255,0.18)"); grad.addColorStop(1, "rgba(255,255,255,0)");
    g.fillStyle = grad; g.fillRect(0, 0, 64, 64);
    glowTex = new THREE.CanvasTexture(c);
    return glowTex;
  }
  function glow(color, size, opacity) {
    var m = new THREE.SpriteMaterial({ map: glowTexture(), color: color, transparent: true, opacity: opacity === undefined ? 1 : opacity,
      blending: THREE.AdditiveBlending, depthWrite: false });
    var s = new THREE.Sprite(m); s.scale.set(size, size, 1);
    return s;
  }

  // ------------------------------------------------------------------ an animated character

  function Actor(realm, model, scale, loadout) {
    this.realm = realm;
    this.root = new THREE.Group();
    this.body = THREE.SkeletonUtils.clone(realm.assets.models[model]);
    this.body.scale.setScalar(scale || 1);
    this.root.add(this.body);
    this.mixer = new THREE.AnimationMixer(this.body);
    this.actions = {}; this.current = null; this.speed = 1;
    var self = this;
    ["r", "l"].forEach(function (side) {
      var name = loadout && loadout[side];
      var slot = self.body.getObjectByName(side === "r" ? "handslotr" : "handslotl");
      if (name && slot && realm.assets.props[name]) { slot.add(realm.assets.props[name].clone()); }
    });
  }
  Actor.prototype.action = function (name) {
    if (!this.actions[name]) {
      var clip = this.realm.assets.clips[name];
      if (!clip) { return null; }
      this.actions[name] = this.mixer.clipAction(clip);
    }
    return this.actions[name];
  };
  Actor.prototype.play = function (name, opts) {
    opts = opts || {};
    if (this.currentName === name && !opts.restart) { return; }
    var next = this.action(name);
    if (!next) { return; }
    next.reset();
    next.setLoop(opts.once ? THREE.LoopOnce : THREE.LoopRepeat, Infinity);
    next.clampWhenFinished = !!opts.once;
    next.timeScale = opts.timeScale || 1;
    next.play();
    if (this.current && this.current !== next) { this.current.crossFadeTo(next, opts.fade === undefined ? 0.25 : opts.fade, false); }
    this.current = next; this.currentName = name;
  };
  Actor.prototype.update = function (dt) { this.mixer.update(dt); };
  Actor.prototype.faceTo = function (p, dt) {
    var dx = p.x - this.root.position.x, dz = p.z - this.root.position.z;
    if (dx * dx + dz * dz < 1e-4) { return; }
    var want = Math.atan2(dx, dz), cur = this.root.rotation.y;
    var diff = Math.atan2(Math.sin(want - cur), Math.cos(want - cur));
    this.root.rotation.y = cur + diff * Math.min(1, dt * 8);
  };
  Actor.prototype.walkTo = function (p, dt, speed) {
    var pos = this.root.position, dx = p.x - pos.x, dz = p.z - pos.z, d = Math.sqrt(dx * dx + dz * dz);
    if (d < 0.25) { return true; }
    var step = Math.min(d, (speed || 7) * dt);
    pos.x += dx / d * step; pos.z += dz / d * step;
    this.faceTo(p, dt);
    return false;
  };

  // ------------------------------------------------------------------ the realm

  function Realm(container) {
    this.el = container;
    this.world = W.create();
    this.time = 0; this.speed = 1; this.paused = false;
    this.heroes = {}; this.foes = {}; this.oracles = {}; this.cells = []; this.sparks = []; this.labels = [];
    this.pickables = []; this.flickers = [];
    this.reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var self = this;
    this.pacer = new W.Pacer(this.world, function (fx, animate) { self.effects(fx, animate); });
    this.initRenderer();
    this.overlay = document.createElement("div");
    this.overlay.className = "realm-labels";
    container.appendChild(this.overlay);
    this.loading = this.label(new THREE.Vector3(0, 6, 0), "Summoning the realm…", "", "realm-loading");
    this.clock = new THREE.Clock();
    this.loop();
    loadAssets().then(function (a) {
      if (self.disposed) { return; }
      self.assets = a;
      self.removeLabel(self.loading);
      self.build();
      self.ready = true;
      self.reconcile(true);
    }).catch(function () {
      if (self.loading) { self.loading.title.textContent = "Could not load the realm's models."; }
    });
  }

  Realm.prototype.initRenderer = function () {
    var r = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
    r.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
    r.outputEncoding = THREE.sRGBEncoding;
    r.toneMapping = THREE.ACESFilmicToneMapping;
    r.toneMappingExposure = 1.05;
    r.shadowMap.enabled = true;
    r.shadowMap.type = THREE.PCFSoftShadowMap;
    r.domElement.tabIndex = 0;
    r.domElement.setAttribute("aria-label", "Fantasy 3D view of the run");
    this.el.appendChild(r.domElement);
    this.renderer = r;
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(0x0a0f1c);
    this.scene.fog = new THREE.FogExp2(0x0a0f1c, 0.0105);
    this.camera = new THREE.PerspectiveCamera(42, 1, 0.5, 600);
    this.orbit = { azimuth: 1.05, polar: 0.92, dist: 74, dragging: false };
    this.target = new THREE.Vector3(0, 2, 6);
    this.raycaster = new THREE.Raycaster();
    var self = this;
    this.onResize = function () { self.resize(); };
    window.addEventListener("resize", this.onResize);
    this.resize();
    this.bindInput();
    this.buildSky();
  };

  Realm.prototype.resize = function () {
    var w = Math.max(320, this.el.clientWidth), h = Math.max(240, this.el.clientHeight);
    this.renderer.setSize(w, h, false);
    this.renderer.domElement.style.width = w + "px"; this.renderer.domElement.style.height = h + "px";
    this.camera.aspect = w / h; this.camera.updateProjectionMatrix();
    this.w = w; this.h = h;
  };

  Realm.prototype.buildSky = function () {
    var s = this.scene;
    s.add(new THREE.HemisphereLight(0x8ea6ff, 0x2a1c12, 0.55));
    var moon = new THREE.DirectionalLight(0xc4d0ff, 1.15);
    moon.position.set(-40, 70, 35);
    moon.castShadow = true;
    moon.shadow.mapSize.set(2048, 2048);
    var sc = moon.shadow.camera; sc.left = -60; sc.right = 60; sc.top = 50; sc.bottom = -50; sc.near = 10; sc.far = 200;
    moon.shadow.bias = -0.0006; moon.shadow.normalBias = 0.03;
    s.add(moon);
    var warm = new THREE.DirectionalLight(0xffb070, 0.35);
    warm.position.set(30, 20, 60);
    s.add(warm);
    var ground = new THREE.Mesh(new THREE.CircleGeometry(170, 64), new THREE.MeshStandardMaterial({ color: 0x1b2216, roughness: 1 }));
    ground.rotation.x = -Math.PI / 2; ground.position.y = -0.12; ground.receiveShadow = true;
    s.add(ground);
    var starGeo = new THREE.BufferGeometry(), pts = [];
    for (var i = 0; i < 700; i++) {
      var th = Math.random() * Math.PI * 2, ph = Math.random() * 0.45 * Math.PI, r = 380;
      pts.push(r * Math.sin(ph) * Math.cos(th), r * Math.cos(ph) * 0.9 + 20, r * Math.sin(ph) * Math.sin(th));
    }
    starGeo.setAttribute("position", new THREE.Float32BufferAttribute(pts, 3));
    s.add(new THREE.Points(starGeo, new THREE.PointsMaterial({ color: 0xbfcaff, size: 1.3, sizeAttenuation: false, fog: false })));
  };

  Realm.prototype.prop = function (name, x, y, z, rotY, parent) {
    var src = this.assets.props[name];
    if (!src) { return null; }
    var o = src.clone();
    o.position.set(x, y || 0, z);
    o.rotation.y = rotY || 0;
    (parent || this.scene).add(o);
    return o;
  };

  Realm.prototype.torch = function (x, y, z, rotY, parent, light) {
    this.prop("torch_mounted", x, y, z, rotY, parent);
    var flame = glow(0xff9a3c, 2.2, 0.9);
    var off = new THREE.Vector3(Math.sin(rotY || 0) * 0.35, 0.75, Math.cos(rotY || 0) * 0.35);
    flame.position.set(x + off.x, (y || 0) + off.y, z + off.z);
    (parent || this.scene).add(flame);
    var item = { flame: flame, seed: Math.random() * 10 };
    if (light) {
      var l = new THREE.PointLight(0xff8a35, 1.6, 18, 2);
      l.position.copy(flame.position);
      (parent || this.scene).add(l);
      item.light = l;
    }
    this.flickers.push(item);
  };

  Realm.prototype.pickBox = function (obj, w, h, d, pick, y) {
    var m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), new THREE.MeshBasicMaterial({ visible: false }));
    m.position.y = y === undefined ? h / 2 : y;
    m.userData.pick = pick;
    obj.add(m);
    this.pickables.push(m);
    return m;
  };

  Realm.prototype.build = function () {
    var self = this, i, j;
    // --- the castle: a walled courtyard with the CodeSift crystal in the middle
    var castle = new THREE.Group(); this.scene.add(castle);
    for (i = -2; i <= 2; i++) { for (j = -2; j <= 2; j++) { this.prop("floor_tile_large", i * 4, 0, j * 4, 0, castle); } }
    for (i = -2; i <= 2; i++) {
      this.prop(i === 0 ? "wall_arched" : "wall", i * 4, 0, -10.5, 0, castle);
      if (i !== 0) { this.prop("wall", i * 4, 0, 10.5, Math.PI, castle); } // the gate is the gap in the middle
      this.prop("wall", -10.5, 0, i * 4, Math.PI / 2, castle);
      this.prop("wall", 10.5, 0, i * 4, -Math.PI / 2, castle);
    }
    [[-10.5, -10.5], [10.5, -10.5], [-10.5, 10.5], [10.5, 10.5]].forEach(function (p) { self.prop("pillar", p[0], 0, p[1], 0, castle); });
    this.prop("pillar", -2.4, 0, 10.5, 0, castle);
    this.prop("pillar", 2.4, 0, 10.5, 0, castle);
    this.prop("banner_patternA_red", -4, 0, -10.0, 0, castle);
    this.prop("banner_shield_yellow", 4, 0, -10.0, 0, castle);
    this.prop("banner_patternA_red", -10.0, 0, -4, Math.PI / 2, castle);
    this.prop("banner_patternA_red", 10.0, 0, 4, -Math.PI / 2, castle);
    this.torch(-8, 2.2, -9.95, 0, castle, true);
    this.torch(8, 2.2, -9.95, 0, castle, true);
    this.torch(-2.4, 2.4, 11.3, 0, castle, true);
    this.torch(2.4, 2.4, 11.3, 0, castle, false);
    this.prop("barrel_large", -8.2, 0, -8.2, 0.3, castle);
    this.prop("barrel_small_stack", 8.0, 0, -8.4, -0.4, castle);
    this.prop("crates_stacked", 8.2, 0, 8.0, 0.2, castle);
    this.prop("chest_gold", -7.6, 0, 7.8, 0.7, castle);
    this.prop("coin_stack_large", -8.6, 0, 5.8, 0, castle);
    // the crystal
    this.prop("column", 0, 0, 0, 0, castle);
    var crystal = new THREE.Mesh(new THREE.OctahedronGeometry(0.9, 0),
      new THREE.MeshStandardMaterial({ color: 0xffc457, emissive: 0xff9d1f, emissiveIntensity: 1.6, roughness: 0.25, metalness: 0.1 }));
    crystal.position.set(0, 2.7, 0); crystal.castShadow = true; castle.add(crystal);
    var halo = glow(0xffb340, 6, 0.75); halo.position.copy(crystal.position); castle.add(halo);
    var coreLight = new THREE.PointLight(0xffb048, 2.2, 22, 2); coreLight.position.set(0, 3.2, 0); castle.add(coreLight);
    this.core = { crystal: crystal, halo: halo, light: coreLight, activity: 0 };
    this.pickBox(castle, 4, 5, 4, { kind: "core" });
    this.coreLabel = this.label(new THREE.Vector3(0, 5.2, 0), "CodeSift castle", "this machine · waiting for a run");

    // --- the wilds: the project, where findings rise as skeletons
    for (i = -2; i <= 2; i++) { for (j = 0; j < 4; j++) { this.prop((i + j) % 3 === 0 ? "floor_tile_large_rocks" : "floor_dirt_large", i * 4, -0.02, 14 + j * 4, 0); } }
    this.prop("rubble_large", -13, 0, 22, 0.6);
    this.prop("rubble_large", 13.5, 0, 27, -0.4);
    this.prop("keg_decorated", 12, 0, 15, 0.5);
    this.torch(-9.6, 0, 13, 0, null, false);
    this.prop("torch_lit", -9.6, 0, 30, 0); this.prop("torch_lit", 9.6, 0, 30, 0);
    var wl = new THREE.PointLight(0xff8a35, 1.2, 20, 2); wl.position.set(0, 3, 30); this.scene.add(wl);
    this.label(new THREE.Vector3(0, 0.5, 33), "The wilds", "your project · findings rise here", "realm-place");

    // --- the oracle tower: the LLM gateway
    var tower = new THREE.Group(); tower.position.copy(PLACES.tower); this.scene.add(tower);
    for (i = -1; i <= 1; i++) { for (j = -1; j <= 1; j++) { this.prop("floor_tile_large", i * 4, 0, j * 4, 0, tower); } }
    this.prop("pillar", 0, 0, -2, 0, tower); this.prop("pillar", 0, 4, -2, 0, tower); this.prop("pillar", 0, 8, -2, 0, tower);
    this.prop("pillar_decorated", 0, 12, -2, 0, tower);
    this.prop("banner_patternA_blue", -1.6, 2, -1.2, 0, tower);
    this.prop("banner_thin_green", 1.6, 6, -1.2, 0, tower);
    this.prop("shelf_small_candles", 3.6, 1.2, -5.4, 0, tower);
    this.prop("table_medium", -3.6, 0, 3, 0.4, tower);
    this.prop("candle_triple", -3.6, 1, 3, 0, tower);
    this.torch(-5.5, 2, -5.4, 0, tower, true);
    this.torch(5.5, 2, -5.4, 0, tower, false);
    this.towerTop = new THREE.Vector3(0, 17.5, -2).add(PLACES.tower);
    this.pickBox(tower, 6, 17, 6, { kind: "llm" }, 8.5);
    var llm = this.world.topology.llm || {};
    this.towerLabel = this.label(this.towerTop.clone().add(new THREE.Vector3(0, 3, 0)), "Oracle tower", "LLM gateway · " + (llm.host || "not set up"));

    // --- the dungeon: the sandbox VM, one cell per job
    var dun = new THREE.Group(); dun.position.copy(PLACES.dungeon); this.scene.add(dun);
    for (i = -1; i <= 1; i++) { for (j = -1; j <= 1; j++) { this.prop("floor_tile_large", i * 4, 0, j * 4, 0, dun); } }
    for (i = -1; i <= 1; i++) {
      this.prop("wall", i * 4, 0, -6.5, 0, dun);
      this.prop("wall_gated", -6.5, 0, i * 4, Math.PI / 2, dun);
      this.prop("wall_gated", 6.5, 0, i * 4, -Math.PI / 2, dun);
    }
    this.prop("stairs", 0, 0, -10.5, 0, dun);
    this.prop("keyring_hanging", 0, 3.4, -5.9, 0, dun);
    this.prop("sword_shield", -3.8, 2.2, -5.95, 0, dun);
    this.torch(-4, 2.2, -5.95, 0, dun, true);
    this.torch(4, 2.2, -5.95, 0, dun, false);
    var cellSpots = [[-6.5, -4], [-6.5, 0], [-6.5, 4], [6.5, -4], [6.5, 0], [6.5, 4]];
    cellSpots.forEach(function (c) {
      var g = glow(0x5abeff, 5, 0); g.position.set(c[0] * 0.82, 2, c[1]); dun.add(g);
      self.cells.push({ glow: g, job: null, flash: 0, color: new THREE.Color(0x5abeff) });
    });
    this.pickBox(dun, 14, 5, 14, { kind: "vm" });
    var vm = this.world.topology.vm || {};
    this.dungeonLabel = this.label(PLACES.dungeon.clone().add(new THREE.Vector3(0, 6.5, 0)), "The dungeon", "sandbox VM · " + (vm.host || "not set up"));

    // a path of tiles from the castle to the tower and the dungeon
    for (i = 3; i <= 5; i++) { this.prop("floor_dirt_large", i * 4, -0.03, -4, 0); this.prop("floor_dirt_large", -i * 4, -0.03, -4, 0); }
  };

  // ------------------------------------------------------------------ labels (DOM: crisp at any zoom)

  Realm.prototype.label = function (pos, title, sub, cls) {
    var el = document.createElement("div");
    el.className = "realm-label" + (cls ? " " + cls : "");
    var t = document.createElement("strong"); t.textContent = title; el.appendChild(t);
    var s = document.createElement("span"); s.textContent = sub || ""; el.appendChild(s);
    this.overlay.appendChild(el);
    var l = { el: el, title: t, sub: s, pos: pos, follow: null, offset: 0 };
    this.labels.push(l);
    return l;
  };
  Realm.prototype.removeLabel = function (l) {
    if (!l) { return; }
    if (l.el.parentNode) { l.el.parentNode.removeChild(l.el); }
    this.labels = this.labels.filter(function (x) { return x !== l; });
  };
  Realm.prototype.setLabel = function (l, title, sub) {
    if (l.title.textContent !== title) { l.title.textContent = title; }
    if (l.sub.textContent !== (sub || "")) { l.sub.textContent = sub || ""; }
  };
  Realm.prototype.placeLabels = function () {
    var v = new THREE.Vector3(), self = this;
    this.labels.forEach(function (l) {
      if (l.follow) { v.copy(l.follow.position); v.y += l.offset; } else { v.copy(l.pos); }
      v.project(self.camera);
      var hide = v.z > 1 || l.hidden;
      l.el.style.display = hide ? "none" : "";
      if (!hide) { l.el.style.transform = "translate(-50%,-100%) translate(" + ((v.x + 1) / 2 * self.w).toFixed(1) + "px," + ((1 - v.y) / 2 * self.h).toFixed(1) + "px)"; }
    });
  };

  // ------------------------------------------------------------------ entities from the world

  function campSpot(i, n) {
    var a = -Math.PI * 0.85 + (Math.PI * 1.7) * (n <= 1 ? 0.5 : i / (n - 1));
    return new THREE.Vector3(Math.sin(a) * 7.2, 0, Math.cos(a) * 7.2 * 0.85);
  }
  function wildSpot(i) {
    var col = i % 5, row = Math.floor(i / 5) % 3;
    return new THREE.Vector3(-8 + col * 4, 0, 15 + row * 4.5);
  }
  function foeSpot(i) {
    var col = i % 10, row = Math.floor(i / 10);
    return new THREE.Vector3(-9 + col * 2 + (row % 2) * 1, 0, 19 + row * 2.4);
  }

  Realm.prototype.hero = function (key, name, cls) {
    if (this.heroes[key]) { return this.heroes[key]; }
    var a = new Actor(this, HERO_MODEL[cls] || "knight", 1, LOADOUT[cls]);
    a.cls = cls; a.key = key; a.name = name;
    this.scene.add(a.root);
    a.label = this.label(null, name, cls);
    a.label.follow = a.root; a.label.offset = 3.1;
    this.pickBox(a.root, 1.6, 2.6, 1.6, key.indexOf("scanner:") === 0 ? { kind: "scanner", key: name } : { kind: "core" });
    a.play("Idle_A");
    this.heroes[key] = a;
    this.layoutHeroes(true);
    return a;
  };

  Realm.prototype.layoutHeroes = function (teleport) {
    var keys = Object.keys(this.heroes), self = this;
    keys.forEach(function (k, i) {
      var h = self.heroes[k];
      h.camp = campSpot(i, keys.length);
      h.wild = wildSpot(i);
      if (teleport && !h.placed) { h.root.position.copy(h.camp); h.root.rotation.y = Math.atan2(h.camp.x, h.camp.z); h.placed = true; }
    });
  };

  Realm.prototype.foe = function (f, index) {
    if (this.foes[f.id]) { return this.foes[f.id]; }
    var spec = FOE[f.severity] || FOE.info;
    var a = new Actor(this, spec.model, spec.scale, { r: spec.r, l: spec.l });
    a.finding = f; a.spot = foeSpot(index);
    a.root.position.copy(a.spot);
    a.root.rotation.y = Math.PI + (Math.random() - 0.5) * 0.6;
    var ring = glow(spec.glow, 3.4 * spec.scale, 0.55); ring.position.y = 0.2; a.root.add(ring); a.ring = ring;
    this.scene.add(a.root);
    this.pickBox(a.root, 1.4, 2.4 * spec.scale, 1.4, { kind: "finding", key: f.id });
    this.foes[f.id] = a;
    return a;
  };

  Realm.prototype.oracle = function (id, i, n) {
    if (this.oracles[id]) { return this.oracles[id]; }
    var m = this.world.models[id];
    var a = new Actor(this, m && m.role === "fallback" ? "rogue_hooded" : "mage", 1, m && m.role === "fallback" ? { r: "wand" } : { r: "staff", l: "spellbook_open" });
    a.root.position.copy(PLACES.tower).add(new THREE.Vector3(-3 + (n > 1 ? i * 6 / (n - 1) : 3), 0, 3.4));
    a.root.rotation.y = -0.6;
    this.scene.add(a.root);
    var orb = new THREE.Mesh(new THREE.SphereGeometry(0.75, 24, 16),
      new THREE.MeshStandardMaterial({ color: 0xcdbdff, emissive: 0x7b5cff, emissiveIntensity: 1.1, roughness: 0.15 }));
    orb.position.copy(this.towerTop).add(new THREE.Vector3((i - (n - 1) / 2) * 2.4, 0, 0));
    this.scene.add(orb);
    var halo = glow(0x9d7bff, 4, 0.6); halo.position.copy(orb.position); this.scene.add(halo);
    a.orb = orb; a.halo = halo; a.id = id;
    a.label = this.label(null, m ? m.name : W.short(id), m && m.role === "fallback" ? "fallback oracle" : "oracle");
    a.label.follow = a.root; a.label.offset = 3.1;
    this.pickBox(a.root, 1.6, 2.6, 1.6, { kind: "model", key: id });
    a.play("Idle_B");
    this.oracles[id] = a;
    return a;
  };

  /* Make the scene match the world. `instant`: a burst or a run opened after the fact - place
     everything where it belongs without walking. */
  Realm.prototype.reconcile = function (instant) {
    if (!this.ready) { return; }
    var wd = this.world, self = this;
    wd.scannerOrder.forEach(function (n) { self.hero("scanner:" + n, n, (wd.scanners[n] || {}).cls || "Squire"); });
    Object.keys(wd.backends).forEach(function (b) { self.hero("backend:" + b, b, "Champion"); });
    wd.modelOrder.forEach(function (id, i) { self.oracle(id, i, wd.modelOrder.length); });
    wd.findings.slice(0, MAX_FOES).forEach(function (f, i) {
      var isNew = !self.foes[f.id];
      var a = self.foe(f, i);
      if (isNew && !instant) { a.play("Skeletons_Awaken_Floor", { once: true, fade: 0 }); a.risingUntil = self.time + 2.2; }
      else if (isNew) { a.play(f.outcome && f.outcome.indexOf("fixed") === 0 ? "Skeletons_Death_Pose" : "Skeletons_Idle", { fade: 0 }); }
    });
    var llm = wd.topology.llm || {}, vm = wd.topology.vm || {};
    if (this.towerLabel) { this.setLabel(this.towerLabel, "Oracle tower", "LLM gateway · " + (llm.host || "not set up")); }
    if (this.dungeonLabel) { this.setLabel(this.dungeonLabel, "The dungeon", "sandbox VM · " + (vm.host || "not set up") + (wd.kind === "scan" ? " · scans never enter" : "")); }
    if (instant) {
      Object.keys(this.heroes).forEach(function (k) {
        var h = self.heroes[k], s = k.indexOf("scanner:") === 0 ? wd.scanners[h.name] : null;
        var out = s && s.status === "running";
        h.root.position.copy(out ? h.wild : h.camp);
      });
    }
    this.refreshCore();
  };

  Realm.prototype.refreshCore = function () {
    var wd = this.world;
    if (!this.coreLabel) { return; }
    var sub = !wd.kind ? "this machine · waiting for a run" : wd.ended ? (wd.kind + " finished · exit " + wd.exitCode + " · " + wd.findings.length + " findings")
      : (wd.kind + " · " + wd.project + " · " + wd.findings.length + " findings");
    this.setLabel(this.coreLabel, "CodeSift castle", sub);
  };

  // ------------------------------------------------------------------ effects of real events

  Realm.prototype.anchor = function (key) {
    if (key === "core") { return new THREE.Vector3(0, 3, 0); }
    if (key === "vm") { return PLACES.dungeon.clone().add(new THREE.Vector3(0, 3, 0)); }
    if (key.indexOf("model:") === 0) { var o = this.oracles[key.slice(6)]; return o ? o.orb.position.clone() : this.towerTop.clone(); }
    if (key.indexOf("scanner:") === 0) { var h = this.heroes[key]; return h ? h.root.position.clone().add(new THREE.Vector3(0, 2, 0)) : new THREE.Vector3(0, 3, 0); }
    return new THREE.Vector3(0, 3, 0);
  };

  Realm.prototype.spark = function (from, to, kind, size, delay) {
    var color = SPARK[kind] || 0xffc457;
    var head = glow(color, 1.6 + (size || 0) * 1.8, 1);
    var trail = [];
    for (var i = 0; i < 6; i++) { var t = glow(color, (1.2 + (size || 0)) * (1 - i * 0.13), 0.55 - i * 0.08); trail.push(t); this.scene.add(t); t.visible = false; }
    this.scene.add(head); head.visible = false;
    var a = this.anchor(from), b = this.anchor(to);
    var mid = a.clone().add(b).multiplyScalar(0.5); mid.y += 6 + a.distanceTo(b) * 0.18;
    this.sparks.push({ head: head, trail: trail, curve: new THREE.QuadraticBezierCurve3(a, mid, b), t: -(delay || 0), dur: 0.9 + a.distanceTo(b) / 45 });
  };

  Realm.prototype.effects = function (fx, animate) {
    if (!this.ready) { return; }
    var self = this;
    this.reconcile(!animate);
    if (!animate) { return; }
    fx.forEach(function (e) {
      if (e.from && e.to) {
        var n = Math.min(e.count || 1, 6);
        for (var i = 0; i < n; i++) { self.spark(e.from, e.to, e.kind, e.size, i * 0.15); }
      }
      if (e.kind === "llm" || e.kind === "scan" || e.kind === "vm") { self.core.activity = Math.min(1, self.core.activity + 0.35); }
      if (e.kind === "vm" && e.job && e.start) {
        var cell = self.cells.filter(function (c) { return !c.job; })[0] || self.cells[0];
        cell.job = e.job; cell.color.setHex(0x5abeff); cell.flash = 0;
      }
      if (e.job && e.end) {
        self.cells.forEach(function (c) {
          if (c.job === e.job) { c.job = null; c.flash = 1; c.color.setHex(e.kind === "fail" ? 0xff4d4d : 0x5ed68c); }
        });
      }
      if (e.kind === "outcome" && self.foes[e.finding.id]) {
        self.foes[e.finding.id].play(e.won ? "Skeletons_Death" : "Skeletons_Taunt", { once: true });
      }
      if (e.kind === "end") {
        self.endedAt = self.time;
        Object.keys(self.heroes).forEach(function (k) { if (e.ok) { self.heroes[k].cheerUntil = self.time + 4; } });
        Object.keys(self.foes).forEach(function (k) { var f = self.foes[k]; if (!e.ok && !(f.finding.outcome || "").match(/^fixed/)) { f.play("Skeletons_Taunt", { once: true, restart: true }); } });
      }
    });
  };

  // ------------------------------------------------------------------ per frame

  Realm.prototype.updateHeroes = function (dt) {
    var wd = this.world, self = this;
    Object.keys(this.heroes).forEach(function (k) {
      var h = self.heroes[k];
      var s = k.indexOf("scanner:") === 0 ? wd.scanners[h.name] : null;
      var status = s ? s.status : "ready";
      var target = h.camp, fighting = false;
      if (s && status === "running") { target = h.wild; fighting = true; }
      if (!s) { // a fix backend: goes to the finding being fixed
        var f = wd.findings.filter(function (x) { return x.stage && x.stage !== "done" && !x.outcome; })[0];
        if (f && self.foes[f.id]) { target = self.foes[f.id].spot.clone().add(new THREE.Vector3(0, 0, -1.8)); fighting = true; }
      }
      var there = h.walkTo(target, dt, fighting ? 8 : 6);
      if (!there) { h.play("Running_A"); }
      else if (fighting) { h.faceTo(target.clone().add(new THREE.Vector3(0, 0, 4)), dt); h.play(ATTACK[h.cls] || "Melee_1H_Attack_Chop"); }
      else {
        h.faceTo(h.camp.clone().multiplyScalar(2), dt);
        if (h.cheerUntil && self.time < h.cheerUntil) { h.play("Cheering"); }
        else if (status === "skipped") { h.play("Sit_Floor_Idle"); }
        else if (status === "error") { h.play("Death_A_Pose"); }
        else { h.play(status === "ok" ? "Idle_A" : "Idle_B"); }
      }
      // keep the castle readable: full labels for heroes at work, names for the rest, none at camp
      h.label.hidden = status === "skipped" && h.picked !== true;
      h.label.el.classList.toggle("bad", status === "error");
      h.label.el.classList.toggle("quiet", status !== "running" && !(h.cheerUntil && self.time < h.cheerUntil));
      var sub = status === "running" ? h.cls + " · searching" : status === "ok" ? h.cls + " · " + s.findings + " found · " + W.fmtS(s.duration)
        : status === "skipped" ? h.cls + " · at camp" : status === "error" ? h.cls + " · fallen" : h.cls;
      if (!s) { sub = "champion · " + (wd.backends[h.name] || 0) + " attempt(s)"; }
      self.setLabel(h.label, h.name, sub);
      h.update(dt);
    });
  };

  Realm.prototype.updateFoes = function (dt) {
    var self = this, many = Object.keys(this.foes).length > 12;
    Object.keys(this.foes).forEach(function (k) {
      var a = self.foes[k], f = a.finding;
      if (a.risingUntil && self.time > a.risingUntil) { a.risingUntil = 0; a.play("Skeletons_Idle"); }
      var dead = f.outcome && f.outcome.indexOf("fixed") === 0;
      a.ring.material.opacity = dead ? 0.08 : 0.45 + 0.15 * Math.sin(self.time * 3 + a.spot.x);
      if (dead && a.currentName === "Skeletons_Death" && a.current && !a.current.isRunning()) { a.play("Skeletons_Death_Pose", { fade: 0.1 }); }
      if (!many && !a.label) { a.label = self.label(null, f.id, ""); a.label.follow = a.root; a.label.offset = 2.6 * (FOE[f.severity] || FOE.info).scale + 0.4; a.label.el.classList.add("foe"); }
      if (a.label) { self.setLabel(a.label, f.id, f.monster + (f.outcome ? " · " + f.outcome.replace(/_/g, " ") : "")); }
      a.update(dt);
    });
  };

  Realm.prototype.updateOracles = function (dt) {
    var wd = this.world, self = this;
    Object.keys(this.oracles).forEach(function (id) {
      var a = self.oracles[id], m = wd.models[id];
      var busy = m && m.inflight > 0;
      a.play(busy ? "Ranged_Magic_Spellcasting" : "Idle_B");
      var pulse = busy ? 1.6 + Math.sin(self.time * 8) * 0.6 : 0.9;
      a.orb.material.emissiveIntensity = pulse;
      a.halo.material.opacity = busy ? 0.95 : 0.5;
      a.halo.scale.setScalar(busy ? 5.5 + Math.sin(self.time * 8) : 4);
      a.orb.position.y = self.towerTop.y + Math.sin(self.time * 1.4 + a.orb.position.x) * 0.25;
      a.halo.position.copy(a.orb.position);
      if (m) { self.setLabel(a.label, m.name, (m.role === "fallback" ? "fallback · " : "") + m.calls + " ravens · " + W.fmtTokens(m.tokensIn + m.tokensOut) + " tok" + (m.failed ? " · " + m.failed + " lost" : "")); }
      a.update(dt);
    });
  };

  Realm.prototype.updateWorldBits = function (dt) {
    var self = this, t = this.time;
    this.flickers.forEach(function (f) {
      var k = 0.85 + 0.15 * Math.sin(t * 13 + f.seed) * Math.sin(t * 7.3 + f.seed * 2);
      f.flame.material.opacity = 0.8 * k;
      if (f.light) { f.light.intensity = 1.6 * k; }
    });
    var c = this.core;
    if (c) {
      c.activity = Math.max(0, c.activity - dt * 0.6);
      c.crystal.rotation.y += dt * (0.6 + c.activity * 3);
      c.crystal.position.y = 2.7 + Math.sin(t * 2) * 0.12;
      var ended = this.world.ended, ok = this.world.exitCode === 0;
      c.crystal.material.emissive.setHex(ended ? (ok ? 0x2fbf6a : 0xd23a3a) : 0xff9d1f);
      c.halo.material.color.setHex(ended ? (ok ? 0x5ed68c : 0xff5c5c) : 0xffb340);
      c.halo.scale.setScalar(6 + c.activity * 3 + Math.sin(t * 3) * 0.4);
      c.light.intensity = 2 + c.activity * 2.5;
      c.halo.position.y = c.crystal.position.y;
    }
    this.cells.forEach(function (cell) {
      if (cell.job) { cell.glow.material.opacity = 0.55 + 0.25 * Math.sin(t * 10); cell.glow.material.color.copy(cell.color); }
      else if (cell.flash > 0) { cell.flash = Math.max(0, cell.flash - dt * 0.5); cell.glow.material.opacity = cell.flash; cell.glow.material.color.copy(cell.color); }
      else { cell.glow.material.opacity = 0; }
    });
    this.sparks = this.sparks.filter(function (s) {
      s.t += dt / s.dur;
      var on = s.t >= 0 && s.t <= 1;
      s.head.visible = on;
      if (on) { s.head.position.copy(s.curve.getPoint(s.t)); }
      s.trail.forEach(function (tr, i) { var u = s.t - (i + 1) * 0.03; tr.visible = on && u >= 0; if (tr.visible) { tr.position.copy(s.curve.getPoint(u)); } });
      if (s.t > 1) {
        self.scene.remove(s.head); s.head.material.dispose();
        s.trail.forEach(function (tr) { self.scene.remove(tr); tr.material.dispose(); });
        return false;
      }
      return true;
    });
  };

  Realm.prototype.loop = function () {
    var self = this;
    var frame = function () {
      if (self.disposed) { return; }
      self.raf = requestAnimationFrame(frame);
      var raw = Math.min(self.clock.getDelta(), 0.1);
      if (!self.paused) {
        var dt = raw * self.speed;
        self.time += dt;
        if (self.ready) {
          self.pacer.step(dt);
          self.updateHeroes(dt); self.updateFoes(dt); self.updateOracles(dt); self.updateWorldBits(dt);
          self.refreshCore();
        }
        if (!self.orbit.dragging && !self.reduced) { self.orbit.azimuth += raw * 0.02; }
      }
      var o = self.orbit, tg = self.target;
      self.camera.position.set(tg.x + Math.sin(o.polar) * Math.cos(o.azimuth) * o.dist, tg.y + Math.cos(o.polar) * o.dist,
        tg.z + Math.sin(o.polar) * Math.sin(o.azimuth) * o.dist);
      self.camera.lookAt(tg);
      self.renderer.render(self.scene, self.camera);
      self.placeLabels();
    };
    frame();
  };

  // ------------------------------------------------------------------ input and API

  Realm.prototype.bindInput = function () {
    var el = this.renderer.domElement, o = this.orbit, self = this;
    el.addEventListener("pointerdown", function (e) { o.dragging = true; o.moved = 0; o.lastX = e.clientX; o.lastY = e.clientY; });
    this.onUp = function (e) { if (o.dragging && o.moved < 4) { self.pick(e); } o.dragging = false; };
    this.onMove = function (e) {
      if (!o.dragging) { return; }
      var dx = e.clientX - o.lastX, dy = e.clientY - o.lastY;
      o.moved += Math.abs(dx) + Math.abs(dy);
      o.azimuth -= dx * 0.005;
      o.polar = Math.min(1.3, Math.max(0.35, o.polar - dy * 0.003));
      o.lastX = e.clientX; o.lastY = e.clientY;
    };
    window.addEventListener("pointerup", this.onUp);
    window.addEventListener("pointermove", this.onMove);
    el.addEventListener("wheel", function (e) { e.preventDefault(); o.dist = Math.min(190, Math.max(22, o.dist * (e.deltaY > 0 ? 1.1 : 0.9))); }, { passive: false });
    el.addEventListener("keydown", function (e) {
      if (e.key === "ArrowLeft") { o.azimuth += 0.1; }
      if (e.key === "ArrowRight") { o.azimuth -= 0.1; }
      if (e.key === "ArrowUp") { o.polar = Math.max(0.35, o.polar - 0.05); }
      if (e.key === "ArrowDown") { o.polar = Math.min(1.3, o.polar + 0.05); }
      if (e.key === "+" || e.key === "=") { o.dist = Math.max(22, o.dist * 0.9); }
      if (e.key === "-") { o.dist = Math.min(190, o.dist * 1.1); }
    });
  };

  Realm.prototype.pick = function (e) {
    var rect = this.renderer.domElement.getBoundingClientRect();
    var mouse = new THREE.Vector2(((e.clientX - rect.left) / rect.width) * 2 - 1, -((e.clientY - rect.top) / rect.height) * 2 + 1);
    this.raycaster.setFromCamera(mouse, this.camera);
    var hits = this.raycaster.intersectObjects(this.pickables, false);
    if (hits.length && this.selectCb) {
      var p = hits[0].object.userData.pick, self = this;
      Object.keys(this.heroes).forEach(function (k) { self.heroes[k].picked = p.kind === "scanner" && self.heroes[k].name === p.key; });
      this.selectCb(p, this.world.info(p));
    }
  };

  Realm.prototype.handle = function (ev) { this.pacer.push(ev); };
  Realm.prototype.info = function (pick) { return this.world.info(pick); };
  Realm.prototype.describe = function () { return this.world.describe("Fantasy 3D view. Drag to rotate, scroll to zoom, arrow keys to turn"); };
  Realm.prototype.onSelect = function (cb) { this.selectCb = cb; };
  Realm.prototype.setPaused = function (p) { this.paused = p; };
  Realm.prototype.setSpeed = function (s) { this.speed = s; };
  Realm.prototype.dispose = function () {
    this.disposed = true;
    cancelAnimationFrame(this.raf);
    window.removeEventListener("resize", this.onResize);
    window.removeEventListener("pointerup", this.onUp);
    window.removeEventListener("pointermove", this.onMove);
    // models are shared with the next realm (cached assets): only the GL context goes
    this.renderer.dispose();
    this.renderer.forceContextLoss();
    if (this.renderer.domElement.parentNode) { this.renderer.domElement.parentNode.removeChild(this.renderer.domElement); }
    if (this.overlay.parentNode) { this.overlay.parentNode.removeChild(this.overlay); }
  };

  window.SiftRealm = { available: available, create: function (el) { return new Realm(el); } };
})();
