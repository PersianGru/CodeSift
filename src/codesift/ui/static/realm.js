/* CodeSift UI: the fantasy 3D view. The run is a small realm drawn from window.SiftWorld:
   - the castle on the hill is this machine; each scanner is a hero who walks out through the gate and
     over the bridge to search the wilds, and walks home when it reports;
   - a skeleton rises in the wilds (the project's graveyard) for each finding, bigger and meaner by severity;
   - the wizard's tower is the LLM gateway, one oracle and one orb per model; a raven is one real call;
   - the dungeon pit is the sandbox VM; a lit cell is one real job; its wards are the isolation self-test;
   - a champion (one per fix backend) duels the skeleton it is fixing, and the proof decides its fate.
   Nothing moves without a real event, apart from ambient motion (fire, flags, breathing).
   The land itself is built in realm-kit.js. Characters and props: KayKit by Kay Lousberg (CC0). */
(function () {
  "use strict";

  var THREE = window.THREE, W = window.SiftWorld, K = window.SiftRealmKit;
  if (!THREE || !THREE.GLTFLoader || !THREE.SkeletonUtils || !K) { window.SiftRealm = { available: function () { return false; } }; return; }
  var L = K.L;

  var ASSET = "/static/vendor/kaykit-";
  var HERO_MODEL = { Rogue: "rogue", Mage: "mage", Ranger: "ranger", Knight: "knight", Barbarian: "barbarian", Scout: "rogue_hooded",
    Cleric: "mage", Alchemist: "mage", Bard: "rogue", Monk: "barbarian", Squire: "knight" };
  var LOADOUT = {
    Rogue: { r: "dagger", l: "dagger" }, Mage: { r: "staff" }, Ranger: { l: "bow_withString" }, Knight: { r: "sword_1handed", l: "shield_badge_color" },
    Barbarian: { r: "axe_2handed" }, Scout: { r: "crossbow_1handed" }, Cleric: { r: "wand", l: "spellbook_open" }, Alchemist: { r: "mug_full" },
    Bard: { r: "dagger" }, Monk: {}, Squire: { r: "sword_1handed" }
  };
  // searching is not fighting: heroes inspect, pick locks, read and cast detection while their scanner runs
  var SEARCH = { Rogue: "Lockpicking", Mage: "Ranged_Magic_Spellcasting", Ranger: "Interact", Knight: "Interact", Barbarian: "Interact", Scout: "Lockpicking",
    Cleric: "Ranged_Magic_Spellcasting", Alchemist: "Use_Item", Bard: "Use_Item", Monk: "Interact", Squire: "Interact" };
  var CHAMPIONS = [
    { model: "knight", gear: { r: "sword_1handed", l: "shield_badge_color" }, attack: "Melee_1H_Attack_Chop" },
    { model: "barbarian", gear: { r: "axe_2handed" }, attack: "Melee_2H_Attack_Spin" },
    { model: "rogue_hooded", gear: { r: "dagger", l: "dagger" }, attack: "Melee_1H_Attack_Chop" },
    { model: "ranger", gear: { r: "sword_1handed" }, attack: "Melee_1H_Attack_Chop" }
  ];
  var FOE = {
    critical: { model: "skeleton_mage", scale: 1.38, r: "Skeleton_Staff", glow: 0xff4d4d },
    high: { model: "skeleton_warrior", scale: 1.14, r: "Skeleton_Blade", l: "Skeleton_Shield_Small_A", glow: 0xff8a6e },
    medium: { model: "skeleton_rogue", scale: 0.98, r: "Skeleton_Axe", glow: 0xf5a524 },
    low: { model: "skeleton_minion", scale: 0.86, glow: 0x7aa2ff },
    info: { model: "skeleton_minion", scale: 0.7, glow: 0x9aa0aa }
  };
  var CLIP_LEN = { Melee_1H_Attack_Chop: 1.07, Melee_2H_Attack_Spin: 2.4 };
  var MAX_BODIES = 40;
  var COL = { stone: 0x8d8ea3, stoneHi: 0xa5a6b8, stoneLo: 0x6a6b80, roof: 0x3d4f86, roofT: 0x5b4390, wood: 0x6f4d31, iron: 0x3b3c48, dark: 0x1b1922,
    fire: 0xff9a3c, window: 0xffc56b, raven: 0x1c1d27, llm: 0xb69cff, reply: 0xffd36e, vm: 0x5abeff, ok: 0x5ed68c, bad: 0xff4d4d, scan: 0x78e6c8, grey: 0x8a8d98 };
  var CAMP = [[-4.6, 6.4], [-7.2, 5.2], [-7.6, 2.4], [-5.8, 0.4], [-2.9, 0.9], [-1.7, 3.6], // around the campfire
    [3.3, 8.2], [-3.3, 8.6], [7.2, -1.4], [7.4, 3.2], [2.6, -6.2], [-2.6, -6.2], [7.2, -5.8], [-7.4, -4.6]]; // posts
  var FIRE_AT = [-4.6, 3.4];
  var CHAMP_AT = [[3.4, 1.4], [4.8, -2.0], [2.2, 4.4], [5.6, 4.0]];

  var LC = {};
  /* A colour as three.js r128 wants it (linear light), from the sRGB hex we write. */
  function lc(hex) { return LC[hex] || (LC[hex] = new THREE.Color(hex).convertSRGBToLinear()); }

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
        scene.traverse(function (o) { if (o.isMesh) { o.castShadow = true; o.receiveShadow = true; o.frustumCulled = false; } });
        out.models[n] = scene;
      });
      Object.keys(out.props).forEach(function (k) {
        out.props[k].traverse(function (o) { if (o.isMesh) { o.castShadow = true; o.receiveShadow = true; } });
      });
      return out;
    });
    assets.catch(function () { assets = null; });
    return assets;
  }

  /* Many copies of the KayKit props, drawn as one mesh per texture instead of one per prop. */
  function Batch(props) { this.props = props; this.groups = []; }
  Batch.prototype.add = function (name, x, y, z, ry, sx, sy, sz) {
    var src = this.props[name], self = this;
    if (!src) { return; }
    var base = K.mat(x, y || 0, z, 0, ry || 0, 0, sx === undefined ? 1 : sx, sy === undefined ? (sx === undefined ? 1 : sx) : sy, sz === undefined ? (sx === undefined ? 1 : sx) : sz);
    (function walk(node, m, root) {
      var wm = m;
      if (!root) { node.updateMatrix(); wm = m.clone().multiply(node.matrix); }
      if (node.isMesh) {
        var key = node.material.map ? node.material.map.image : node.material, g = null;
        for (var i = 0; i < self.groups.length; i++) { if (self.groups[i].key === key) { g = self.groups[i]; } }
        if (!g) { g = { key: key, material: node.material, parts: [] }; self.groups.push(g); }
        g.parts.push({ geo: node.geometry, matrix: wm });
      }
      node.children.forEach(function (c) { walk(c, wm, false); });
    })(src, base, true);
  };
  Batch.prototype.build = function (parent) {
    var v = new THREE.Vector3(), nm = new THREE.Matrix3();
    this.groups.forEach(function (g) {
      var pos = [], nor = [], uv = [], idx = [];
      g.parts.forEach(function (p) {
        var gp = p.geo.attributes.position, gn = p.geo.attributes.normal, gu = p.geo.attributes.uv, off = pos.length / 3, i;
        nm.getNormalMatrix(p.matrix);
        for (i = 0; i < gp.count; i++) {
          v.fromBufferAttribute(gp, i).applyMatrix4(p.matrix); pos.push(v.x, v.y, v.z);
          if (gn) { v.fromBufferAttribute(gn, i).applyMatrix3(nm).normalize(); nor.push(v.x, v.y, v.z); } else { nor.push(0, 1, 0); }
          if (gu) { uv.push(gu.getX(i), gu.getY(i)); } else { uv.push(0, 0); }
        }
        if (p.geo.index) { for (i = 0; i < p.geo.index.count; i++) { idx.push(p.geo.index.getX(i) + off); } }
        else { for (i = 0; i < gp.count; i++) { idx.push(off + i); } }
      });
      var geo = new THREE.BufferGeometry();
      geo.setAttribute("position", new THREE.Float32BufferAttribute(pos, 3));
      geo.setAttribute("normal", new THREE.Float32BufferAttribute(nor, 3));
      geo.setAttribute("uv", new THREE.Float32BufferAttribute(uv, 2));
      geo.setIndex(idx);
      var mesh = new THREE.Mesh(geo, g.material);
      mesh.castShadow = true; mesh.receiveShadow = true;
      parent.add(mesh);
    });
  };

  // ------------------------------------------------------------------ an animated character

  function Actor(realm, model, scale, loadout) {
    this.realm = realm;
    this.root = new THREE.Group();
    this.body = THREE.SkeletonUtils.clone(realm.assets.models[model]);
    this.body.scale.setScalar(scale || 1);
    this.root.add(this.body);
    this.mixer = new THREE.AnimationMixer(this.body);
    this.actions = {}; this.current = null; this.lockUntil = 0; this.path = [];
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
  /* Loop a clip. Ignored while a one-shot (once) is still playing, unless opts.force. */
  Actor.prototype.play = function (name, opts) {
    opts = opts || {};
    if (!opts.force && this.realm.time < this.lockUntil) { return; }
    if (this.currentName === name && !opts.restart) { return; }
    var next = this.action(name);
    if (!next) { return; }
    next.reset();
    next.setLoop(opts.once ? THREE.LoopOnce : THREE.LoopRepeat, Infinity);
    next.clampWhenFinished = !!opts.once;
    next.timeScale = opts.timeScale || 1;
    next.play();
    if (this.current && this.current !== next) { this.current.crossFadeTo(next, opts.fade === undefined ? 0.22 : opts.fade, false); }
    this.current = next; this.currentName = name; this.still = false;
  };
  Actor.prototype.once = function (name, seconds, fade) {
    this.play(name, { once: true, restart: true, force: true, fade: fade });
    this.lockUntil = this.realm.time + seconds;
  };
  Actor.prototype.update = function (dt) { this.mixer.update(dt); };
  Actor.prototype.faceTo = function (x, z, dt) {
    var dx = x - this.root.position.x, dz = z - this.root.position.z;
    if (dx * dx + dz * dz < 1e-4) { return; }
    this.turn(Math.atan2(dx, dz), dt);
  };
  Actor.prototype.turn = function (want, dt) {
    var cur = this.root.rotation.y, diff = Math.atan2(Math.sin(want - cur), Math.cos(want - cur));
    this.root.rotation.y = cur + diff * Math.min(1, dt * 9);
  };
  /* Walk along this.path; true when there is nowhere left to go. */
  Actor.prototype.walk = function (dt, speed) {
    var pos = this.root.position, left = speed * dt;
    while (this.path.length && left > 0) {
      var p = this.path[0], dx = p.x - pos.x, dz = p.z - pos.z, d = Math.sqrt(dx * dx + dz * dz);
      if (d < 0.12) { this.path.shift(); continue; }
      var step = Math.min(d, left);
      pos.x += dx / d * step; pos.z += dz / d * step; left -= step;
      this.faceTo(p.x, p.z, dt);
      if (step >= d) { this.path.shift(); }
    }
    pos.y = this.realm.land.ground(pos.x, pos.z);
    return !this.path.length;
  };

  // ------------------------------------------------------------------ the realm

  function Realm(container) {
    window.SiftRealm.current = this; // the live view, for debugging from the console
    this.el = container;
    this.world = W.create();
    this.time = 0; this.real = 0; this.frame = 0; this.speed = 1; this.paused = false;
    this.heroes = {}; this.foes = {}; this.oracles = {}; this.cells = []; this.fx = []; this.labels = [];
    this.pickables = []; this.fires = []; this.flags = []; this.slotOf = {}; this.slotUsed = [];
    this.reduced = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
    var self = this;
    this.pacer = new W.Pacer(this.world, function (fx, animate) { self.effects(fx, animate); });
    this.initRenderer();
    this.overlay = document.createElement("div");
    this.overlay.className = "realm-labels";
    container.appendChild(this.overlay);
    this.loading = this.label(new THREE.Vector3(0, 12, 0), "Summoning the realm…", "", "realm-loading", 99);
    this.clock = new THREE.Clock();
    this.loop();
    loadAssets().then(function (a) {
      if (self.disposed) { return; }
      self.assets = a;
      self.removeLabel(self.loading); self.loading = null;
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
    r.toneMappingExposure = 1.3;
    r.shadowMap.enabled = true;
    r.shadowMap.type = THREE.PCFSoftShadowMap;
    r.domElement.tabIndex = 0;
    r.domElement.setAttribute("aria-label", "Fantasy 3D view of the run. Arrow keys turn, plus and minus zoom, Home resets the view.");
    this.el.appendChild(r.domElement);
    this.renderer = r;
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(0x070b16);
    this.scene.fog = new THREE.FogExp2(0x16223c, 0.0046);
    this.camera = new THREE.PerspectiveCamera(40, 1, 1, 1200);
    this.orbit = { azimuth: 1.47, polar: 0.9, dist: 104, dragging: false };
    this.home = { x: 0.5, y: 2, z: 13 };
    this.cam = { x: this.home.x, y: this.home.y, z: this.home.z, dist: 104 };
    this.focus = null; this.handsOff = 0;
    this.raycaster = new THREE.Raycaster();
    var self = this;
    this.onResize = function () { self.resize(); };
    window.addEventListener("resize", this.onResize);
    this.resize();
    this.bindInput();
    this.land = new K.Land();
    K.sky(this.scene);
    this.land.addTo(this.scene);
    var s = this.scene;
    s.add(new THREE.HemisphereLight(0x7d93d6, 0x2c2a26, 0.62));
    var moon = new THREE.DirectionalLight(0xc3d2ff, 1.1);
    moon.position.set(-46, 78, 18); moon.target.position.set(0, 0, 14);
    moon.castShadow = true;
    moon.shadow.mapSize.set(2048, 2048);
    var sc = moon.shadow.camera; sc.left = -78; sc.right = 78; sc.top = 66; sc.bottom = -66; sc.near = 10; sc.far = 240;
    moon.shadow.bias = -0.0005; moon.shadow.normalBias = 0.06;
    s.add(moon); s.add(moon.target);
    var warm = new THREE.DirectionalLight(0xffb070, 0.34);
    warm.position.set(50, 28, 80);
    s.add(warm);
  };

  Realm.prototype.resize = function () {
    var w = Math.max(320, this.el.clientWidth), h = Math.max(240, this.el.clientHeight);
    this.renderer.setSize(w, h, false);
    this.renderer.domElement.style.width = w + "px"; this.renderer.domElement.style.height = h + "px";
    this.camera.aspect = w / h; this.camera.updateProjectionMatrix();
    this.w = w; this.h = h;
    this.fit = Math.max(1, 1.62 / (w / h)); // a narrow window steps back so the whole realm still fits
  };

  // ------------------------------------------------------------------ building blocks

  Realm.prototype.prop = function (name, x, y, z, rotY, parent, scale) {
    var src = this.assets.props[name];
    if (!src) { return null; }
    var o = src.clone();
    o.position.set(x, y || 0, z);
    o.rotation.y = rotY || 0;
    if (scale) { o.scale.setScalar(scale); }
    (parent || this.scene).add(o);
    return o;
  };

  var flameGeo = null;
  /* A flame that sits on something: every caller builds the torch, bowl or lantern under it first. */
  Realm.prototype.fire = function (x, y, z, size, color, light) {
    if (!flameGeo) { flameGeo = new THREE.ConeGeometry(0.2, 0.62, 5); flameGeo.translate(0, 0.31, 0); }
    var g = new THREE.Group(); g.position.set(x, y, z);
    var outer = new THREE.Mesh(flameGeo, new THREE.MeshBasicMaterial({ color: lc(color || COL.fire), toneMapped: false }));
    var inner = new THREE.Mesh(flameGeo, new THREE.MeshBasicMaterial({ color: lc(0xfff0b0), toneMapped: false }));
    inner.scale.setScalar(0.55);
    var halo = K.glow(color || COL.fire, 2.6 * size, 0.7); halo.position.y = 0.3 * size;
    outer.scale.setScalar(size); inner.scale.setScalar(size * 0.55);
    g.add(outer); g.add(inner); g.add(halo);
    this.scene.add(g);
    var item = { group: g, outer: outer, inner: inner, halo: halo, size: size, seed: this.fires.length * 1.7, power: 0 };
    if (light) {
      item.light = new THREE.PointLight(color || 0xff8a35, light, 26, 2);
      item.light.position.set(x, y + 0.6, z); item.power = light;
      this.scene.add(item.light);
    }
    this.fires.push(item);
    return item;
  };

  /* A KayKit wall torch on a wall face, with its flame on the torch head. */
  Realm.prototype.torch = function (x, y, z, rotY, light) {
    this.batch.add("torch_mounted", x, y, z, rotY);
    return this.fire(x + Math.sin(rotY || 0) * 0.34, y + 0.66, z + Math.cos(rotY || 0) * 0.34, 0.8, COL.fire, light);
  };

  /* A wooden post with a hanging lantern. */
  Realm.prototype.lamp = function (x, z, ry, color) {
    var y = this.land.ground(x, z), s = this.stone, dx = Math.sin(ry), dz = Math.cos(ry);
    s.cyl(0.11, 0.15, 3.0, 5, COL.wood, x, y + 1.5, z);
    s.box(0.12, 0.12, 0.95, COL.wood, x + dx * 0.36, y + 2.85, z + dz * 0.36, ry);
    s.box(0.07, 0.3, 0.07, COL.iron, x + dx * 0.72, y + 2.65, z + dz * 0.72);
    s.box(0.34, 0.1, 0.34, COL.iron, x + dx * 0.72, y + 2.5, z + dz * 0.72); s.box(0.34, 0.08, 0.34, COL.iron, x + dx * 0.72, y + 2.06, z + dz * 0.72);
    this.lit.box(0.26, 0.38, 0.26, color || COL.window, x + dx * 0.72, y + 2.28, z + dz * 0.72);
    var halo = K.glow(color || COL.fire, 2.6, 0.6); halo.position.set(x + dx * 0.72, y + 2.28, z + dz * 0.72); this.scene.add(halo);
    this.fires.push({ halo: halo, size: 1, seed: this.fires.length * 2.3, lampOnly: true });
  };

  Realm.prototype.pickBox = function (obj, w, h, d, pick, x, y, z) {
    var m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), new THREE.MeshBasicMaterial({ visible: false }));
    m.position.set(x || 0, y === undefined ? h / 2 : y, z || 0);
    m.userData.pick = pick;
    obj.add(m);
    this.pickables.push(m);
    return m;
  };

  // ------------------------------------------------------------------ the places

  Realm.prototype.build = function () {
    this.batch = new Batch(this.assets.props);
    this.stone = new K.Merger(21);   // every stone and timber thing built in code: one mesh
    this.lit = new K.Merger(22);     // windows and lantern glass: one unlit mesh
    this.layoutWilds();
    this.buildCastle(); this.buildBridge(); this.buildTower(); this.buildDungeon(); this.buildWilds(); this.buildRoadside();
    this.batch.build(this.scene);
    this.stone.mesh(this.scene);
    var litMesh = new THREE.Mesh(this.lit.geometry(), new THREE.MeshBasicMaterial({ vertexColors: true, toneMapped: false }));
    this.scene.add(litMesh);
    this.land.plant(this.scene, this.keepClear);
    this.selectRing = K.decal(0xffd36e, 4.2, 0); this.scene.add(this.selectRing);
  };

  /* Where skeletons stand and where heroes search: loose spots in the graveyard, the same every time. */
  Realm.prototype.layoutWilds = function () {
    var r = K.rng(77), w = L.wilds, land = this.land, slots = [], spots = [], x, z, tries, i, ok;
    for (tries = 0; slots.length < 46 && tries < 6000; tries++) {
      x = w.x + (r() * 2 - 1) * w.rx; z = w.z + (r() * 2 - 1) * w.rz;
      if (!land.inWilds(x, z, -1.6) || land.roadDist(x, z) < 2.0) { continue; }
      for (ok = true, i = 0; i < slots.length; i++) { if ((slots[i].x - x) * (slots[i].x - x) + (slots[i].z - z) * (slots[i].z - z) < 3.1 * 3.1) { ok = false; break; } }
      if (ok) { slots.push({ x: x, z: z, turn: (r() - 0.5) * 0.9 }); }
    }
    for (tries = 0; spots.length < 14 && tries < 6000; tries++) {
      x = w.x + (r() * 2 - 1) * (w.rx - 2); z = w.z + (r() * 2 - 1) * (w.rz - 1.5);
      if (!land.inWilds(x, z, -2) || land.roadDist(x, z) < 1.2) { continue; }
      for (ok = true, i = 0; i < slots.length; i++) { if ((slots[i].x - x) * (slots[i].x - x) + (slots[i].z - z) * (slots[i].z - z) < 2.0 * 2.0) { ok = false; break; } }
      for (i = 0; ok && i < spots.length; i++) { if ((spots[i].x - x) * (spots[i].x - x) + (spots[i].z - z) * (spots[i].z - z) < 4.6 * 4.6) { ok = false; } }
      if (ok) { spots.push({ x: x, z: z }); }
    }
    this.slots = slots; this.spots = spots;
    this.keepClear = slots.map(function (s) { return { x: s.x, z: s.z, r: 1.4 }; }).concat(spots.map(function (s) { return { x: s.x, z: s.z, r: 1.2 }; }));
  };

  Realm.prototype.buildCastle = function () {
    var b = this.batch, s = this.stone, y = L.core.y, i, j, self = this;
    for (i = -2; i <= 2; i++) { for (j = -2; j <= 2; j++) { b.add((i * 3 + j * 5) % 7 === 0 ? "floor_tile_large_rocks" : "floor_tile_large", i * 4, y, j * 4, ((i + j) & 3) * Math.PI / 2); } }
    for (i = -2; i <= 2; i++) {
      b.add("wall", i * 4, y, -10.5, 0);
      if (i !== 0) { b.add("wall", i * 4, y, 10.5, Math.PI); }
      b.add("wall", -10.5, y, i * 4, Math.PI / 2);
      b.add("wall", 10.5, y, i * 4, -Math.PI / 2);
    }
    // battlements along the wall tops
    for (i = -5; i <= 5; i++) {
      if (Math.abs(i) > 1) { s.box(1.0, 0.6, 0.5, COL.stoneHi, i * 1.9, y + 4.3, 10.75); }
      s.box(0.5, 0.6, 1.0, COL.stoneHi, -10.75, y + 4.3, i * 1.9); s.box(0.5, 0.6, 1.0, COL.stoneHi, 10.75, y + 4.3, i * 1.9);
      if (Math.abs(i) > 2) { s.box(1.0, 0.6, 0.5, COL.stoneHi, i * 1.9, y + 4.3, -10.75); }
    }
    // the gate: two pillars, a lintel with merlons, torches on the pillars
    b.add("pillar", -2.75, y, 10.5, 0); b.add("pillar", 2.75, y, 10.5, 0);
    s.box(7.0, 1.0, 1.5, COL.stone, 0, y + 4.5, 10.5);
    for (i = -2; i <= 2; i++) { s.box(0.9, 0.6, 0.5, COL.stoneHi, i * 1.5, y + 5.3, 11.0); }
    this.torch(-2.75, y + 2.3, 11.28, 0, 2.2); this.torch(2.75, y + 2.3, 11.28, 0, 0);
    b.add("banner_patternA_red", -6, y + 0.2, 10.55, 0); b.add("banner_patternA_red", 6, y + 0.2, 10.55, 0);
    // corner towers with slate roofs and pennants
    [[-10.9, -10.9], [10.9, -10.9], [-10.9, 10.9], [10.9, 10.9]].forEach(function (p, k) {
      s.cyl(2.5, 2.9, 10, 8, COL.stone, p[0], y + 1.2, p[1]);
      s.cyl(2.85, 2.6, 0.6, 8, COL.stoneHi, p[0], y + 6.3, p[1]);
      s.cone(3.0, 3.6, 8, COL.roof, p[0], y + 8.4, p[1]);
      s.cyl(0.06, 0.06, 2.4, 4, COL.wood, p[0], y + 11.2, p[1]);
      self.lit.box(0.06, 0.9, 0.5, COL.window, p[0] + (p[0] < 0 ? 2.6 : -2.6) * 0, y + 4.2, p[1] + (p[1] < 0 ? 2.72 : 2.72));
      self.flag(p[0], y + 11.9, p[1], 0xf5a524, 1.5, k);
    });
    // the keep at the back, with the beacon on its roof
    s.box(8.4, 12, 7, COL.stone, 0, y + 5, -12.2);
    s.box(9.2, 0.7, 7.8, COL.stoneHi, 0, y + 11.1, -12.2);
    for (i = -2; i <= 2; i++) {
      s.box(1.0, 0.7, 0.6, COL.stoneHi, i * 2.0, y + 11.8, -8.6); s.box(1.0, 0.7, 0.6, COL.stoneHi, i * 2.0, y + 11.8, -15.8);
      if (Math.abs(i) < 2) { s.box(0.6, 0.7, 1.0, COL.stoneHi, -4.3, y + 11.8, -12.2 + i * 2.2); s.box(0.6, 0.7, 1.0, COL.stoneHi, 4.3, y + 11.8, -12.2 + i * 2.2); }
    }
    s.box(2.4, 3.2, 0.5, COL.stoneLo, 0, y + 1.6, -8.6); s.box(1.7, 2.7, 0.5, COL.wood, 0, y + 1.35, -8.5);
    [[-2.4, 7.2], [2.4, 7.2], [0, 8.2], [-2.4, 4.0], [2.4, 4.0]].forEach(function (wv) { self.lit.box(0.6, 1.2, 0.1, COL.window, wv[0], y + wv[1], -8.66); });
    b.add("banner_shield_yellow", 0, y + 3.4, -9.15, 0);
    s.cyl(1.25, 0.7, 0.7, 8, COL.iron, 0, y + 11.9, -12.2); s.cyl(0.5, 0.7, 0.6, 6, COL.stoneLo, 0, y + 11.4, -12.2);
    this.beacon = this.fire(0, y + 12.2, -12.2, 3.0, COL.fire, 2.6);
    this.beaconTop = new THREE.Vector3(0, y + 14.2, -12.2);
    // the courtyard: the crystal, the campfire, stores
    b.add("column", 0, y + 0.1, 0, 0);
    var crystal = new THREE.Mesh(new THREE.OctahedronGeometry(0.9, 0),
      new THREE.MeshStandardMaterial({ color: lc(0xffc457), emissive: lc(0xff9d1f), emissiveIntensity: 1.6, roughness: 0.25, metalness: 0.1, flatShading: true }));
    crystal.position.set(0, y + 2.8, 0); crystal.castShadow = true; this.scene.add(crystal);
    var halo = K.glow(0xffb340, 6, 0.7); halo.position.copy(crystal.position); this.scene.add(halo);
    var coreLight = new THREE.PointLight(0xffb048, 2.0, 24, 2); coreLight.position.set(0, y + 3.4, 0); this.scene.add(coreLight);
    this.core = { crystal: crystal, halo: halo, light: coreLight, activity: 0, y: y + 2.8 };
    for (i = 0; i < 7; i++) { var a = i / 7 * 6.283; s.add(new THREE.IcosahedronGeometry(0.28, 0), COL.stoneLo, K.mat(FIRE_AT[0] + Math.cos(a) * 0.85, y + 0.25, FIRE_AT[1] + Math.sin(a) * 0.85, a, a, 0)); }
    for (i = 0; i < 3; i++) { s.cyl(0.11, 0.11, 1.3, 5, COL.wood, FIRE_AT[0], y + 0.35, FIRE_AT[1], Math.PI / 2 - 0.25, 0, i * 2.1); }
    this.fire(FIRE_AT[0], y + 0.3, FIRE_AT[1], 1.7, COL.fire, 2.4);
    this.torch(-7, y + 2.4, -9.98, 0, 0); this.torch(7, y + 2.4, -9.98, 0, 0);
    this.torch(9.98, y + 2.4, 5.5, -Math.PI / 2, 0); this.torch(-9.98, y + 2.4, -5.5, Math.PI / 2, 0);
    b.add("barrel_large", 8.0, y + 0.1, -7.9, 0.3); b.add("barrel_small_stack", 5.6, y + 0.1, -8.6, 0);
    b.add("crates_stacked", 7.9, y + 0.1, 7.6, 0.2); b.add("chest_gold", -7.9, y + 0.1, -7.6, 0.8);
    b.add("keg_decorated", -8.2, y + 0.1, 7.2, Math.PI / 2); b.add("table_medium", 6.2, y + 0.1, 1.0, 0.2); b.add("mug_full", 6.0, y + 1.3, 0.8, 0.5);
    b.add("banner_patternA_blue", -10.05, y + 0.3, 2, Math.PI / 2); b.add("banner_thin_green", 10.05, y + 0.3, -3, -Math.PI / 2);
    var holder = new THREE.Group(); this.scene.add(holder);
    this.pickBox(holder, 4, 5, 4, { kind: "core" }, 0, y + 2.5, 0);
    this.pickBox(holder, 9, 13, 8, { kind: "core" }, 0, y + 6, -12.2);
    this.coreLabel = this.label(new THREE.Vector3(0, y + 17.2, -12.2), "CodeSift castle", "this machine · waiting for a run", "realm-place", 7);
  };

  var flagGeo = null;
  Realm.prototype.flag = function (x, y, z, color, size, seed) {
    if (!flagGeo) {
      flagGeo = new THREE.BufferGeometry();
      flagGeo.setAttribute("position", new THREE.Float32BufferAttribute([0, 0.4, 0, 0, -0.4, 0, 1.4, 0, 0], 3));
      flagGeo.computeVertexNormals();
    }
    var m = new THREE.Mesh(flagGeo, new THREE.MeshStandardMaterial({ color: lc(color), side: THREE.DoubleSide, roughness: 0.9, flatShading: true }));
    m.position.set(x, y, z); m.scale.setScalar(size || 1);
    this.scene.add(m);
    this.flags.push({ mesh: m, seed: (seed || 0) * 1.9 });
    return m;
  };

  Realm.prototype.buildBridge = function () {
    var s = this.stone, b = L.bridge, n = 8, seg = (b.z1 - b.z0) / n, k, land = this.land;
    for (k = 0; k < n; k++) {
      var zc = b.z0 + seg * (k + 0.5), y = land.deck(zc), rx = -Math.atan((land.deck(zc + 0.1) - land.deck(zc - 0.1)) / 0.2);
      s.box(5.2, 0.55, seg + 0.14, k % 2 ? COL.stone : COL.stoneHi, b.x, y - 0.3, zc, 0, rx);
      s.box(0.42, 0.8, seg + 0.14, COL.stoneLo, b.x - 2.55, y + 0.3, zc, 0, rx); s.box(0.42, 0.8, seg + 0.14, COL.stoneLo, b.x + 2.55, y + 0.3, zc, 0, rx);
    }
    s.box(4.8, 3.6, 1.1, COL.stoneLo, b.x, -0.9, 22.4); s.box(4.8, 3.6, 1.1, COL.stoneLo, b.x, -0.9, 25.6);
    s.box(5.8, 2.6, 1.3, COL.stone, b.x, 0.1, b.z0 + 0.2); s.box(5.8, 2.6, 1.3, COL.stone, b.x, 0.1, b.z1 - 0.2);
    var self = this;
    [[-2.55, b.z0 + 0.3], [2.55, b.z0 + 0.3], [-2.55, b.z1 - 0.3], [2.55, b.z1 - 0.3]].forEach(function (p, i) {
      var y0 = land.deck(p[1]);
      s.box(0.72, 1.7, 0.72, COL.stone, b.x + p[0], y0 + 0.55, p[1]); s.cyl(0.34, 0.2, 0.26, 6, COL.iron, b.x + p[0], y0 + 1.52, p[1]);
      self.fire(b.x + p[0], y0 + 1.6, p[1], 0.75, COL.fire, 0);
    });
  };

  /* The wizard's tower: the LLM gateway. Built looking down its own +z (the door side), then turned. */
  Realm.prototype.buildTower = function () {
    var T = L.tower, s = this.stone, lit = this.lit, i, a;
    s.at(T.x, T.y, T.z, T.door); lit.at(T.x, T.y, T.z, T.door);
    s.cyl(4.7, 5.1, 1.0, 10, COL.stoneLo, 0, 0.3, 0);
    s.cyl(3.0, 3.9, 12.4, 10, COL.stone, 0, 7.0, 0);
    [4.2, 8.4].forEach(function (yb) { s.cyl(3.75 - yb * 0.07, 3.8 - yb * 0.07, 0.4, 10, COL.stoneHi, 0, yb, 0); });
    s.cyl(4.0, 3.0, 1.1, 10, COL.stoneHi, 0, 13.4, 0);          // the flared crown
    for (i = 0; i < 10; i++) { a = i / 10 * 6.283 + 0.314; s.box(1.1, 0.8, 0.5, COL.stoneHi, Math.sin(a) * 3.75, 14.35, Math.cos(a) * 3.75, a); }
    // the door, with steps down to the path and a lantern each side
    s.box(2.5, 3.3, 0.6, COL.stoneLo, 0, 2.2, 3.62); s.box(1.6, 2.6, 0.5, COL.wood, 0, 2.0, 3.75);
    s.cyl(0.95, 0.95, 0.5, 8, COL.stoneLo, 0, 3.3, 3.62, Math.PI / 2);
    for (i = 0; i < 3; i++) { s.box(3.0 + i * 0.5, 0.3, 0.8, COL.stoneHi, 0, 0.75 - i * 0.26, 4.5 + i * 0.75); }
    [-1.75, 1.75].forEach(function (x) {
      s.box(0.14, 0.14, 0.7, COL.iron, x, 3.3, 3.9); s.box(0.36, 0.1, 0.36, COL.iron, x, 3.12, 4.2);
      lit.box(0.28, 0.4, 0.28, COL.window, x, 2.87, 4.2); s.box(0.36, 0.08, 0.36, COL.iron, x, 2.63, 4.2);
    });
    // lit windows winding up the wall
    [[0.9, 5.2], [2.6, 7.4], [-1.2, 6.4], [4.3, 9.8], [-2.6, 10.4], [0.2, 10.6]].forEach(function (wv) {
      var rr = 3.72 - wv[1] * 0.07;
      lit.box(0.55, 1.05, 0.12, 0xd9b8ff, Math.sin(wv[0]) * rr, wv[1], Math.cos(wv[0]) * rr, wv[0]);
    });
    // a side turret with a pointed roof: the silhouette of a wizard's tower
    s.cyl(1.25, 1.25, 9, 8, COL.stone, -2.9, 9.6, -2.1); s.cyl(1.5, 1.25, 0.5, 8, COL.stoneHi, -2.9, 14.2, -2.1);
    s.cone(1.75, 4.2, 8, COL.roofT, -2.9, 16.5, -2.1); s.cyl(0.9, 1.25, 1.2, 8, COL.stoneLo, -2.9, 4.6, -2.1);
    lit.box(0.4, 0.8, 0.1, 0xd9b8ff, -2.9, 12.4, -0.84);
    // a balcony ring half-way up
    s.cyl(4.25, 3.6, 0.45, 10, COL.stoneLo, 0, 9.2, 0);
    for (i = 0; i < 10; i++) { a = i / 10 * 6.283; s.box(0.14, 0.8, 0.14, COL.wood, Math.sin(a) * 4.1, 9.8, Math.cos(a) * 4.1); }
    s.add(new THREE.TorusGeometry(4.1, 0.07, 4, 10), COL.wood, K.mat(0, 10.2, 0, Math.PI / 2, 0, 0));
    s.at(); lit.at();
    // the open top: a scrying pool and a ring of runes turning above it
    var top = new THREE.Group(); top.position.set(T.x, T.y, T.z); top.rotation.y = T.door; this.scene.add(top);
    var pool = new THREE.Mesh(new THREE.CylinderGeometry(2.5, 2.5, 0.2, 10), new THREE.MeshBasicMaterial({ color: lc(0x7b5cff), toneMapped: false }));
    pool.position.y = 13.95; top.add(pool);
    var ring = new THREE.Mesh(new THREE.TorusGeometry(2.7, 0.11, 5, 20), new THREE.MeshBasicMaterial({ color: lc(0xcdbdff), toneMapped: false }));
    ring.rotation.x = Math.PI / 2; ring.position.y = 16.6; top.add(ring);
    var ring2 = new THREE.Mesh(new THREE.TorusGeometry(1.9, 0.08, 5, 16), new THREE.MeshBasicMaterial({ color: lc(0x9d7bff), toneMapped: false }));
    ring2.position.y = 16.6; top.add(ring2);
    var poolGlow = K.glow(0x8f6bff, 11, 0.5); poolGlow.position.y = 15.4; top.add(poolGlow);
    var tl = new THREE.PointLight(0x9d7bff, 1.8, 30, 2); tl.position.set(0, 16, 0); top.add(tl);
    this.tower = { group: top, pool: pool, ring: ring, ring2: ring2, glow: poolGlow, light: tl, flash: 0 };
    this.towerTop = new THREE.Vector3(T.x, T.y + 16.6, T.z);
    this.pickBox(top, 8, 17, 8, { kind: "llm" }, 0, 8.5, 0);
    this.towerLabel = this.label(new THREE.Vector3(T.x, T.y + 20.2, T.z), "Oracle tower", "LLM gateway", "realm-place", 7);
  };

  Realm.prototype.towerPoint = function (lx, ly, lz) { // a spot given in the tower's own frame, in world space
    var T = L.tower, c = Math.cos(T.door), s = Math.sin(T.door);
    return new THREE.Vector3(T.x + lx * c + lz * s, T.y + ly, T.z - lx * s + lz * c);
  };

  /* The dungeon: an open pit with a cell block, stairs going down into it and a gatehouse at the top. */
  Realm.prototype.buildDungeon = function () {
    var D = L.dungeon, b = this.batch, s = this.stone, i, fy = D.floor, self = this;
    for (i = 0; i < 5; i++) {
      b.add("floor_tile_large", D.x0 + 3 + i * 4, fy, D.z0 + 3, 0); b.add("floor_tile_large", D.x0 + 3 + i * 4, fy, D.z0 + 7, 0); b.add("floor_tile_large", D.x0 + 3 + i * 4, fy, D.z0 + 11, 0);
      b.add("wall", D.x0 + 3 + i * 4, fy, D.z0 + 0.5, 0); b.add("wall", D.x0 + 3 + i * 4, fy, D.z1 - 0.5, Math.PI);
    }
    for (i = 0; i < 3; i++) { b.add("wall", D.x0 + 0.5, fy, D.z0 + 3 + i * 4, Math.PI / 2); b.add("wall", D.x1 - 0.5, fy, D.z0 + 3 + i * 4, -Math.PI / 2); }
    [[D.x0 + 0.6, D.z0 + 0.6], [D.x1 - 0.6, D.z0 + 0.6], [D.x0 + 0.6, D.z1 - 0.6], [D.x1 - 0.6, D.z1 - 0.6]].forEach(function (p) { b.add("pillar", p[0], fy, p[1], 0); });
    // a stone kerb round the rim (open where the stairs arrive)
    s.box(D.x1 - D.x0 + 0.6, 0.4, 1.3, COL.stoneLo, (D.x0 + D.x1) / 2, D.y + 0.12, D.z0 + 0.5); s.box(D.x1 - D.x0 + 0.6, 0.4, 1.3, COL.stoneLo, (D.x0 + D.x1) / 2, D.y + 0.12, D.z1 - 0.5);
    s.box(1.3, 0.4, D.z1 - D.z0, COL.stoneLo, D.x0 + 0.5, D.y + 0.12, (D.z0 + D.z1) / 2);
    s.box(1.3, 0.4, D.stairZ - 2.6 - D.z0, COL.stoneLo, D.x1 - 0.5, D.y + 0.12, (D.z0 + D.stairZ - 2.6) / 2); s.box(1.3, 0.4, D.z1 - D.stairZ - 2.6, COL.stoneLo, D.x1 - 0.5, D.y + 0.12, (D.z1 + D.stairZ + 2.6) / 2);
    // stairs down the east wall, and the gatehouse they start from
    b.add("stairs", D.x1 - 1, fy, D.stairZ, -Math.PI / 2, 1, D.depth / 4, 1);
    b.add("wall_doorway", D.x1 + 2.2, D.y - 0.05, D.stairZ, Math.PI / 2);
    b.add("pillar", D.x1 + 2.2, D.y - 0.05, D.stairZ - 2.75, 0); b.add("pillar", D.x1 + 2.2, D.y - 0.05, D.stairZ + 2.75, 0);
    s.box(1.7, 0.6, 7.2, COL.stoneHi, D.x1 + 2.2, D.y + 4.25, D.stairZ);
    for (i = -2; i <= 2; i++) { s.box(0.5, 0.55, 0.9, COL.stoneHi, D.x1 + 2.75, D.y + 4.8, D.stairZ + i * 1.5); }
    s.box(3.4, 0.3, 5.2, COL.stoneLo, D.x1 + 0.6, D.y + 0.02, D.stairZ);
    this.torch(D.x1 + 2.98, D.y + 2.3, D.stairZ - 2.75, Math.PI / 2, 2.0); this.torch(D.x1 + 2.98, D.y + 2.3, D.stairZ + 2.75, Math.PI / 2, 0);
    // the cell block along the north wall: five barred cells, each with a lamp over its door
    var front = D.z0 + 4.5;
    for (i = 0; i < 5; i++) {
      var cx = D.x0 + 3 + i * 4;
      b.add("wall_gated", cx, fy, front, 0);
      if (i > 0) { s.box(0.4, 3.9, 3.2, COL.stoneLo, cx - 2, fy + 1.95, D.z0 + 2.5); }
      s.box(0.5, 0.12, 0.5, COL.iron, cx, fy + 3.72, front + 0.72); s.box(0.1, 0.3, 0.1, COL.iron, cx, fy + 3.9, front + 0.6);
      var lamp = new THREE.Mesh(new THREE.BoxGeometry(0.36, 0.44, 0.36), new THREE.MeshBasicMaterial({ color: lc(0x1d2230), toneMapped: false }));
      lamp.position.set(cx, fy + 3.44, front + 0.72); this.scene.add(lamp);
      var glowIn = K.glow(COL.vm, 6.5, 0); glowIn.position.set(cx, fy + 1.8, D.z0 + 2.6); this.scene.add(glowIn);
      var halo = K.glow(COL.vm, 2.6, 0); halo.position.copy(lamp.position); this.scene.add(halo);
      var crate = this.prop("crates_stacked", cx, fy + 0.1, D.z0 + 2.5, i * 0.7, null, 0.62); crate.visible = false;
      this.cells.push({ lamp: lamp, glow: glowIn, halo: halo, crate: crate, job: null, state: "", flash: 0, color: new THREE.Color(COL.vm), x: cx, z: D.z0 + 2.5 });
    }
    // the guard room: stores, a table, torches on the walls you can see
    b.add("barrel_large", D.x0 + 2.2, fy + 0.1, D.z1 - 2.2, 0.4); b.add("barrel_small_stack", D.x0 + 5, fy + 0.1, D.z1 - 1.7, 0);
    b.add("table_medium", D.x0 + 9.5, fy + 0.1, D.z1 - 2.4, 0.3); b.add("candle_triple", D.x0 + 9.5, fy + 1.1, D.z1 - 2.4, 0);
    b.add("keg_decorated", D.x0 + 14.5, fy + 0.1, D.z1 - 1.9, Math.PI); b.add("keyring_hanging", D.x0 + 1.15, fy + 3.3, D.z1 - 4.5, Math.PI / 2);
    this.torch(D.x0 + 1.02, fy + 2.3, D.z0 + 7, Math.PI / 2, 0); this.torch(D.x0 + 1.02, fy + 2.3, D.z1 - 1.6, Math.PI / 2, 0);
    // the wards: four rune stones and a line of light round the rim; lit by the isolation self-test
    this.wardMat = new THREE.MeshBasicMaterial({ color: lc(0x27304a), toneMapped: false });
    var wardGeo = new K.Merger(31);
    [[D.x0 - 1.6, D.z0 - 1.6], [D.x1 + 1.6, D.z0 - 1.6], [D.x0 - 1.6, D.z1 + 1.6], [D.x1 + 1.6, D.z1 + 3.4]].forEach(function (p) {
      var gy = self.land.height(p[0], p[1]);
      s.cyl(0.42, 0.7, 3.4, 4, 0x4b4c60, p[0], gy + 1.6, p[1], 0, 0, Math.PI / 4); s.cone(0.6, 0.8, 4, 0x4b4c60, p[0], gy + 3.7, p[1], Math.PI / 4);
      wardGeo.box(0.16, 1.7, 0.75, 0xffffff, p[0], gy + 1.9, p[1], Math.PI / 4); wardGeo.box(0.75, 1.7, 0.16, 0xffffff, p[0], gy + 1.9, p[1], Math.PI / 4);
    });
    wardGeo.box(D.x1 - D.x0 + 2.4, 0.08, 0.16, 0xffffff, (D.x0 + D.x1) / 2, D.y + 0.2, D.z0 - 1.1); wardGeo.box(D.x1 - D.x0 + 2.4, 0.08, 0.16, 0xffffff, (D.x0 + D.x1) / 2, D.y + 0.2, D.z1 + 1.1);
    wardGeo.box(0.16, 0.08, D.z1 - D.z0 + 2.4, 0xffffff, D.x0 - 1.1, D.y + 0.2, (D.z0 + D.z1) / 2);
    var wards = new THREE.Mesh(wardGeo.geometry(), this.wardMat); this.scene.add(wards);
    this.wardGlow = K.decal(0x59e0ff, 44, 0); this.wardGlow.position.set((D.x0 + D.x1) / 2, D.y + 0.3, (D.z0 + D.z1) / 2); this.scene.add(this.wardGlow);
    var pl = new THREE.PointLight(0xffa860, 1.5, 22, 2); pl.position.set((D.x0 + D.x1) / 2, fy + 3.2, D.z1 - 4); this.scene.add(pl);
    var holder = new THREE.Group(); this.scene.add(holder);
    this.pickBox(holder, D.x1 - D.x0 + 6, 7, D.z1 - D.z0, { kind: "vm" }, (D.x0 + D.x1) / 2 + 2, fy + 3.5, (D.z0 + D.z1) / 2);
    this.dungeonLabel = this.label(new THREE.Vector3((D.x0 + D.x1) / 2, D.y + 7.5, D.z0 - 1), "The dungeon", "sandbox VM", "realm-place", 7);
    // the way a message runs along the road from the castle gate down into the pit
    var path = [], rd = this.land.roads;
    rd.trunkA.forEach(function (p) { if (p.z <= L.junction.z) { path.push(new THREE.Vector3(p.x, p.y + 0.25, p.z)); } });
    rd.dungeon.forEach(function (p) { path.push(new THREE.Vector3(p.x, p.y + 0.25, p.z)); });
    path.push(new THREE.Vector3(D.x1 + 0.4, D.y + 0.3, D.stairZ), new THREE.Vector3(D.x1 - 1.2, D.y + 0.3, D.stairZ), new THREE.Vector3(D.x1 - 5, fy + 0.3, D.stairZ), new THREE.Vector3((D.x0 + D.x1) / 2, fy + 0.3, D.stairZ + 0.5));
    this.vmPath = new THREE.CatmullRomCurve3(path, false, "catmullrom", 0.2);
  };

  Realm.prototype.buildWilds = function () {
    var b = this.batch, land = this.land, w = L.wilds, self = this, s = this.stone;
    function put(name, x, z, ry, tiltScale) { b.add(name, x, land.height(x, z) - 0.12, z, ry, tiltScale || 1); }
    put("rubble_large", -15.5, 34.2, 0.5, 0.8); put("rubble_large", 16, 44.5, -0.5, 0.8);
    put("pillar", -3.6, 31.6, 0.1, 0.9); put("pillar", 3.6, 31.6, -0.2, 0.9);
    put("column", -11, 46.6, 0.4); put("column", 13.4, 34.6, 1.0); put("wall_half", -17.2, 41.6, 1.2, 0.85); put("wall_half", 8.2, 47.2, 0.2, 0.8);
    // lanterns at the gate of the wilds, with a sickly flame
    this.lamp(-3.6, 30.0, Math.PI / 2, 0x9dff8a); this.lamp(3.6, 30.0, -Math.PI / 2, 0x9dff8a);
    var gl = new THREE.PointLight(0x8dffb0, 1.1, 34, 2); gl.position.set(w.x, 5, w.z); this.scene.add(gl);
    // mist that drifts over the graves (ambient)
    this.mist = [];
    for (var i = 0; i < 9; i++) {
      var m = K.glow(0x9fb6c9, 13 + (i % 3) * 4, 0.085, true);
      m.position.set(w.x + Math.cos(i * 2.4) * (w.rx - 3) * (0.3 + (i % 4) * 0.2), 1.6, w.z + Math.sin(i * 2.4) * (w.rz - 1) * 0.8);
      this.scene.add(m); this.mist.push({ sprite: m, x: m.position.x, z: m.position.z, seed: i * 1.3 });
    }
    // banners for the horde: when there are more findings than bodies, the rest are counted here by severity
    this.hordes = {};
    W.SEVERITIES.forEach(function (sev, k) {
      var x = w.x - 10 + k * 5, z = w.z + w.rz + 2.2 - Math.abs(k - 2) * 0.7, y = land.height(x, z), g = new THREE.Group(), size = 1.9 - k * 0.25;
      var pole = new K.Merger(40 + k); pole.cyl(0.08, 0.11, 4.6, 5, COL.wood, 0, 2.3, 0); pole.mesh(g);
      g.position.set(x, y, z); g.visible = false; self.scene.add(g);
      var flag = self.flag(x, y + 4.6 - size * 0.42, z, W.SEV_COLORS[sev], size, k + 5); flag.visible = false;
      var lab = self.label(new THREE.Vector3(x, y + 5.3, z), "", "", "foe horde", 4); lab.hidden = true;
      self.hordes[sev] = { group: g, flag: flag, label: lab };
    });
    void s;
    this.wildsLabel = this.label(new THREE.Vector3(w.x, 1.2, w.z + w.rz + 5.6), "The wilds", "your project · findings rise here", "realm-place", 6);
    var holder = new THREE.Group(); this.scene.add(holder);
  };

  Realm.prototype.buildRoadside = function () {
    this.lamp(1.9, 17.6, Math.PI, COL.window);                       // the crossroads below the gate
    this.lamp(18.5, 17.9, Math.PI * 1.1, COL.window); this.lamp(-17.5, 17.6, Math.PI * 0.9, COL.window);
    this.lamp(27.4, 11.6, -Math.PI / 2, 0xd9b8ff);
    var s = this.stone, y = this.land.ground(-1.9, 17.3);           // a signpost: three roads meet here
    s.cyl(0.1, 0.13, 2.4, 5, COL.wood, -1.9, y + 1.2, 17.3);
    s.box(1.3, 0.3, 0.08, COL.wood, -1.3, y + 2.1, 17.3, -0.2); s.box(1.3, 0.3, 0.08, COL.wood, -2.5, y + 1.7, 17.3, 0.25); s.box(0.08, 0.3, 1.2, COL.wood, -1.9, y + 1.3, 17.9, 0.1);
  };

  // ------------------------------------------------------------------ labels (DOM: crisp at any zoom)

  Realm.prototype.label = function (pos, title, sub, cls, prio) {
    var el = document.createElement("div");
    el.className = "realm-label" + (cls ? " " + cls : "");
    var t = document.createElement("strong"); t.textContent = title; el.appendChild(t);
    var s = document.createElement("span"); s.textContent = sub || ""; el.appendChild(s);
    this.overlay.appendChild(el);
    var l = { el: el, title: t, sub: s, pos: pos, follow: null, offset: 0, prio: prio || 1, w: 0, h: 0, dirty: true, shown: true };
    this.labels.push(l);
    return l;
  };
  Realm.prototype.removeLabel = function (l) {
    if (!l) { return; }
    if (l.el.parentNode) { l.el.parentNode.removeChild(l.el); }
    this.labels = this.labels.filter(function (x) { return x !== l; });
  };
  Realm.prototype.setLabel = function (l, title, sub) {
    if (l.title.textContent !== title) { l.title.textContent = title; l.dirty = true; }
    if (l.sub.textContent !== (sub || "")) { l.sub.textContent = sub || ""; l.dirty = true; }
  };
  Realm.prototype.setClass = function (l, cls, on) {
    if (l.el.classList.contains(cls) !== !!on) { l.el.classList.toggle(cls, !!on); l.dirty = true; }
  };
  /* Put each label over its thing; where two would overlap, the less important one steps aside or hides. */
  Realm.prototype.placeLabels = function () {
    var v = new THREE.Vector3(), self = this, live = [], placed = [], i, k;
    this.labels.forEach(function (l) {
      if (l.hidden) { if (l.shown) { l.el.style.display = "none"; l.shown = false; } return; }
      if (l.follow) { v.copy(l.follow.position); v.y += l.offset; } else { v.copy(l.pos); }
      v.project(self.camera);
      if (v.z > 1 || Math.abs(v.x) > 1.15 || Math.abs(v.y) > 1.15) { if (l.shown) { l.el.style.display = "none"; l.shown = false; } return; }
      l.sx = (v.x + 1) / 2 * self.w; l.sy = (1 - v.y) / 2 * self.h;
      live.push(l);
    });
    live.sort(function (a, b) { return b.prio - a.prio; });
    for (i = 0; i < live.length; i++) {
      var l = live[i], ok = false;
      if (!l.shown) { l.el.style.display = ""; l.shown = true; l.dirty = true; }
      if (l.dirty) { l.w = l.el.offsetWidth; l.h = l.el.offsetHeight; l.dirty = false; }
      var x0 = l.sx - l.w / 2, y0 = l.sy - l.h;
      for (var tryN = 0; tryN < 3 && !ok; tryN++) {
        ok = true;
        for (k = 0; k < placed.length; k++) {
          var p = placed[k];
          if (x0 < p.x1 + 4 && x0 + l.w > p.x0 - 4 && y0 < p.y1 + 2 && y0 + l.h > p.y0 - 2) { ok = false; break; }
        }
        if (!ok) { y0 -= l.h + 3; }
      }
      if (!ok) { l.el.style.display = "none"; l.shown = false; continue; }
      placed.push({ x0: x0, y0: y0, x1: x0 + l.w, y1: y0 + l.h });
      l.el.style.transform = "translate(" + Math.round(x0) + "px," + Math.round(y0) + "px)";
    }
  };

  // ------------------------------------------------------------------ entities from the world

  Realm.prototype.hero = function (key, name, cls) {
    if (this.heroes[key]) { return this.heroes[key]; }
    var champion = cls === "Champion", n = Object.keys(this.heroes).filter(function (k) { return (k.indexOf("backend:") === 0) === champion; }).length;
    var kind = champion ? CHAMPIONS[n % CHAMPIONS.length] : null;
    var a = new Actor(this, champion ? kind.model : (HERO_MODEL[cls] || "knight"), champion ? 1.14 : 1, champion ? kind.gear : LOADOUT[cls]);
    a.cls = cls; a.key = key; a.name = name; a.champion = champion; a.attack = champion ? kind.attack : null;
    var c = L.core.y + 0.1, at = champion ? CHAMP_AT[n % CHAMP_AT.length] : CAMP[n % CAMP.length];
    a.camp = new THREE.Vector3(at[0], c, at[1]);
    a.spot = this.spots[n % this.spots.length];
    a.root.position.copy(a.camp);
    a.root.rotation.y = champion ? Math.atan2(-at[0], -at[1]) : Math.atan2(FIRE_AT[0] - at[0], FIRE_AT[1] - at[1]);
    if (!champion && n >= 6) { a.root.rotation.y = n < 8 ? 0 : Math.atan2(-at[0], -at[1]); }
    a.homeTurn = a.root.rotation.y;
    if (champion) { a.ring = K.decal(0xffd36e, 3.4, 0.55); a.ring.position.y = 0.12; a.root.add(a.ring); }
    a.scan = K.decal(COL.scan, 1, 0); a.scan.position.y = 0.14; a.root.add(a.scan);
    this.scene.add(a.root);
    a.label = this.label(null, name, cls, champion ? "champion" : "", 3);
    a.label.follow = a.root; a.label.offset = champion ? 3.5 : 3.0;
    this.pickBox(a.root, 1.7, 2.7, 1.7, champion ? { kind: "backend", key: name } : { kind: "scanner", key: name });
    a.play("Idle_A");
    this.heroes[key] = a;
    return a;
  };

  Realm.prototype.slotFor = function (f) {
    if (this.slotOf[f.id] !== undefined) { return this.slots[this.slotOf[f.id]]; }
    var hero = f.tool && this.heroes["scanner:" + f.tool], from = hero ? hero.spot : { x: L.wilds.x, z: L.wilds.z - 3 }, best = -1, bd = 1e9;
    for (var i = 0; i < this.slots.length; i++) {
      if (this.slotUsed[i]) { continue; }
      var d = (this.slots[i].x - from.x) * (this.slots[i].x - from.x) + (this.slots[i].z - from.z) * (this.slots[i].z - from.z);
      if (d < bd) { bd = d; best = i; }
    }
    if (best < 0) { return null; }
    this.slotUsed[best] = true; this.slotOf[f.id] = best;
    return this.slots[best];
  };

  Realm.prototype.foe = function (f) {
    if (this.foes[f.id]) { return this.foes[f.id]; }
    var slot = this.slotFor(f);
    if (!slot) { return null; }
    var spec = FOE[f.severity] || FOE.info;
    var a = new Actor(this, spec.model, spec.scale, { r: spec.r, l: spec.l });
    a.finding = f; a.spec = spec;
    a.root.position.set(slot.x, this.land.ground(slot.x, slot.z), slot.z);
    a.homeTurn = Math.atan2(-slot.x, 6 - slot.z) + slot.turn; // facing the castle, each a little differently
    a.root.rotation.y = a.homeTurn;
    a.ring = K.decal(spec.glow, 3.6 * spec.scale, 0.6); a.ring.position.y = 0.12; a.root.add(a.ring);
    this.scene.add(a.root);
    this.pickBox(a.root, 1.5, 2.5 * spec.scale, 1.5, { kind: "finding", key: f.id });
    a.label = this.label(null, f.id, "", "foe", 3); a.label.follow = a.root; a.label.offset = 2.5 * spec.scale + 0.5; a.label.hidden = true;
    a.index = Object.keys(this.foes).length;
    this.foes[f.id] = a;
    return a;
  };

  Realm.prototype.oracle = function (id, i) {
    if (this.oracles[id]) { return this.oracles[id]; }
    var m = this.world.models[id], fallback = m && m.role === "fallback";
    var a = new Actor(this, fallback ? "rogue_hooded" : "mage", fallback ? 0.95 : 1.08, fallback ? { r: "wand" } : { r: "staff", l: "spellbook_open" });
    var side = [2.9, -2.9, 5.0, -5.0][i % 4], at = this.towerPoint(side, 0, 5.2);
    a.root.position.set(at.x, this.land.ground(at.x, at.z), at.z);
    a.root.rotation.y = L.tower.door + (side > 0 ? -0.35 : 0.35);
    this.scene.add(a.root);
    // the oracle's orb stands on its own pedestal on the tower's parapet
    var ang = [0.6, -0.6, 1.5, -1.5][i % 4], r = fallback ? 0.5 : 0.72, base = this.towerPoint(Math.sin(ang) * 3.2, 14.0, Math.cos(ang) * 3.2);
    var ped = new K.Merger(50 + i); ped.cyl(0.3, 0.44, 1.5, 6, COL.stoneLo, 0, 0.75, 0); ped.cyl(0.5, 0.3, 0.3, 6, COL.iron, 0, 1.6, 0);
    var pm = ped.mesh(this.scene); pm.position.copy(base);
    var orb = new THREE.Mesh(new THREE.IcosahedronGeometry(r, 1),
      new THREE.MeshStandardMaterial({ color: lc(0xcdbdff), emissive: lc(fallback ? 0x4f7bff : 0x7b5cff), emissiveIntensity: 1.1, roughness: 0.2, flatShading: true }));
    orb.position.copy(base); orb.position.y += 1.75 + r; this.scene.add(orb);
    var halo = K.glow(fallback ? 0x7b9cff : 0x9d7bff, 4, 0.55); halo.position.copy(orb.position); this.scene.add(halo);
    a.orb = orb; a.halo = halo; a.id = id; a.orbY = orb.position.y; a.orbR = r; a.flash = 0; a.fail = 0;
    a.label = this.label(null, m ? m.name : W.short(id), fallback ? "fallback oracle" : "oracle", "oracle", 5);
    a.label.follow = a.root; a.label.offset = 3.2;
    this.pickBox(a.root, 1.7, 2.8, 1.7, { kind: "model", key: id });
    var ob = new THREE.Group(); ob.position.copy(orb.position); this.scene.add(ob); this.pickBox(ob, 2, 2, 2, { kind: "model", key: id }, 0, 0, 0);
    a.play("Idle_B");
    this.oracles[id] = a;
    return a;
  };

  /* Does this finding get a body? The first forty do, and so does any finding a champion goes after. */
  Realm.prototype.bodied = function (f) { return f.index < MAX_BODIES || !!f.backend || this.world.duel === f.id; };

  /* Make the scene match the world. `instant`: a burst or a run opened after the fact - everything is
     put where it belongs, in its final pose, without walking or playing an entrance. */
  Realm.prototype.reconcile = function (instant) {
    if (!this.ready) { return; }
    var wd = this.world, self = this;
    wd.scannerOrder.forEach(function (n) { self.hero("scanner:" + n, n, (wd.scanners[n] || {}).cls || "Squire"); });
    Object.keys(wd.backends).forEach(function (b) { self.hero("backend:" + b, b, "Champion"); });
    wd.modelOrder.forEach(function (id, i) { self.oracle(id, i); });
    var over = {};
    wd.findings.forEach(function (f) {
      if (!self.bodied(f)) { over[f.severity] = (over[f.severity] || 0) + 1; return; }
      var isNew = !self.foes[f.id], a = self.foe(f);
      if (!a) { over[f.severity] = (over[f.severity] || 0) + 1; return; }
      if (isNew && !instant) { a.once("Skeletons_Awaken_Floor", 2.2, 0); a.risen = self.time; self.rise(a); }
      else if (isNew) { a.risen = -99; self.poseFoe(a, 0); }
    });
    W.SEVERITIES.forEach(function (sev) {
      var h = self.hordes[sev], n = over[sev] || 0;
      h.group.visible = h.flag.visible = n > 0; h.label.hidden = n === 0;
      if (n) { self.setLabel(h.label, "+" + n + " " + sev, "more " + (W.MONSTERS[sev] || "bones").toLowerCase() + "s"); }
    });
    var llm = wd.topology.llm || {}, vm = wd.topology.vm || {};
    this.setLabel(this.towerLabel, "Oracle tower", "LLM gateway · " + (llm.host || "not set up"));
    this.setLabel(this.dungeonLabel, "The dungeon", "sandbox VM · " + (vm.host || "not set up") + (wd.kind === "scan" ? " · scans never enter" : ""));
    // cells: the newest five jobs, one per cell
    this.cells.forEach(function (c) { c.next = null; });
    wd.jobOrder.forEach(function (id, i) { self.cells[i % self.cells.length].next = wd.jobs[id]; });
    this.cells.forEach(function (c) {
      var j = c.next, state = j ? j.state : "";
      if (c.job !== (j ? j.id : null) || c.state !== state) {
        if (!instant && j && state !== "running" && c.job === j.id) { c.flash = 1; }
        c.job = j ? j.id : null; c.state = state;
        c.color.copy(lc(state === "running" ? COL.vm : state === "done" ? COL.ok : state === "failed" ? COL.bad : 0x1d2230));
        c.crate.visible = !!j;
      }
    });
    if (instant) { this.snap = true; }
    this.refreshCore();
  };

  Realm.prototype.refreshCore = function () {
    var wd = this.world;
    if (!this.coreLabel) { return; }
    var sub = !wd.kind ? "this machine · waiting for a run" : wd.ended ? (wd.kind + " finished · exit " + wd.exitCode + (wd.exitCode === 0 ? " · victory" : " · not clean"))
      : (wd.kind + " · " + wd.project);
    this.setLabel(this.coreLabel, "CodeSift castle", sub);
    this.setClass(this.coreLabel, "won", wd.ended && wd.exitCode === 0);
    this.setClass(this.coreLabel, "lost", wd.ended && wd.exitCode !== 0);
  };

  /* The pose a skeleton rests in, from its fate. */
  Realm.prototype.poseFoe = function (a, fade) {
    var fate = W.fate(a.finding);
    a.play(fate === "slain" ? "Skeletons_Death_Pose" : fate === "wounded" ? "Sit_Floor_Idle" : "Skeletons_Idle", { fade: fade });
  };

  // ------------------------------------------------------------------ effects of real events

  Realm.prototype.burst = function (pos, color, n, size, up) {
    var parts = [];
    for (var i = 0; i < n; i++) {
      var s = K.glow(color, size * (0.6 + Math.random() * 0.7), 1); s.position.copy(pos); this.scene.add(s);
      var a = Math.random() * 6.283, sp = 2 + Math.random() * 3.5;
      parts.push({ s: s, vx: Math.cos(a) * sp, vy: (up || 2) + Math.random() * 3, vz: Math.sin(a) * sp });
    }
    var t = 0, scene = this.scene;
    this.fx.push({ update: function (dt) {
      t += dt * 1.5;
      parts.forEach(function (p) { p.s.position.x += p.vx * dt; p.s.position.y += p.vy * dt; p.s.position.z += p.vz * dt; p.vy -= 7 * dt; p.s.material.opacity = Math.max(0, 1 - t); });
      return t < 1;
    }, dispose: function () { parts.forEach(function (p) { scene.remove(p.s); p.s.material.dispose(); }); } });
  };

  /* A pool of light on the ground that grows and fades. */
  Realm.prototype.ripple = function (pos, color, size, seconds) {
    var d = K.decal(color, 1, 0.9), t = 0, scene = this.scene; d.position.copy(pos); scene.add(d);
    this.fx.push({ update: function (dt) { t += dt / (seconds || 1); d.scale.set(1 + size * t, 1, 1 + size * t); d.material.opacity = 0.9 * (1 - t); return t < 1; },
      dispose: function () { scene.remove(d); d.material.dispose(); } });
  };

  Realm.prototype.rise = function (a) { // a finding is detected: the ground breaks and a column of light marks the spot
    var p = a.root.position, color = a.spec.glow, scene = this.scene, t = 0;
    var beam = new THREE.Mesh(new THREE.CylinderGeometry(0.16 * a.spec.scale, 0.5 * a.spec.scale, 11, 8, 1, true),
      new THREE.MeshBasicMaterial({ color: lc(color), transparent: true, opacity: 0.32, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide, fog: false }));
    beam.position.set(p.x, p.y + 5.5, p.z); scene.add(beam);
    this.fx.push({ update: function (dt) { t += dt / 1.5; beam.material.opacity = 0.32 * (1 - t); beam.scale.set(1 - t * 0.6, 1, 1 - t * 0.6); return t < 1; },
      dispose: function () { scene.remove(beam); beam.geometry.dispose(); beam.material.dispose(); } });
    this.burst(new THREE.Vector3(p.x, p.y + 0.4, p.z), 0x9a8f7a, 7, 0.9, 3);
    this.ripple(new THREE.Vector3(p.x, p.y + 0.15, p.z), color, 7, 1.1);
  };

  var ravenGeo = null;
  function ravenParts() {
    if (ravenGeo) { return ravenGeo; }
    var body = new K.Merger(60);
    body.add(new THREE.OctahedronGeometry(0.34, 0), COL.raven, K.mat(0, 0, 0, 0, 0, 0, 0.75, 0.62, 2.1), 0.2);
    body.add(new THREE.OctahedronGeometry(0.2, 0), COL.raven, K.mat(0, 0.12, 0.72, 0, 0, 0, 1, 1, 1.2), 0.2);
    body.add(new THREE.ConeGeometry(0.07, 0.34, 4), 0xd9a441, K.mat(0, 0.1, 1.05, Math.PI / 2, 0, 0), 0);
    body.box(0.36, 0.04, 0.6, COL.raven, 0, 0.02, -0.85);
    var wing = new THREE.BufferGeometry();
    wing.setAttribute("position", new THREE.Float32BufferAttribute([0, 0, 0.42, 0, 0, -0.42, 1.0, 0, 0.1, 1.0, 0, 0.1, 0, 0, -0.42, 1.25, 0, -0.5, 1.0, 0, 0.1, 1.25, 0, -0.5, 2.0, 0, -0.15], 3));
    wing.computeVertexNormals();
    ravenGeo = { body: body.geometry(), wing: wing };
    return ravenGeo;
  }

  /* One LLM call: a raven carrying a light. `fail`: it never arrives - it turns grey and falls. */
  Realm.prototype.raven = function (from, to, color, size, fail, onArrive) {
    var parts = ravenParts(), g = new THREE.Group(), self = this, scene = this.scene;
    var bodyMat = new THREE.MeshStandardMaterial({ vertexColors: true, flatShading: true, roughness: 0.8 });
    var wingMat = new THREE.MeshStandardMaterial({ color: lc(0x2a2b3a), side: THREE.DoubleSide, flatShading: true, roughness: 0.8 });
    var body = new THREE.Mesh(parts.body, bodyMat), wl = new THREE.Mesh(parts.wing, wingMat), wr = new THREE.Mesh(parts.wing, wingMat);
    wr.scale.x = -1; g.add(body); g.add(wl); g.add(wr);
    var light = K.glow(color, 3.2, 0.95); light.position.set(0, -0.35, 0.2); g.add(light);
    var sc = 1.15 + (size || 0) * 0.95; g.scale.setScalar(sc);
    scene.add(g);
    var mid = from.clone().add(to).multiplyScalar(0.5); mid.y += 7 + from.distanceTo(to) * 0.12;
    var curve = new THREE.QuadraticBezierCurve3(from, mid, to), t = 0, dur = 1.5 + from.distanceTo(to) / 34, tmp = new THREE.Vector3(), vel = null, spin = 0;
    var trail = [];
    for (var i = 0; i < 5; i++) { var tr = K.glow(color, 1.6 - i * 0.22, 0.5 - i * 0.09); scene.add(tr); trail.push(tr); }
    this.fx.push({ update: function (dt) {
      if (!vel) {
        t += dt / dur;
        var u = t < 0.5 ? 2 * t * t : 1 - 2 * (1 - t) * (1 - t);
        curve.getPoint(Math.min(1, u), g.position);
        curve.getPoint(Math.min(1, u + 0.02), tmp); g.lookAt(tmp);
        trail.forEach(function (tr, k) { curve.getPoint(Math.max(0, u - 0.022 * (k + 1)), tr.position); });
        var flap = Math.sin(self.time * 17) * 0.75;
        wl.rotation.z = flap; wr.rotation.z = -flap;
        if (fail && t > 0.46) { // the call failed: the raven is lost on the way
          curve.getTangent(u, tmp); vel = tmp.clone().multiplyScalar(curve.getLength() / dur * 0.5);
          wingMat.color.copy(lc(COL.grey)); bodyMat.color.copy(lc(0x9a9ca8)); light.material.color.copy(lc(COL.bad));
          self.burst(g.position.clone(), COL.bad, 8, 1.1, 1);
          trail.forEach(function (tr) { tr.visible = false; });
        }
        if (t >= 1) { if (onArrive) { onArrive(); } return false; }
        return true;
      }
      vel.y -= 16 * dt; g.position.addScaledVector(vel, dt); spin += dt * 9;
      g.rotation.set(spin, spin * 0.6, spin * 0.3); wl.rotation.z = 1.1; wr.rotation.z = -1.1;
      light.material.opacity = Math.max(0, light.material.opacity - dt * 1.2);
      if (g.position.y <= self.land.height(g.position.x, g.position.z) + 0.3) { self.burst(g.position.clone(), COL.grey, 6, 0.8, 1.5); return false; }
      return true;
    }, dispose: function () { scene.remove(g); bodyMat.dispose(); wingMat.dispose(); light.material.dispose(); trail.forEach(function (tr) { scene.remove(tr); tr.material.dispose(); }); } });
  };

  /* One command to the sandbox VM: a rune that runs along the road and down the dungeon stairs (or back). */
  Realm.prototype.rune = function (back, color, onArrive) {
    var scene = this.scene, path = this.vmPath, t = 0, self = this, p = new THREE.Vector3();
    var d = K.decal(color, 3.4, 0.95), head = K.glow(color, 2.2, 0.95), trail = [];
    scene.add(d); scene.add(head);
    for (var i = 0; i < 6; i++) { var tr = K.decal(color, 2.4 - i * 0.3, 0.5 - i * 0.07); scene.add(tr); trail.push(tr); }
    this.fx.push({ update: function (dt) {
      t += dt / 1.25;
      var u = Math.min(1, t), w = back ? 1 - u : u;
      path.getPoint(w, p); d.position.copy(p); head.position.set(p.x, p.y + 0.7 + Math.sin(self.time * 14) * 0.15, p.z);
      trail.forEach(function (tr, k) { path.getPoint(Math.min(1, Math.max(0, w + (back ? 1 : -1) * 0.02 * (k + 1))), tr.position); });
      if (t >= 1) { if (onArrive) { onArrive(p); } return false; }
      return true;
    }, dispose: function () { scene.remove(d); scene.remove(head); d.material.dispose(); head.material.dispose(); trail.forEach(function (tr) { scene.remove(tr); tr.material.dispose(); }); } });
  };

  Realm.prototype.look = function (x, z, dist, hold, prio) { // ask the camera to visit a spot for a while
    if (this.reduced || this.real < this.handsOff) { return; }
    if (this.focus && this.real < this.focus.until && this.focus.prio > prio && this.real - this.focus.since < 3) { return; }
    this.focus = { x: x, y: this.land.height(x, z) + 2, z: z, dist: dist, until: this.real + hold, prio: prio, since: this.real };
  };

  Realm.prototype.champion = function (f) { return f && f.backend ? this.heroes["backend:" + f.backend] : null; };

  Realm.prototype.effects = function (fx, animate) {
    if (!this.ready) { return; }
    var self = this, wd = this.world, D = L.dungeon;
    this.reconcile(!animate);
    if (!animate) { return; }
    fx.forEach(function (e) {
      var foe = e.finding ? self.foes[e.finding.id] : null, hero = e.finding ? self.champion(e.finding) : null, o;
      switch (e.kind) {
        case "scan":
          if (e.from === "core") { self.core.activity = Math.min(1, self.core.activity + 0.4); self.look(0, 27, 74, 7, 1); }
          break;
        case "finding":
          if (foe) { self.look(foe.root.position.x * 0.5, 36, 62, 5, 2); }
          break;
        case "llm":
          o = self.oracles[e.to.slice(6)];
          self.core.activity = Math.min(1, self.core.activity + 0.35);
          self.raven(self.beaconTop.clone(), o ? o.orb.position.clone() : self.towerTop.clone(), COL.llm, e.size, false, function () { if (o) { o.flash = 1; } self.tower.flash = 1; });
          break;
        case "reply":
          o = self.oracles[e.from.slice(6)];
          self.raven(o ? o.orb.position.clone() : self.towerTop.clone(), self.beaconTop.clone(), COL.reply, e.size, false, function () { self.core.activity = 1; });
          break;
        case "fail":
          if (e.from.indexOf("model:") === 0) {
            o = self.oracles[e.from.slice(6)];
            if (o) { o.fail = 1; self.burst(o.orb.position.clone(), COL.bad, 10, 1.3, 2); }
            self.raven(o ? o.orb.position.clone() : self.towerTop.clone(), self.beaconTop.clone(), COL.reply, 0.3, true);
            self.look(L.tower.x - 6, L.tower.z + 4, 60, 5, 4);
          } else if (e.from === "vm") {
            self.rune(true, COL.bad, function () { self.core.activity = 1; });
          }
          break;
        case "vm":
          if (e.from === "core") { self.rune(false, COL.vm, function (p) { self.ripple(p, COL.vm, 9, 0.8); }); if (e.job) { self.look((D.x0 + D.x1) / 2 + 3, 6, 50, 4.5, 2); } }
          else { self.rune(true, COL.ok, function () { self.core.activity = Math.min(1, self.core.activity + 0.5); }); }
          break;
        case "wards":
          self.wardFlash = 1; self.look((D.x0 + D.x1) / 2 + 3, 6, 56, 3.5, 2);
          break;
        case "attack":
          if (foe) { self.look(foe.root.position.x, foe.root.position.z - 2, 44, 7, 3); }
          break;
        case "stage":
          if (foe && e.stage === "verify") { self.look(foe.root.position.x, foe.root.position.z - 2, 40, 5, 3); }
          break;
        case "policy":
          if (foe) { self.burst(foe.root.position.clone().setY(foe.root.position.y + 3.4), e.ok ? COL.reply : COL.bad, 6, 0.8, 1); if (!e.ok && hero && hero.atDuel) { hero.once("Hit_A", 0.67); } }
          break;
        case "gate":
          if (!foe) { break; }
          var mid = foe.root.position.clone().setY(foe.root.position.y + 1.6);
          if (e.status === "pass") {
            if (hero && hero.atDuel) { hero.once("Melee_1H_Attack_Chop", 0.9); mid.lerp(hero.root.position, 0.4).setY(foe.root.position.y + 1.6); }
            foe.once("Hit_A", 0.67); self.burst(mid, COL.ok, 9, 1.1, 2);
          } else if (e.status === "fail") {
            foe.once("Melee_1H_Attack_Chop", 1.0);
            if (hero && hero.atDuel) { hero.once("Hit_A", 0.67); }
            self.burst(mid, COL.bad, 9, 1.1, 2);
          } else { self.burst(mid.setY(mid.y + 1.6), COL.grey, 4, 0.7, 0.6); }
          break;
        case "outcome":
          if (!foe) { break; }
          o = W.fate(e.finding);
          if (o === "slain") { foe.once("Skeletons_Death", 2.0); if (hero) { hero.once("Cheering", 2.4); } self.burst(foe.root.position.clone().setY(foe.root.position.y + 1.5), COL.ok, 14, 1.3, 3); }
          else if (o === "wounded") { foe.once("Hit_A", 0.67); self.burst(foe.root.position.clone().setY(foe.root.position.y + 1.5), 0xf5a524, 8, 1.0, 2); }
          else if (o === "escaped") { foe.once("Skeletons_Taunt", 1.03); if (hero && hero.atDuel) { hero.once("Hit_A", 0.67); } self.burst(foe.root.position.clone().setY(foe.root.position.y + 2.6), COL.bad, 8, 1.0, 2); }
          if (hero) { hero.lingerUntil = self.time + 2.4; }
          self.look(foe.root.position.x, foe.root.position.z - 2, 40, 3.5, 3);
          break;
        case "end":
          self.endedAt = self.time; self.focus = null;
          self.burst(self.beaconTop.clone(), e.ok ? COL.ok : COL.bad, 22, 2.2, 5);
          Object.keys(self.foes).forEach(function (k, i) { var f = self.foes[k], fate = W.fate(f.finding); if (!e.ok && fate !== "slain" && fate !== "wounded") { f.tauntAt = self.time + 0.2 + (i % 5) * 0.25; f.taunts = 3; } });
          break;
        default: break;
      }
    });
    void wd;
  };

  // ------------------------------------------------------------------ per frame

  var SIDES = [1.57, -1.57, 2.3, -2.3, 3.14, 0.8, -0.8, 0]; // beside it first, so the camera sees both fighters
  Realm.prototype.duelSpot = function (foe) { // where a champion stands to fight this skeleton: the clearest side
    if (foe.duelAt) { return foe.duelAt; }
    var p = foe.root.position, best = null, bs = -1, self = this;
    for (var i = 0; i < 8; i++) {
      var a = SIDES[i], x = p.x + Math.sin(a) * 2.0, z = p.z + Math.cos(a) * 2.0, near = 9;
      Object.keys(self.foes).forEach(function (k) { var q = self.foes[k].root.position; if (self.foes[k] !== foe) { near = Math.min(near, Math.sqrt((q.x - x) * (q.x - x) + (q.z - z) * (q.z - z))); } });
      var score = Math.min(near, 2.6) - i * 0.12;
      if (score > bs) { bs = score; best = new THREE.Vector3(x, 0, z); }
    }
    foe.duelAt = best;
    return best;
  };

  Realm.prototype.updateHeroes = function (dt) {
    var wd = this.world, self = this, t = this.time;
    var cheer = wd.ended && wd.exitCode === 0 && this.endedAt !== undefined && t < this.endedAt + 9;
    Object.keys(this.heroes).forEach(function (k) {
      var h = self.heroes[k], s = h.champion ? null : wd.scanners[h.name], status = s ? s.status : "ready";
      var mode = "camp", target = h.camp, foe = null, f = null;
      if (s && status === "running") { mode = "search"; target = h.spot; }
      if (h.champion) {
        f = wd.duel ? wd.byId[wd.duel] : null;
        if (f && f.backend === h.name && !f.outcome && self.foes[f.id]) { foe = self.foes[f.id]; mode = "duel"; target = self.duelSpot(foe); h.lastFoe = foe; }
        else if (h.lingerUntil && t < h.lingerUntil && h.lastFoe) { foe = h.lastFoe; mode = "linger"; target = self.duelSpot(foe); }
      }
      var key = mode + ":" + target.x.toFixed(1) + ":" + target.z.toFixed(1);
      if (h.wantKey !== key) { h.wantKey = key; h.path = self.land.route(h.root.position, target); }
      if (self.snap) { h.path = []; h.root.position.set(target.x, self.land.ground(target.x, target.z), target.z); if (mode === "camp") { h.root.rotation.y = h.homeTurn; } }
      var there = h.walk(dt, mode === "camp" ? 8.5 : 11);
      h.atDuel = there && (mode === "duel" || mode === "linger");
      h.scan.material.opacity = 0;
      if (!there) { h.play("Running_A"); }
      else if (mode === "search") {
        h.play(SEARCH[h.cls] || "Interact");
        var ph = (t * 0.7 + h.root.position.x * 0.13) % 1; // the scanner is running: a sweep of light over the ground
        h.scan.scale.set(2 + ph * 9, 1, 2 + ph * 9); h.scan.material.opacity = 0.7 * (1 - ph);
      } else if (h.atDuel) {
        h.faceTo(foe.root.position.x, foe.root.position.z, dt);
        foe.duelStamp = self.frame; foe.duelWith = h;
        if (mode === "duel" && f.stage === "fix") {
          h.play(h.attack);
          var len = CLIP_LEN[h.attack] || 1.07, phase = h.current ? (h.current.time % len) / len : 0, mark = h.attack === "Melee_2H_Attack_Spin" ? 0.5 : 0.42;
          if (h.currentName === h.attack && h.prevPhase < mark && phase >= mark) { // the blow lands: the skeleton blocks or reels
            foe.blocks = !foe.blocks; foe.once(foe.blocks ? "Melee_Block" : "Hit_A", 0.6);
            self.burst(foe.root.position.clone().lerp(h.root.position, 0.35).setY(foe.root.position.y + 1.7), 0xfff0c2, 4, 0.6, 1.5);
          }
          h.prevPhase = phase;
        } else if (mode === "duel") { h.play(f.stage === "sandbox" || f.stage === "verify" ? "Melee_Block" : "Idle_B"); }
        else { h.play("Idle_A"); }
      } else {
        h.turn(h.homeTurn, dt);
        if (cheer) { h.play("Cheering"); }
        else if (status === "skipped") { h.play("Sit_Floor_Idle"); }
        else if (status === "error") { h.play("Death_A_Pose"); }
        else { h.play(status === "ok" ? "Idle_A" : "Idle_B"); }
      }
      if (h.ring) { h.ring.material.opacity = mode === "duel" ? 0.6 + 0.2 * Math.sin(t * 5) : 0.3; }
      // labels: full for heroes at work; at camp only on hover or when chosen, so the courtyard stays readable
      var busy = mode !== "camp" || (cheer && h.champion);
      h.label.hidden = !(busy || h.picked || h.hover);
      h.label.prio = mode === "duel" ? 9 : busy ? 6 : 8;
      self.setClass(h.label, "bad", status === "error");
      var sub = status === "running" ? h.cls + (there ? " · searching" : " · riding out") : status === "ok" ? h.cls + (there ? "" : " · riding home") + " · " + s.findings + " found · " + W.fmtS(s.duration)
        : status === "skipped" ? h.cls + " · stayed at camp" : status === "error" ? h.cls + " · fallen" : h.cls;
      if (h.champion) { sub = mode === "duel" ? "champion · " + f.stage + " " + f.id : "champion · " + (wd.backends[h.name] || 0) + " attempt" + ((wd.backends[h.name] || 0) === 1 ? "" : "s"); }
      self.setLabel(h.label, h.name, sub);
      h.update(dt);
    });
  };

  Realm.prototype.updateFoes = function (dt) {
    var self = this, t = this.time, wd = this.world;
    Object.keys(this.foes).forEach(function (k) {
      var a = self.foes[k], f = a.finding, fate = W.fate(f), dueling = a.duelStamp === self.frame;
      if (a.tauntAt && t >= a.tauntAt && a.taunts > 0) { a.once("Skeletons_Taunt", 1.03); a.taunts -= 1; a.tauntAt = a.taunts ? t + 1.9 : 0; }
      if (dueling && !fate) {
        a.faceTo(a.duelWith.root.position.x, a.duelWith.root.position.z, dt);
        if (f.stage !== "fix" && t > (a.nextTaunt || 0) && t > a.lockUntil) { a.nextTaunt = t + 4.5; if (a.nextTauntArmed) { a.once("Skeletons_Taunt", 1.03); } a.nextTauntArmed = true; }
        a.play("Skeletons_Idle");
      } else {
        if (!fate) { a.turn(a.homeTurn, dt); }
        self.poseFoe(a);
      }
      if (self.snap) { a.lockUntil = 0; self.poseFoe(a, 0); a.root.rotation.y = a.homeTurn; }
      a.ring.material.opacity = fate === "slain" ? 0 : fate === "wounded" ? 0.22 : fate === "fog" ? 0.15 : (dueling ? 0.85 : 0.5) + 0.14 * Math.sin(t * 3 + a.index);
      if (fate === "fog" && !a.fog) { // lost in fog: the proof could not tell either way
        a.fog = [];
        for (var i = 0; i < 4; i++) { var m = K.glow(0xb9c2cf, 5.5, 0, true); a.root.add(m); a.fog.push(m); }
      }
      if (a.fog) { a.fog.forEach(function (m, i) { m.position.set(Math.cos(t * 0.5 + i * 1.6) * 0.9, 1.1 + (i % 2) * 0.9, Math.sin(t * 0.5 + i * 1.6) * 0.9); m.material.opacity = Math.min(0.5, m.material.opacity + dt * 0.3); }); }
      var fought = wd.duel === f.id && !f.outcome;
      a.label.hidden = !(fought || a.picked || a.hover || t < a.risen + 3.2 || (f.outcome && wd.duel === null && t < (a.outcomeAt || 0) + 4));
      if (f.outcome && !a.outcomeSeen) { a.outcomeSeen = true; a.outcomeAt = self.snap ? -99 : t; }
      a.label.prio = fought ? 10 : 4;
      self.setClass(a.label, "fought", fought);
      self.setLabel(a.label, f.id + " · " + f.severity, f.outcome ? f.outcome.replace(/_/g, " ") : fought ? f.monster + " · " + f.stage : f.monster + (f.path ? " · " + f.path.split("/").pop() : ""));
      // a body lying still needs no animation; idle skeletons far from the action tick at half rate
      var still = fate === "slain" && t > a.lockUntil + 0.6;
      if (still && a.still) { return; }
      if (still) { a.update(dt); a.still = true; return; }
      if (dueling || t < a.lockUntil || (self.frame + a.index) % 2 === 0) { a.update(dueling || t < a.lockUntil ? dt : dt * 2); }
    });
  };

  Realm.prototype.updateOracles = function (dt) {
    var wd = this.world, self = this, t = this.time;
    Object.keys(this.oracles).forEach(function (id) {
      var a = self.oracles[id], m = wd.models[id], busy = m && m.inflight > 0;
      a.play(busy ? "Ranged_Magic_Spellcasting" : "Idle_B");
      a.flash = Math.max(0, a.flash - dt * 1.4); a.fail = Math.max(0, a.fail - dt * 0.45);
      a.orb.material.emissive.copy(lc(a.fail > 0.02 ? COL.bad : m && m.role === "fallback" ? 0x4f7bff : 0x7b5cff));
      a.orb.material.emissiveIntensity = (busy ? 1.7 + Math.sin(t * 8) * 0.6 : 0.8) + a.flash * 1.5;
      a.halo.material.color.copy(lc(a.fail > 0.02 ? COL.bad : m && m.role === "fallback" ? 0x7b9cff : 0x9d7bff));
      a.halo.material.opacity = (busy ? 0.9 : 0.4) + a.flash * 0.3;
      a.halo.scale.setScalar((busy ? 5.5 + Math.sin(t * 8) : 3.6) * (a.orbR / 0.72));
      a.orb.position.y = a.orbY + Math.sin(t * 1.4 + a.orbY) * 0.08; a.orb.rotation.y += dt * (busy ? 2.5 : 0.4);
      a.halo.position.copy(a.orb.position);
      a.label.prio = busy ? 7 : 5;
      self.setClass(a.label, "bad", a.fail > 0.02);
      if (m) {
        self.setLabel(a.label, m.name, busy ? (m.role === "fallback" ? "fallback · " : "") + "answering" + (m.finding ? " " + m.finding : "") + (m.purpose ? " · " + m.purpose : "")
          : (m.role === "fallback" ? "fallback · " : "") + m.calls + " raven" + (m.calls === 1 ? "" : "s") + " · " + W.fmtTokens(m.tokensIn + m.tokensOut) + " tok" + (m.failed ? " · " + m.failed + " lost" : ""));
      }
      a.update(dt);
    });
  };

  Realm.prototype.updateWorldBits = function (dt) {
    var self = this, t = this.time, wd = this.world;
    var ended = wd.ended, ok = wd.exitCode === 0;
    this.fires.forEach(function (f) {
      var k = 0.86 + 0.14 * Math.sin(t * 13 + f.seed) * Math.sin(t * 7.3 + f.seed * 2);
      f.halo.material.opacity = (f.lampOnly ? 0.5 : 0.62) * k;
      if (f.lampOnly) { return; }
      f.outer.scale.set(f.size * (0.92 + 0.1 * Math.sin(t * 9 + f.seed)), f.size * (0.85 + 0.3 * k), f.size * (0.92 + 0.1 * Math.cos(t * 8 + f.seed)));
      f.outer.rotation.y = t * 2 + f.seed;
      if (f.light) { f.light.intensity = f.power * k; }
    });
    // the beacon on the keep tells how the run ended: amber while it lives, green for victory, red otherwise
    var bc = ended ? (ok ? COL.ok : COL.bad) : COL.fire;
    if (this.beaconColor !== bc) {
      this.beaconColor = bc;
      this.beacon.outer.material.color.copy(lc(bc)); this.beacon.halo.material.color.copy(lc(bc)); this.beacon.light.color.copy(lc(bc));
      this.beacon.halo.scale.setScalar(ended ? 22 : 8); this.beacon.power = ended ? 4.5 : 2.6; this.beacon.light.distance = ended ? 60 : 26;
    }
    this.flags.forEach(function (f) { f.mesh.rotation.y = -0.5 + Math.sin(t * 1.3 + f.seed) * 0.35; f.mesh.rotation.z = Math.sin(t * 2.6 + f.seed) * 0.08; });
    this.mist.forEach(function (m) { m.sprite.position.x = m.x + Math.sin(t * 0.07 + m.seed) * 4; m.sprite.position.z = m.z + Math.cos(t * 0.05 + m.seed * 2) * 2; });
    var c = this.core;
    c.activity = Math.max(0, c.activity - dt * 0.6);
    c.crystal.rotation.y += dt * (0.6 + c.activity * 3);
    c.crystal.position.y = c.y + Math.sin(t * 2) * 0.12;
    c.crystal.material.emissive.copy(lc(ended ? (ok ? 0x2fbf6a : 0xd23a3a) : 0xff9d1f));
    c.halo.material.color.copy(lc(ended ? (ok ? COL.ok : 0xff5c5c) : 0xffb340));
    c.halo.scale.setScalar(6 + c.activity * 3 + Math.sin(t * 3) * 0.4);
    c.light.intensity = 1.8 + c.activity * 2.5;
    c.halo.position.y = c.crystal.position.y;
    var tw = this.tower, busy = wd.llmInflight > 0;
    tw.flash = Math.max(0, tw.flash - dt * 1.2);
    tw.ring.rotation.z += dt * (busy ? 1.6 : 0.25); tw.ring2.rotation.y += dt * (busy ? 2.2 : 0.35); tw.ring2.rotation.x += dt * 0.2;
    tw.ring.position.y = 16.6 + Math.sin(t * 1.1) * 0.15; tw.ring2.position.y = tw.ring.position.y;
    tw.glow.material.opacity = (busy ? 0.75 + 0.15 * Math.sin(t * 6) : 0.4) + tw.flash * 0.3;
    tw.light.intensity = (busy ? 2.8 : 1.6) + tw.flash * 2;
    // cells: lamp and glow from the job's state; a finished job flashes, then keeps a dim ember of its result
    this.cells.forEach(function (cell) {
      cell.flash = Math.max(0, cell.flash - dt * 0.6);
      var on = cell.state === "running" ? 0.6 + 0.25 * Math.sin(t * 9) : cell.state ? 0.16 + cell.flash * 0.8 : 0;
      cell.glow.material.color.copy(cell.color); cell.glow.material.opacity = on;
      cell.halo.material.color.copy(cell.color); cell.halo.material.opacity = cell.state ? 0.5 + cell.flash * 0.4 : 0;
      cell.lamp.material.color.copy(cell.color);
      if (cell.crate.visible && cell.state === "running") { cell.crate.rotation.y += dt * 0.8; }
    });
    // wards: dark until the self-test reports; then a steady cyan (holding) or a red flicker (failed)
    var st = wd.selftest;
    this.wardFlash = Math.max(0, (this.wardFlash || 0) - dt * 0.5);
    if (!st) { this.wardMat.color.copy(lc(0x27304a)); this.wardGlow.material.opacity = 0; }
    else if (st.passed) { this.wardMat.color.copy(lc(0x59e0ff)).multiplyScalar(0.8 + 0.2 * Math.sin(t * 2)); this.wardGlow.material.color.copy(lc(0x59e0ff)); this.wardGlow.material.opacity = 0.1 + this.wardFlash * 0.6; }
    else { this.wardMat.color.copy(lc(Math.sin(t * 11) > 0 ? 0xff4d4d : 0x5a1f1f)); this.wardGlow.material.color.copy(lc(COL.bad)); this.wardGlow.material.opacity = 0.18 + this.wardFlash * 0.6; }
    this.fx = this.fx.filter(function (e) { if (e.update(dt)) { return true; } e.dispose(); return false; });
    // the gold ring under whatever was clicked
    var sel = this.selected, ring = this.selectRing;
    if (sel && sel.root) { ring.position.set(sel.root.position.x, sel.root.position.y + 0.2, sel.root.position.z); ring.material.opacity = 0.75 + 0.2 * Math.sin(t * 4); }
    else { ring.material.opacity = 0; }
    void self;
  };

  Realm.prototype.loop = function () {
    var self = this;
    var frame = function () {
      if (self.disposed) { return; }
      self.raf = requestAnimationFrame(frame);
      var raw = Math.min(self.clock.getDelta(), 0.1);
      if (document.hidden) { return; }
      self.real += raw; self.frame += 1;
      if (!self.paused) {
        var dt = raw * self.speed;
        self.time += dt;
        if (self.ready) {
          self.pacer.step(dt);
          self.updateHeroes(dt); self.updateFoes(dt); self.updateOracles(dt); self.updateWorldBits(dt);
          self.snap = false;
          self.refreshCore();
        }
      }
      // the camera eases toward where it was asked to look, and home again; the user's hand always wins
      var o = self.orbit, c = self.cam, want = self.focus && self.real < self.focus.until && !self.paused ? self.focus : null;
      var k = self.reduced ? 1 : 1 - Math.exp(-raw * (want ? 2.2 : 1.2));
      c.x += ((want ? want.x : self.home.x) - c.x) * k; c.y += ((want ? want.y : self.home.y) - c.y) * k; c.z += ((want ? want.z : self.home.z) - c.z) * k;
      c.dist += ((want ? Math.min(o.dist, want.dist) : o.dist) * self.fit - c.dist) * k;
      var az = o.azimuth + (self.reduced || o.dragging ? 0 : Math.sin(self.real * 0.11) * 0.05);
      self.camera.position.set(c.x + Math.sin(o.polar) * Math.cos(az) * c.dist, c.y + Math.cos(o.polar) * c.dist, c.z + Math.sin(o.polar) * Math.sin(az) * c.dist);
      self.camera.lookAt(c.x, c.y, c.z);
      self.renderer.render(self.scene, self.camera);
      self.placeLabels();
    };
    frame();
  };

  // ------------------------------------------------------------------ input and API

  Realm.prototype.touched = function () { this.focus = null; this.handsOff = this.real + 20; };

  Realm.prototype.bindInput = function () {
    var el = this.renderer.domElement, o = this.orbit, self = this;
    this.onDown = function (e) { o.dragging = true; o.moved = 0; o.lastX = e.clientX; o.lastY = e.clientY; };
    el.addEventListener("pointerdown", this.onDown);
    this.onUp = function (e) { if (o.dragging && o.moved < 5) { self.pick(e, true); } o.dragging = false; };
    this.onMove = function (e) {
      if (!o.dragging) { if (e.target === el && self.ready && self.frame % 3 === 0) { self.pick(e, false); } return; }
      var dx = e.clientX - o.lastX, dy = e.clientY - o.lastY;
      o.moved += Math.abs(dx) + Math.abs(dy);
      if (o.moved >= 5) { self.touched(); }
      o.azimuth -= dx * 0.005;
      o.polar = Math.min(1.32, Math.max(0.3, o.polar - dy * 0.003));
      o.lastX = e.clientX; o.lastY = e.clientY;
    };
    window.addEventListener("pointerup", this.onUp);
    window.addEventListener("pointermove", this.onMove);
    el.addEventListener("wheel", function (e) { e.preventDefault(); self.touched(); o.dist = Math.min(220, Math.max(24, o.dist * (e.deltaY > 0 ? 1.1 : 0.9))); }, { passive: false });
    el.addEventListener("keydown", function (e) {
      var used = true;
      if (e.key === "ArrowLeft") { o.azimuth += 0.1; }
      else if (e.key === "ArrowRight") { o.azimuth -= 0.1; }
      else if (e.key === "ArrowUp") { o.polar = Math.max(0.3, o.polar - 0.05); }
      else if (e.key === "ArrowDown") { o.polar = Math.min(1.32, o.polar + 0.05); }
      else if (e.key === "+" || e.key === "=") { o.dist = Math.max(24, o.dist * 0.9); }
      else if (e.key === "-") { o.dist = Math.min(220, o.dist * 1.1); }
      else if (e.key === "Home" || e.key === "0") { o.azimuth = 1.47; o.polar = 0.9; o.dist = 104; }
      else { used = false; }
      if (used) { e.preventDefault(); self.touched(); if (e.key === "Home" || e.key === "0") { self.handsOff = 0; } }
    });
  };

  Realm.prototype.entity = function (p) {
    if (!p) { return null; }
    return p.kind === "scanner" ? this.heroes["scanner:" + p.key] : p.kind === "backend" ? this.heroes["backend:" + p.key]
      : p.kind === "finding" ? this.foes[p.key] : p.kind === "model" ? this.oracles[p.key] : null;
  };

  Realm.prototype.pick = function (e, click) {
    var rect = this.renderer.domElement.getBoundingClientRect();
    var mouse = new THREE.Vector2(((e.clientX - rect.left) / rect.width) * 2 - 1, -((e.clientY - rect.top) / rect.height) * 2 + 1);
    this.raycaster.setFromCamera(mouse, this.camera);
    var hits = this.raycaster.intersectObjects(this.pickables, false), p = hits.length ? hits[0].object.userData.pick : null, ent = this.entity(p);
    if (!click) { // hover: name the thing under the pointer
      if (this.hovered && this.hovered !== ent) { this.hovered.hover = false; }
      this.hovered = ent; if (ent) { ent.hover = true; }
      this.renderer.domElement.style.cursor = p ? "pointer" : "grab";
      return;
    }
    if (this.selected) { this.selected.picked = false; }
    this.selected = ent; if (ent) { ent.picked = true; }
    if (this.selectCb) { this.selectCb(p, p ? this.world.info(p) : []); }
  };

  Realm.prototype.handle = function (ev) { this.pacer.push(ev); };
  Realm.prototype.info = function (pick) { return this.world.info(pick); };
  Realm.prototype.describe = function () {
    var wd = this.world, parts = [], f = wd.duel ? wd.byId[wd.duel] : null;
    if (wd.running) { parts.push(wd.running + " hero" + (wd.running === 1 ? "" : "es") + " searching the wilds"); }
    if (f && f.backend && !f.outcome) { parts.push("champion " + f.backend + " is fighting " + f.id + " (" + f.stage + ")"); }
    if (wd.ended) { parts.push(wd.exitCode === 0 ? "the beacon burns green: victory" : "the beacon burns red: exit " + wd.exitCode); }
    return wd.describe("Fantasy 3D view. Drag or use the arrow keys to turn, scroll or plus and minus to zoom") + (parts.length ? " Now: " + parts.join("; ") + "." : "");
  };
  Realm.prototype.onSelect = function (cb) { this.selectCb = cb; };
  Realm.prototype.setPaused = function (p) { this.paused = p; };
  Realm.prototype.setSpeed = function (s) { this.speed = s; };
  Realm.prototype.dispose = function () {
    this.disposed = true;
    cancelAnimationFrame(this.raf);
    window.removeEventListener("resize", this.onResize);
    window.removeEventListener("pointerup", this.onUp);
    window.removeEventListener("pointermove", this.onMove);
    this.fx.forEach(function (e) { e.dispose(); });
    // models are shared with the next realm (cached assets); scenery built here goes with the GL context
    this.scene.traverse(function (o) { if (o.isInstancedMesh || (o.isMesh && o.geometry && o.geometry.attributes.color)) { o.geometry.dispose(); } });
    this.renderer.dispose();
    this.renderer.forceContextLoss();
    if (this.renderer.domElement.parentNode) { this.renderer.domElement.parentNode.removeChild(this.renderer.domElement); }
    if (this.overlay.parentNode) { this.overlay.parentNode.removeChild(this.overlay); }
    if (window.SiftRealm.current === this) { window.SiftRealm.current = null; }
  };

  window.SiftRealm = { available: available, create: function (el) { return new Realm(el); }, current: null };
})();
