/* CodeSift "living city": a night city of the user's project, driven by run events, lit by the
   amber ops-centre orb. Buildings are files grouped in districts; findings are bug characters that
   walk to the ops centre and come back repaired, go to the landfill (rejected) or to limbo
   (inconclusive). Palette after 21cel.com: near-black, amber, soft green/red. */
(function () {
  "use strict";
  var THREE = window.THREE;

  var C = {
    bg: 0x0d0f12, surface: 0x14171c, surface2: 0x1a1e24, steel: 0x23272f, text: 0xedeef0, dim: 0x9aa0aa,
    amber: 0xf5a524, amber2: 0xffc861, amberDeep: 0xd9820f, ok: 0x6ee7a0, bad: 0xff8a8a, violet: 0xa78bfa, sky: 0x7aa2ff
  };
  var TYPES = {
    sqli: { name: "Syringe leech", color: 0xff8a8a },
    xss: { name: "Mask imp", color: 0xe879f9 },
    cmdi: { name: "Shell wraith", color: 0xf5a524 },
    traversal: { name: "Tunnel worm", color: 0xa78bfa },
    secret: { name: "Key thief", color: 0x7dd3fc },
    dependency: { name: "Rotten crate", color: 0xbef264 },
    glitch: { name: "Glitch", color: 0x5eead4 }
  };
  var DISTRICT_ORDER = ["db", "web", "tools", "uploads", "config", "vendor", "annex"];
  var DISTRICT_NAMES = {
    db: "db/ Data Vault", web: "web/ Neon Market", tools: "tools/ Workshop Row", uploads: "uploads/ Storage Yard",
    config: "config/ Config Bank", vendor: "vendor/ Supply Docks", annex: "Annex"
  };
  var STATE_COLORS = { healthy: 0x4a505a, latent: 0xffc861, infected: 0xff8a8a, repair: 0xf5a524, fixed: 0x6ee7a0 };
  var FONT = "\"Segoe UI Variable Display\", \"Segoe UI\", system-ui, sans-serif";
  var RING = 16, BOULEVARD = 42, DISTRICT_R = 62, MAX_BUILDINGS = 9;
  var BACKEND_STATION = { gateway: "garage", "claude-cli": "forge", "claude-api": "relay" };

  function available() {
    if (!THREE) { return false; }
    try {
      var c = document.createElement("canvas");
      return !!(window.WebGLRenderingContext && (c.getContext("webgl") || c.getContext("experimental-webgl")));
    } catch (e) { return false; }
  }

  function label(text, color, scale) {
    var canvas = document.createElement("canvas");
    canvas.width = 512; canvas.height = 96;
    var ctx = canvas.getContext("2d");
    ctx.font = "600 38px " + FONT;
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.shadowColor = "rgba(0,0,0,0.9)"; ctx.shadowBlur = 10; ctx.shadowOffsetY = 2;
    ctx.fillStyle = color;
    ctx.fillText(String(text).slice(0, 28), 256, 48);
    ctx.shadowColor = color; ctx.shadowBlur = 14; ctx.shadowOffsetY = 0;
    ctx.globalAlpha = 0.5;
    ctx.fillText(String(text).slice(0, 28), 256, 48);
    var tex = new THREE.CanvasTexture(canvas);
    var sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false, fog: false }));
    var s = scale || 6;
    sprite.scale.set(s, s * 96 / 512, 1);
    return sprite;
  }

  // Soft radial glow, drawn additively: a cheap stand-in for bloom.
  var glowTex = null;
  function glow(color, size, opacity) {
    if (!glowTex) {
      var c = document.createElement("canvas");
      c.width = c.height = 128;
      var ctx = c.getContext("2d");
      var g = ctx.createRadialGradient(64, 64, 0, 64, 64, 64);
      g.addColorStop(0, "rgba(255,255,255,1)");
      g.addColorStop(0.2, "rgba(255,255,255,0.55)");
      g.addColorStop(0.5, "rgba(255,255,255,0.14)");
      g.addColorStop(1, "rgba(255,255,255,0)");
      ctx.fillStyle = g; ctx.fillRect(0, 0, 128, 128);
      glowTex = new THREE.CanvasTexture(c);
    }
    var s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color: color, transparent: true, opacity: opacity || 0.9,
      blending: THREE.AdditiveBlending, depthWrite: false }));
    s.scale.set(size, size, 1);
    s.userData.noPick = true;
    return s;
  }

  // A flat additive glow lying on the ground (light pool).
  function groundGlow(color, radius, opacity) {
    glow(color, 1);
    var m = new THREE.Mesh(new THREE.PlaneGeometry(radius * 2, radius * 2), new THREE.MeshBasicMaterial({
      map: glowTex, color: color, transparent: true, opacity: opacity, blending: THREE.AdditiveBlending, depthWrite: false }));
    m.rotation.x = -Math.PI / 2;
    return m;
  }

  function windowTexture(seed) {
    var canvas = document.createElement("canvas");
    canvas.width = 64; canvas.height = 128;
    var ctx = canvas.getContext("2d");
    ctx.fillStyle = "#000000"; ctx.fillRect(0, 0, 64, 128);
    var r = seed;
    for (var y = 5; y < 128; y += 11) {
      for (var x = 5; x < 64; x += 11) {
        r = (r * 9301 + 49297) % 233280;
        var v = r / 233280;
        if (v > 0.5) {
          ctx.fillStyle = v > 0.92 ? "#edeef0" : (v > 0.7 ? "#ffc861" : "#b8761a");
          ctx.fillRect(x, y, 6, 6);
        }
      }
    }
    var tex = new THREE.CanvasTexture(canvas);
    tex.wrapS = tex.wrapT = THREE.RepeatWrapping;
    return tex;
  }

  function shadows(obj) {
    obj.traverse(function (o) {
      if (o.isMesh && o.material && o.material.isMeshStandardMaterial) { o.castShadow = true; o.receiveShadow = true; }
    });
    return obj;
  }

  function polar(r, a, y) { return new THREE.Vector3(Math.cos(a) * r, y || 0, Math.sin(a) * r); }

  function City(container, opts) {
    this.opts = opts || {};
    this.reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    this.paused = false;
    this.speed = 1;
    this.selectCb = null;
    this.buildings = {};     // path -> building
    this.bugs = {};          // finding id -> bug
    this.districts = {};
    this.stations = {};
    this.pickables = [];
    this.animated = [];      // {update(dt, t)}
    this.cars = [];
    this.smoke = [];
    this.links = {};
    this.findingBuilding = {};
    this.packets = [];
    this.scheduled = [];
    this.traffic = { idle: 1.5 };
    this.stats = { repaired: 0, landfill: 0, limbo: 0, tokens: 0 };
    this.container = container;
    this.init();
  }

  City.prototype.init = function () {
    var w = this.container.clientWidth || 800, h = this.container.clientHeight || 600;
    this.renderer = new THREE.WebGLRenderer({ antialias: true });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.setSize(w, h);
    this.renderer.setClearColor(C.bg);
    this.renderer.shadowMap.enabled = true;
    this.renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    this.container.appendChild(this.renderer.domElement);
    this.renderer.domElement.setAttribute("tabindex", "0");
    this.renderer.domElement.setAttribute("aria-label", "3D city view; use the plain dashboard for a text version");
    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(C.bg, 0.0048);
    this.camera = new THREE.PerspectiveCamera(42, w / h, 0.5, 700);
    this.orbit = { azimuth: 0.9, polar: 1.0, dist: 120, dragging: false, lastX: 0, lastY: 0, idle: 0 };
    this.buildLights();
    this.clock = new THREE.Clock();
    this.raycaster = new THREE.Raycaster();
    this.buildGround();
    this.buildRoads();
    this.buildOpsCenter();
    this.buildDistricts();
    this.buildLife();
    shadows(this.scene);
    this.bindInput();
    var self = this;
    window.addEventListener("resize", function () { self.resize(); });
    this.loop();
  };

  City.prototype.resize = function () {
    var w = this.container.clientWidth || 800, h = this.container.clientHeight || 600;
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(w, h);
  };

  // ------------------------------------------------------------------ static city

  City.prototype.buildLights = function () {
    // warm sky over a near-black ground, a warm key light with soft shadows, a cool rim light from behind
    this.scene.add(new THREE.HemisphereLight(0xffe2b8, 0x0d0f12, 0.5));
    this.scene.add(new THREE.AmbientLight(0x9aa0aa, 0.1));
    var key = new THREE.DirectionalLight(0xffe0b0, 1.0);
    key.position.set(70, 120, 50);
    key.castShadow = true;
    key.shadow.mapSize.set(2048, 2048);
    var sc = key.shadow.camera;
    sc.left = -110; sc.right = 110; sc.top = 110; sc.bottom = -110; sc.near = 20; sc.far = 320;
    key.shadow.bias = -0.0004;
    key.shadow.normalBias = 0.04;
    key.shadow.radius = 3;
    this.scene.add(key);
    var rim = new THREE.DirectionalLight(C.sky, 0.32);
    rim.position.set(-90, 45, -70);
    this.scene.add(rim);
    // the amber core: the ops-centre orb lights the inner city
    var core = new THREE.PointLight(C.amber, 2.4, 120, 1.6);
    core.position.set(0, 17, 0);
    this.scene.add(core);
    this.coreLight = core;
  };

  City.prototype.buildGround = function () {
    var ground = new THREE.Mesh(new THREE.CircleGeometry(320, 64),
      new THREE.MeshStandardMaterial({ color: 0x111418, roughness: 0.92, metalness: 0.05 }));
    ground.rotation.x = -Math.PI / 2;
    this.scene.add(ground);
    var grid = new THREE.GridHelper(400, 80, 0x3a2c12, 0x1b1e23);
    grid.material.transparent = true; grid.material.opacity = 0.55;
    grid.position.y = 0.02;
    this.scene.add(grid);
    var pool = groundGlow(C.amber, 70, 0.22);   // light pool under the orb, like the site's glow
    pool.position.y = 0.06;
    this.scene.add(pool);
  };

  City.prototype.road = function (a, b, width, color, dashed) {
    var len = a.distanceTo(b);
    var mesh = new THREE.Mesh(new THREE.BoxGeometry(len + width * 0.5, 0.12, width),
      new THREE.MeshStandardMaterial({ color: 0x1a1d22, roughness: 0.75, metalness: 0.15 }));
    mesh.position.copy(a).add(b).multiplyScalar(0.5);
    mesh.position.y = 0.06;
    mesh.rotation.y = -Math.atan2(b.z - a.z, b.x - a.x);
    this.scene.add(mesh);
    var line = new THREE.Mesh(new THREE.BoxGeometry(dashed ? len * 0.55 : len, 0.14, 0.14),
      new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: dashed ? 0.7 : 0.9 }));
    line.position.copy(mesh.position); line.rotation.copy(mesh.rotation);
    this.scene.add(line);
  };

  City.prototype.buildRoads = function () {
    var i, n = 5;
    for (i = 0; i < n; i++) {   // pentagon ring road around the ops centre
      this.road(polar(RING, i * 2 * Math.PI / n), polar(RING, (i + 1) * 2 * Math.PI / n), 3, C.amber);
    }
    var seg = 56;
    for (i = 0; i < seg; i++) { // boulevard loop, dashed centre line
      this.road(polar(BOULEVARD, i * 2 * Math.PI / seg), polar(BOULEVARD, (i + 1) * 2 * Math.PI / seg), 4, C.amber2, true);
    }
    for (i = 0; i < DISTRICT_ORDER.length; i++) { // spokes: districts -> boulevard -> ring
      var a = this.districtAngle(i);
      this.road(polar(RING, a), polar(DISTRICT_R - 8, a), 2.5, C.amberDeep);
    }
    // street lamps along the boulevard
    for (i = 0; i < 14; i++) {
      var p = polar(BOULEVARD + 3.4, (i + 0.5) * 2 * Math.PI / 14);
      var lamp = new THREE.Group();
      lamp.position.copy(p);
      var post = new THREE.Mesh(new THREE.CylinderGeometry(0.1, 0.14, 4, 6), new THREE.MeshStandardMaterial({ color: C.steel, metalness: 0.6, roughness: 0.4 }));
      post.position.y = 2; lamp.add(post);
      var bulb = new THREE.Mesh(new THREE.SphereGeometry(0.25, 8, 6), new THREE.MeshBasicMaterial({ color: C.amber2 }));
      bulb.position.y = 4.1; lamp.add(bulb);
      var halo = glow(C.amber, 3.2, 0.7); halo.position.y = 4.1; lamp.add(halo);
      var puddle = groundGlow(C.amber, 3.5, 0.18); puddle.position.y = 0.15; lamp.add(puddle);
      this.scene.add(lamp);
    }
  };

  City.prototype.districtAngle = function (i) { return -Math.PI / 2 + i * 2 * Math.PI / DISTRICT_ORDER.length; };

  City.prototype.station = function (key, title, pos, build) {
    var group = new THREE.Group();
    group.position.copy(pos);
    build.call(this, group);
    var tag = label(title, "#edeef0", 7);
    tag.position.set(0, 9, 0);
    group.add(tag);
    group.traverse(function (o) { if (!o.userData.noPick) { o.userData.pick = { kind: "station", key: key, title: title }; } });
    this.scene.add(group);
    this.pickables.push(group);
    this.stations[key] = { group: group, pos: pos.clone(), title: title, visits: 0 };
    return group;
  };

  function neon(color, intensity) {
    return new THREE.MeshStandardMaterial({ color: C.surface2, emissive: color, emissiveIntensity: intensity || 0.6, roughness: 0.4, metalness: 0.3 });
  }
  function metal(color) {
    return new THREE.MeshStandardMaterial({ color: color || C.steel, roughness: 0.38, metalness: 0.7 });
  }

  City.prototype.buildOpsCenter = function () {
    var self = this;
    // Command tower: a dark metal spire carrying the glowing amber orb, with orbiting rings and a scanner sweep
    this.station("tower", "Command tower", new THREE.Vector3(0, 0, 0), function (g) {
      var plinth = new THREE.Mesh(new THREE.CylinderGeometry(4.2, 4.8, 1.2, 6), metal(C.surface2));
      plinth.position.y = 0.6; g.add(plinth);
      var tower = new THREE.Mesh(new THREE.CylinderGeometry(1.0, 2.2, 12, 6), metal());
      tower.position.y = 7; g.add(tower);
      var trim = new THREE.Mesh(new THREE.TorusGeometry(2.3, 0.12, 6, 6), new THREE.MeshBasicMaterial({ color: C.amber }));
      trim.rotation.x = Math.PI / 2; trim.position.y = 1.25; g.add(trim);
      var orb = new THREE.Mesh(new THREE.SphereGeometry(2.4, 32, 24), new THREE.MeshStandardMaterial({
        color: C.amberDeep, emissive: C.amber, emissiveIntensity: 1.0, roughness: 0.25, metalness: 0.2 }));
      orb.position.y = 16; orb.castShadow = false; orb.userData.noShadow = true; g.add(orb);
      var core = glow(C.amber2, 9, 0.85); core.position.y = 16; g.add(core);
      var halo = glow(C.amber, 22, 0.35); halo.position.y = 16; g.add(halo);
      var rings = [];
      [[3.6, 0.3, 0.9], [4.4, -0.5, -0.6], [5.3, 1.1, 0.4]].forEach(function (r) {
        var ring = new THREE.Mesh(new THREE.TorusGeometry(r[0], 0.05, 6, 64), new THREE.MeshBasicMaterial({ color: C.amber2, transparent: true, opacity: 0.55 }));
        ring.position.y = 16; ring.rotation.set(Math.PI / 2 + r[1], r[2], 0); g.add(ring);
        rings.push({ mesh: ring, speed: r[2] });
      });
      var sweep = new THREE.Mesh(new THREE.CircleGeometry(BOULEVARD + 25, 32, 0, 0.35),
        new THREE.MeshBasicMaterial({ color: C.amber, transparent: true, opacity: 0.06, side: THREE.DoubleSide, depthWrite: false, blending: THREE.AdditiveBlending }));
      sweep.rotation.x = -Math.PI / 2; sweep.position.y = 0.3; g.add(sweep);
      self.animated.push({ update: function (dt, t) {
        sweep.rotation.z += dt * 0.45;
        rings.forEach(function (r) { r.mesh.rotation.z += dt * r.speed; });
        var pulse = 1 + Math.sin(t * 1.6) * 0.06;
        core.scale.set(9 * pulse, 9 * pulse, 1);
        orb.material.emissiveIntensity = 0.9 + Math.sin(t * 1.6) * 0.12;
        if (self.coreLight) { self.coreLight.intensity = 2.2 + Math.sin(t * 1.6) * 0.25; }
      } });
      self.sweep = sweep;
    });
    var names = [["oracle", "The Oracle"], ["garage", "Local garage"], ["forge", "Claude forge"], ["relay", "Relay tower"],
      ["checkpoint", "Checkpoint"], ["quarantine", "Quarantine lab"], ["courthouse", "Courthouse"]];
    names.forEach(function (n, i) {
      var pos = polar(10.5, -Math.PI / 2 + i * 2 * Math.PI / names.length);
      self.station(n[0], n[1], pos, function (g) { self["build_" + n[0]](g); });
    });
    // Landfill and limbo sit in the gaps between districts, inside the boulevard
    var gap = Math.PI / DISTRICT_ORDER.length;
    this.station("landfill", "Landfill", polar(30, this.districtAngle(3) + gap), this.build_landfill);
    this.station("limbo", "Limbo yard", polar(30, this.districtAngle(4) + gap), this.build_limbo);
  };

  City.prototype.build_oracle = function (g) {
    var eye = new THREE.Mesh(new THREE.SphereGeometry(1.6, 24, 16), new THREE.MeshStandardMaterial({ color: C.text, roughness: 0.2, metalness: 0.1 }));
    var iris = new THREE.Mesh(new THREE.TorusGeometry(0.9, 0.25, 8, 24), new THREE.MeshBasicMaterial({ color: C.amber }));
    var shine = glow(C.amber2, 3, 0.6);
    eye.position.y = 4; iris.position.set(0, 4, 1.45); shine.position.set(0, 4, 1.6); g.add(eye); g.add(iris); g.add(shine);
    this.animated.push({ update: function (dt, t) { eye.position.y = iris.position.y = shine.position.y = 4 + Math.sin(t * 1.5) * 0.5; } });
  };
  City.prototype.build_garage = function (g) {
    var box = new THREE.Mesh(new THREE.BoxGeometry(5, 3, 4), metal(C.surface2));
    box.position.y = 1.5; g.add(box);
    var door = new THREE.Mesh(new THREE.PlaneGeometry(3, 1.8), new THREE.MeshBasicMaterial({ color: C.ok, transparent: true, opacity: 0.6 }));
    door.position.set(0, 1.1, 2.01); g.add(door);
    var worker = new THREE.Mesh(new THREE.CylinderGeometry(0.3, 0.3, 1.2, 8), neon(C.amber2, 0.8));
    worker.position.set(0, 0.7, 2.8); g.add(worker);
    this.animated.push({ update: function (dt, t) { worker.position.x = Math.sin(t * 2) * 2; } });
  };
  City.prototype.build_forge = function (g) {
    var box = new THREE.Mesh(new THREE.BoxGeometry(4.5, 3.5, 4), metal(C.surface2));
    box.position.y = 1.75; g.add(box);
    var chimney = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.7, 3, 8), metal());
    chimney.position.set(1.2, 5, 0); g.add(chimney);
    var fire = new THREE.PointLight(C.amberDeep, 1.6, 16);
    fire.position.set(1.2, 7, 0); g.add(fire);
    var flame = glow(C.amber, 4, 0.9); flame.position.set(1.2, 6.8, 0); g.add(flame);
    this.animated.push({ update: function (dt, t) {
      var f = 1.1 + Math.sin(t * 13) * 0.3 + Math.random() * 0.2;
      fire.intensity = f; flame.scale.set(3 + f, 3 + f, 1);
    } });
  };
  City.prototype.build_relay = function (g) {
    var mast = new THREE.Mesh(new THREE.ConeGeometry(1.5, 9, 4, 1, true), new THREE.MeshBasicMaterial({ color: C.violet, wireframe: true }));
    mast.position.y = 4.5; g.add(mast);
    var dish = new THREE.Mesh(new THREE.SphereGeometry(1.2, 16, 8, 0, Math.PI * 2, 0, Math.PI / 3), metal(C.text));
    dish.position.y = 9; dish.rotation.x = Math.PI / 2; g.add(dish);
    var tip = glow(C.violet, 3, 0.8); tip.position.y = 9.6; g.add(tip);
    this.animated.push({ update: function (dt, t) { dish.rotation.z += dt * 1.2; tip.material.opacity = 0.5 + Math.abs(Math.sin(t * 3)) * 0.5; } });
  };
  City.prototype.build_checkpoint = function (g) {
    var arch = new THREE.Mesh(new THREE.TorusGeometry(2.5, 0.3, 8, 24, Math.PI), neon(C.amber, 0.9));
    arch.position.y = 0.2; g.add(arch);
    var boom = new THREE.Mesh(new THREE.BoxGeometry(4, 0.25, 0.25), neon(C.bad, 0.9));
    boom.position.set(0, 1.2, 0.8); g.add(boom);
    var shield = new THREE.Mesh(new THREE.CircleGeometry(1, 6), new THREE.MeshBasicMaterial({ color: C.amber2, transparent: true, opacity: 0.5, side: THREE.DoubleSide }));
    shield.position.set(0, 4, 0); g.add(shield);
    this.boom = boom; this.boomOpen = 0;
    var self = this;
    this.animated.push({ update: function (dt) {
      self.boomOpen = Math.max(0, self.boomOpen - dt);
      boom.rotation.z = self.boomOpen > 0 ? Math.min(1.2, boom.rotation.z + dt * 3) : Math.max(0, boom.rotation.z - dt * 3);
      shield.rotation.y += dt;
    } });
  };
  City.prototype.build_quarantine = function (g) {
    var dome = new THREE.Mesh(new THREE.SphereGeometry(3.2, 20, 10, 0, Math.PI * 2, 0, Math.PI / 2),
      new THREE.MeshBasicMaterial({ color: C.ok, wireframe: true, transparent: true, opacity: 0.7 }));
    g.add(dome);
    var glass = new THREE.Mesh(new THREE.SphereGeometry(3.15, 24, 12, 0, Math.PI * 2, 0, Math.PI / 2),
      new THREE.MeshStandardMaterial({ color: C.ok, transparent: true, opacity: 0.08, roughness: 0.1, metalness: 0.5, depthWrite: false }));
    g.add(glass);
    var mark = label("NO NETWORK", "#6ee7a0", 5);
    mark.position.set(0, 4.2, 0); g.add(mark);
  };
  City.prototype.build_courthouse = function (g) {
    var base = new THREE.Mesh(new THREE.BoxGeometry(5, 1, 4), new THREE.MeshStandardMaterial({ color: 0xcfd2d8, roughness: 0.6, metalness: 0.1 }));
    base.position.y = 0.5; g.add(base);
    var roof = new THREE.Mesh(new THREE.ConeGeometry(3.6, 1.2, 4), new THREE.MeshStandardMaterial({ color: 0xcfd2d8, roughness: 0.6 }));
    roof.position.y = 4.6; roof.rotation.y = Math.PI / 4; roof.scale.set(1, 1, 0.8); g.add(roof);
    for (var i = -2; i <= 2; i += 1) {
      var col = new THREE.Mesh(new THREE.CylinderGeometry(0.2, 0.2, 3, 10), new THREE.MeshStandardMaterial({ color: C.text, roughness: 0.5 }));
      col.position.set(i, 2.5, 1.6); g.add(col);
    }
    var beam = new THREE.Group();
    beam.position.y = 6.6;
    var bar = new THREE.Mesh(new THREE.BoxGeometry(4, 0.15, 0.15), neon(C.amber, 0.9));
    beam.add(bar);
    [-1.8, 1.8].forEach(function (x) {
      var pan = new THREE.Mesh(new THREE.CylinderGeometry(0.6, 0.6, 0.1, 16), neon(C.amber2, 0.9));
      pan.position.set(x, -0.6, 0); beam.add(pan);
    });
    g.add(beam);
    var ring = new THREE.Mesh(new THREE.TorusGeometry(3.4, 0.08, 6, 48), new THREE.MeshBasicMaterial({ color: C.amber }));
    ring.rotation.x = Math.PI / 2; ring.position.y = 0.3; g.add(ring);
    this.animated.push({ update: function (dt, t) { beam.rotation.z = Math.sin(t * 1.3) * 0.15; ring.rotation.z += dt * 0.5; } });
  };
  City.prototype.build_landfill = function (g) {
    var fence = new THREE.Mesh(new THREE.CylinderGeometry(5, 5, 1.5, 16, 1, true), new THREE.MeshBasicMaterial({ color: 0x5a5f68, wireframe: true }));
    fence.position.y = 0.75; g.add(fence);
    for (var i = 0; i < 4; i++) {
      var pile = new THREE.Mesh(new THREE.ConeGeometry(1.2, 1.2, 7), new THREE.MeshStandardMaterial({ color: 0x2a2620, roughness: 1 }));
      pile.position.set(Math.cos(i * 1.7) * 2.5, 0.6, Math.sin(i * 1.7) * 2.5); g.add(pile);
    }
    var fire = new THREE.PointLight(C.amberDeep, 1.3, 14);
    fire.position.set(0, 1.8, 0); g.add(fire);
    var barrel = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.5, 1, 12), metal(0x3a3f48));
    barrel.position.set(0, 0.5, 0); g.add(barrel);
    var flame = glow(C.amber, 3, 0.9); flame.position.set(0, 1.4, 0); g.add(flame);
    this.animated.push({ update: function (dt, t) { var f = 0.9 + Math.random() * 0.5; fire.intensity = f; flame.scale.set(2 + f, 2.4 + f, 1); } });
    this.smokeSource(g.position, 0x6b5a4a);
  };
  City.prototype.build_limbo = function (g) {
    var fog = groundGlow(C.dim, 6, 0.25);
    fog.position.y = 0.1; g.add(fog);
    var post = new THREE.Mesh(new THREE.BoxGeometry(0.3, 2.4, 0.3), metal());
    post.position.set(0, 1.2, -3); g.add(post);
    var sign = new THREE.Mesh(new THREE.BoxGeometry(2.2, 0.8, 0.1), new THREE.MeshStandardMaterial({ color: C.surface2, emissive: C.dim, emissiveIntensity: 0.25 }));
    sign.position.set(0, 2.3, -3); g.add(sign);
  };

  City.prototype.buildDistricts = function () {
    var self = this;
    DISTRICT_ORDER.forEach(function (key, i) {
      var a = self.districtAngle(i);
      var center = polar(DISTRICT_R, a);
      var name = (self.opts.districtNames && self.opts.districtNames[key]) || DISTRICT_NAMES[key];
      var sign = label(name, "#f5a524", 12);
      sign.position.set(center.x, 26, center.z);
      self.scene.add(sign);
      // raised hexagonal district plate with a faint amber edge
      var pad = new THREE.Mesh(new THREE.CylinderGeometry(15, 15.6, 0.5, 6), new THREE.MeshStandardMaterial({ color: C.surface, roughness: 0.85, metalness: 0.1 }));
      pad.position.set(center.x, 0.25, center.z); pad.rotation.y = -a;
      self.scene.add(pad);
      var edge = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.CylinderGeometry(15, 15.6, 0.5, 6)),
        new THREE.LineBasicMaterial({ color: C.amber, transparent: true, opacity: 0.35 }));
      edge.position.copy(pad.position); edge.rotation.y = -a;
      self.scene.add(edge);
      self.districts[key] = { center: center, angle: a, slots: 0, overflow: null, overflowCount: 0 };
      for (var k = 0; k < 3; k++) { self.addBuilding(key, null); } // other (healthy) files keep the city alive
    });
  };

  City.prototype.slotPosition = function (d, slot) {
    var col = slot % 3, row = Math.floor(slot / 3);
    var tangent = new THREE.Vector3(-Math.sin(d.angle), 0, Math.cos(d.angle));
    var radial = new THREE.Vector3(Math.cos(d.angle), 0, Math.sin(d.angle));
    return d.center.clone().add(tangent.multiplyScalar((col - 1) * 8)).add(radial.multiplyScalar((row - 1) * 8));
  };

  City.prototype.addBuilding = function (districtKey, path) {
    var d = this.districts[districtKey] || this.districts.annex;
    if (d.slots >= MAX_BUILDINGS) {
      d.overflowCount += 1;
      if (!d.overflow) { d.overflow = this.makeBuilding(d, MAX_BUILDINGS - 1, "+1 files", true); }
      d.overflow.sign.material.map = label("+" + d.overflowCount + " files", "#edeef0").material.map;
      return d.overflow;
    }
    var b = this.makeBuilding(d, d.slots, path, false);
    d.slots += 1;
    return b;
  };

  City.prototype.makeBuilding = function (d, slot, path, aggregate) {
    var pos = this.slotPosition(d, slot);
    var h = 6 + ((slot * 7 + (path || "").length * 3) % 14);
    var group = new THREE.Group();
    group.position.copy(pos);
    var tex = windowTexture(slot * 31 + (path || "x").length * 17);
    tex.repeat.set(1, h / 8);
    group.rotation.y = -d.angle + Math.PI / 2;
    var plinth = new THREE.Mesh(new THREE.BoxGeometry(6, 0.5, 6), new THREE.MeshStandardMaterial({ color: C.surface2, roughness: 0.8 }));
    plinth.position.y = 0.75;
    group.add(plinth);
    var body = new THREE.Mesh(new THREE.BoxGeometry(5, h, 5), new THREE.MeshStandardMaterial({
      color: C.surface2, emissive: 0xffffff, emissiveMap: tex, emissiveIntensity: 0.85, roughness: 0.5, metalness: 0.45 }));
    body.position.y = h / 2 + 1;
    group.add(body);
    var roof = new THREE.Mesh(new THREE.BoxGeometry(5.3, 0.4, 5.3), metal(C.steel));
    roof.position.y = h + 1.2;
    group.add(roof);
    var vent = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.9, 1.4), metal(0x30353e));
    vent.position.set(1.4, h + 1.85, -1.3);
    group.add(vent);
    var edges = new THREE.LineSegments(new THREE.EdgesGeometry(body.geometry), new THREE.LineBasicMaterial({ color: STATE_COLORS.healthy, transparent: true, opacity: 0.8 }));
    edges.position.copy(body.position);
    group.add(edges);
    var gear = new THREE.Mesh(new THREE.TorusGeometry(0.8, 0.2, 8, 12), neon(C.amberDeep, 0.6));
    gear.rotation.x = Math.PI / 2; gear.position.y = h + 1.8;
    group.add(gear);
    var beacon = new THREE.Mesh(new THREE.SphereGeometry(0.3, 10, 8), new THREE.MeshBasicMaterial({ color: C.bad }));
    beacon.position.y = h + 2.8;
    group.add(beacon);
    var beaconGlow = glow(C.bad, 2.6, 0.75);
    beaconGlow.position.y = h + 2.8;
    group.add(beaconGlow);
    var name = aggregate ? path : (path ? path.split("/").pop() : "");
    var sign = label(name || "", "#edeef0", 5);
    sign.position.set(0, h + 4, 0);
    sign.visible = !!name;
    group.add(sign);
    shadows(group);
    this.scene.add(group);
    var b = { path: path, group: group, body: body, edges: edges, gear: gear, beacon: beacon, beaconGlow: beaconGlow, sign: sign, height: h + 1,
      state: "healthy", district: d, flag: null, scaffold: null, aggregate: aggregate, findings: [] };
    group.traverse(function (o) { if (!o.userData.noPick) { o.userData.pick = { kind: "building", building: b }; } });
    this.pickables.push(group);
    var phase = Math.random() * 6;
    this.animated.push({ update: function (dt, t) {
      gear.rotation.z += dt * 0.8;
      beacon.visible = beaconGlow.visible = Math.sin(t * 2 + phase) > -0.6 || Math.random() > 0.97;
    } });
    return b;
  };

  City.prototype.setBuildingState = function (b, state) {
    b.state = state;
    b.edges.material.color.setHex(STATE_COLORS[state] || STATE_COLORS.healthy);
    if (state === "infected" && !b.flag) {
      var pole = new THREE.Group();
      var stick = new THREE.Mesh(new THREE.CylinderGeometry(0.08, 0.08, 3, 6), metal(0xcfd2d8));
      stick.position.y = 1.5;
      var cloth = new THREE.Mesh(new THREE.PlaneGeometry(1.4, 0.9), new THREE.MeshBasicMaterial({ color: C.bad, side: THREE.DoubleSide }));
      cloth.position.set(0.7, 2.6, 0);
      pole.add(stick); pole.add(cloth);
      pole.position.set(1.8, b.height, 1.8);
      b.group.add(pole);
      b.flag = pole;
      b.smoke = this.smokeSource(b.group.position.clone().setY(b.height), 0x5a5f68);
      b.body.material.emissive.setHex(0xffb0b0);
    }
    if (state !== "infected" && b.flag) { b.group.remove(b.flag); b.flag = null; if (b.smoke) { b.smoke.active = false; } }
    if (state === "repair" && !b.scaffold) {
      b.scaffold = new THREE.Mesh(new THREE.BoxGeometry(6, b.height + 1, 6), new THREE.MeshBasicMaterial({ color: C.amber, wireframe: true }));
      b.scaffold.position.y = (b.height + 1) / 2;
      b.group.add(b.scaffold);
      this.sparks(b.group.position.clone().setY(b.height));
    }
    if (state !== "repair" && b.scaffold) { b.group.remove(b.scaffold); b.scaffold = null; }
    if (state !== "infected") { b.body.material.emissive.setHex(0xffffff); }
    if (state === "fixed") { b.beacon.material.color.setHex(C.ok); b.beaconGlow.material.color.setHex(C.ok); }
    this.notifyStats();
  };

  // ------------------------------------------------------------------ always alive

  City.prototype.buildLife = function () {
    var self = this;
    var carCount = this.reduced ? 10 : 40;
    for (var i = 0; i < carCount; i++) {
      var lane = i % 2;                    // two lanes, opposite directions
      var onRing = i % 4 === 3;
      var radius = onRing ? RING + (lane ? 0.7 : -0.7) : BOULEVARD + (lane ? 1 : -1);
      var car = new THREE.Group();
      var shell = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.45, 0.8), metal(lane ? 0x2c3038 : 0x3a3f48));
      shell.castShadow = true; car.add(shell);
      var lights = new THREE.Mesh(new THREE.BoxGeometry(0.08, 0.18, 0.6), new THREE.MeshBasicMaterial({ color: C.amber2 }));
      lights.position.x = 0.72; car.add(lights);
      var tail = new THREE.Mesh(new THREE.BoxGeometry(0.08, 0.18, 0.6), new THREE.MeshBasicMaterial({ color: C.bad }));
      tail.position.x = -0.72; car.add(tail);
      var beam = glow(C.amber2, 1.8, 0.55); beam.position.x = 1.1; car.add(beam);
      car.position.y = 0.4;
      this.scene.add(car);
      this.cars.push({ mesh: car, radius: radius, angle: Math.random() * Math.PI * 2, speed: (lane ? 1 : -1) * (0.1 + Math.random() * 0.12) * (onRing ? 1.8 : 1) });
    }
    var droneCount = this.reduced ? 2 : 7;
    for (var d = 0; d < droneCount; d++) {
      var drone = new THREE.Group();
      drone.add(new THREE.Mesh(new THREE.BoxGeometry(1, 0.2, 1), metal(0x3a3f48)));
      var blink = glow(C.bad, 1.4, 0.9);
      blink.position.y = -0.2; drone.add(blink);
      this.scene.add(drone);
      (function (dr, bl, r, h, sp, ph) {
        self.animated.push({ update: function (dt, t) {
          var a = t * sp + ph;
          dr.position.set(Math.cos(a) * r, h + Math.sin(t * 1.3 + ph) * 1.5, Math.sin(a) * r);
          bl.visible = Math.sin(t * 6 + ph) > 0;
        } });
      })(drone, blink, 25 + d * 11, 22 + (d % 3) * 4, (d % 2 ? 1 : -1) * (0.08 + d * 0.01), d * 1.3);
    }
    // slow amber dust in the air, like the site's floating specks
    var drops = this.reduced ? 120 : 700;
    var geo = new THREE.BufferGeometry();
    var arr = new Float32Array(drops * 3);
    for (var r = 0; r < drops; r++) {
      arr[r * 3] = (Math.random() - 0.5) * 240; arr[r * 3 + 1] = Math.random() * 60; arr[r * 3 + 2] = (Math.random() - 0.5) * 240;
    }
    geo.setAttribute("position", new THREE.BufferAttribute(arr, 3));
    glow(C.amber, 1);
    var dust = new THREE.Points(geo, new THREE.PointsMaterial({ color: C.amber2, map: glowTex, size: 0.9, transparent: true, opacity: 0.45,
      blending: THREE.AdditiveBlending, depthWrite: false }));
    this.scene.add(dust);
    this.animated.push({ update: function (dt, t) {
      var p = geo.attributes.position.array;
      for (var k = 0; k < p.length; k += 3) {
        p[k + 1] += dt * 1.2; p[k] += Math.sin(t * 0.3 + k) * dt * 0.4;
        if (p[k + 1] > 60) { p[k + 1] = 0; }
      }
      geo.attributes.position.needsUpdate = true;
    } });
  };

  City.prototype.smokeSource = function (pos, color) {
    var src = { pos: pos.clone(), color: color, active: true, timer: 0 };
    this.smoke.push(src);
    return src;
  };

  City.prototype.sparks = function (pos) {
    var self = this;
    for (var i = 0; i < (this.reduced ? 4 : 14); i++) {
      var s = glow(C.amber2, 0.8, 1);
      s.position.copy(pos);
      var v = new THREE.Vector3((Math.random() - 0.5) * 6, Math.random() * 6, (Math.random() - 0.5) * 6);
      this.scene.add(s);
      (function (mesh, vel) {
        var life = 1.2, item = { update: function (dt) {
          life -= dt; vel.y -= dt * 9; mesh.position.addScaledVector(vel, dt);
          if (life <= 0) { self.scene.remove(mesh); item.dead = true; }
        } };
        self.animated.push(item);
      })(s, v);
    }
  };

  City.prototype.updateSmoke = function (dt) {
    var self = this;
    this.smoke.forEach(function (src) {
      if (!src.active) { return; }
      src.timer -= dt;
      if (src.timer > 0) { return; }
      src.timer = self.reduced ? 1.5 : 0.4;
      var puff = new THREE.Mesh(new THREE.SphereGeometry(0.6, 6, 4), new THREE.MeshBasicMaterial({ color: src.color, transparent: true, opacity: 0.35, depthWrite: false }));
      puff.position.copy(src.pos);
      self.scene.add(puff);
      var life = 3, item = { update: function (d) {
        life -= d; puff.position.y += d * 2; puff.scale.multiplyScalar(1 + d * 0.4);
        puff.material.opacity = Math.max(0, 0.35 * life / 3);
        if (life <= 0) { self.scene.remove(puff); item.dead = true; }
      } };
      self.animated.push(item);
    });
  };

  // ------------------------------------------------------------------ bugs

  City.prototype.makeBug = function (f, building) {
    var type = TYPES[f.bug_type] ? f.bug_type : "glitch";
    var color = TYPES[type].color;
    var sev = { critical: 1.5, high: 1.25, medium: 1.0, low: 0.85, info: 0.7 }[f.severity] || 1;
    var g = new THREE.Group();
    var mat = neon(color, 0.9);
    var body;
    if (type === "sqli") {          // syringe leech
      body = new THREE.Group();
      var barrel = new THREE.Mesh(new THREE.CylinderGeometry(0.35, 0.35, 1.6, 8), mat);
      barrel.rotation.z = Math.PI / 2;
      var needle = new THREE.Mesh(new THREE.ConeGeometry(0.12, 0.9, 6), mat);
      needle.rotation.z = -Math.PI / 2; needle.position.x = 1.2;
      body.add(barrel); body.add(needle);
    } else if (type === "xss") {    // mask imp
      body = new THREE.Group();
      body.add(new THREE.Mesh(new THREE.SphereGeometry(0.6, 10, 8), mat));
      var mask = new THREE.Mesh(new THREE.TorusGeometry(0.55, 0.12, 6, 16), new THREE.MeshBasicMaterial({ color: C.text }));
      mask.position.z = 0.35; body.add(mask);
    } else if (type === "cmdi") {   // shell wraith
      body = new THREE.Mesh(new THREE.ConeGeometry(0.7, 2, 8, 1, true), new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.8 }));
    } else if (type === "traversal") { // tunnel worm
      body = new THREE.Group();
      for (var s = 0; s < 4; s++) {
        var seg = new THREE.Mesh(new THREE.SphereGeometry(0.4 - s * 0.05, 8, 6), mat);
        seg.position.x = -s * 0.55; body.add(seg);
      }
    } else if (type === "secret") { // key thief
      body = new THREE.Group();
      var ring = new THREE.Mesh(new THREE.TorusGeometry(0.4, 0.12, 6, 14), mat);
      var shaft = new THREE.Mesh(new THREE.BoxGeometry(1.2, 0.18, 0.18), mat);
      shaft.position.x = 0.9; body.add(ring); body.add(shaft);
    } else if (type === "dependency") { // rotten crate
      body = new THREE.Mesh(new THREE.BoxGeometry(1, 1, 1), new THREE.MeshStandardMaterial({ color: 0x3b2a12, emissive: color, emissiveIntensity: 0.35 }));
    } else {                        // glitch
      body = new THREE.Mesh(new THREE.IcosahedronGeometry(0.7, 0), new THREE.MeshBasicMaterial({ color: color, wireframe: true }));
    }
    body.position.y = 1.2;
    g.add(body);
    var aura = glow(color, 3.2, 0.55);
    aura.position.y = 1.2; g.add(aura);
    g.userData.aura = aura;
    shadows(body);
    var tag = label(f.id + " " + TYPES[type].name, "#" + ("000000" + color.toString(16)).slice(-6), 6);
    tag.position.y = 3;
    g.add(tag);
    if (f.severity === "critical") {
      var beam = new THREE.Mesh(new THREE.CylinderGeometry(0.12, 0.12, 30, 6), new THREE.MeshBasicMaterial({ color: C.bad, transparent: true, opacity: 0.45, blending: THREE.AdditiveBlending }));
      beam.position.y = 15; g.add(beam);
      g.userData.beam = beam;
    }
    g.scale.setScalar(sev);
    var start = building.group.position.clone();
    start.y = 0;
    g.position.copy(start);
    this.scene.add(g);
    var bug = { f: f, type: type, group: g, body: body, building: building, queue: [], target: null, home: start.clone(),
      final: null, citizen: false, phase: Math.random() * 6 };
    g.traverse(function (o) { o.userData.pick = { kind: "bug", bug: bug }; });
    this.pickables.push(g);
    return bug;
  };

  // Route between two places through the road network (spoke -> ring -> station).
  City.prototype.route = function (from, to) {
    var pts = [];
    var fromR = Math.hypot(from.x, from.z), toR = Math.hypot(to.x, to.z);
    if (fromR > RING + 4) {
      var a1 = Math.atan2(from.z, from.x);
      pts.push(polar(BOULEVARD, a1), polar(RING, a1));
    }
    if (toR > RING + 4) {
      var a2 = Math.atan2(to.z, to.x);
      pts.push(polar(RING, a2), polar(BOULEVARD, a2));
    }
    pts.push(to.clone().setY(0));
    return pts;
  };

  City.prototype.walk = function (bug, dest, then) {
    var from = bug.queue.length ? bug.queue[bug.queue.length - 1].point : bug.group.position;
    var pts = this.route(from, dest);
    for (var i = 0; i < pts.length; i++) {
      bug.queue.push({ point: pts[i], then: i === pts.length - 1 ? then : null });
    }
  };

  City.prototype.toStation = function (bug, key) {
    var st = this.stations[key];
    if (!st) { return; }
    var self = this;
    var jitter = new THREE.Vector3((Math.random() - 0.5) * 3, 0, (Math.random() - 0.5) * 3);
    this.walk(bug, st.pos.clone().add(jitter), function () {
      st.visits += 1;
      if (key === "checkpoint") { self.boomOpen = 1.2; }
      self.ping(st.pos);
    });
  };

  City.prototype.ping = function (pos) {
    var self = this;
    var ring = new THREE.Mesh(new THREE.RingGeometry(0.5, 0.8, 32), new THREE.MeshBasicMaterial({ color: C.amber2, transparent: true, opacity: 0.8, side: THREE.DoubleSide, blending: THREE.AdditiveBlending }));
    ring.rotation.x = -Math.PI / 2; ring.position.copy(pos).setY(0.3);
    this.scene.add(ring);
    var life = 1, item = { update: function (dt) {
      life -= dt; ring.scale.multiplyScalar(1 + dt * 3); ring.material.opacity = Math.max(0, life);
      if (life <= 0) { self.scene.remove(ring); item.dead = true; }
    } };
    this.animated.push(item);
  };

  // ------------------------------------------------------------------ traffic between tools, LLM and sandbox

  // Packet kinds; the colours are explained in the Traffic panel.
  var TRAFFIC = {
    scan: C.sky,        // scanners and re-scans <-> command tower
    llm: C.amber,       // prompts to an LLM backend
    reply: C.amber2,    // LLM replies, patches
    sandbox: C.ok,      // jobs to and results from the sandbox VM
    verdict: C.text,    // gate verdicts to the courthouse / tower
    fail: C.bad         // failed gate or fixer
  };

  City.prototype.anchor = function (x) {
    if (x && x.isVector3) { return x.clone(); }
    if (x && x.group) { return x.group.position.clone().setY(x.height + 1); }   // a building
    var st = this.stations[x];
    if (!st) { return new THREE.Vector3(0, 16, 0); }
    return st.pos.clone().setY(x === "tower" ? 16 : 5);
  };

  City.prototype.link = function (from, to) {
    var a = this.anchor(from), b = this.anchor(to);
    var key = [a.x, a.y, a.z, b.x, b.y, b.z].map(function (n) { return n.toFixed(1); }).join(",");
    var l = this.links[key];
    if (l) { return l; }
    var mid = a.clone().add(b).multiplyScalar(0.5);
    mid.y = Math.max(a.y, b.y) + 4 + a.distanceTo(b) * 0.22;
    var curve = new THREE.QuadraticBezierCurve3(a, mid, b);
    var geo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(48));
    var mat = new THREE.LineDashedMaterial({ color: C.amber, dashSize: 0.8, gapSize: 0.7, transparent: true, opacity: 0.12,
      blending: THREE.AdditiveBlending, depthWrite: false });
    var line = new THREE.Line(geo, mat);
    line.computeLineDistances();
    this.scene.add(line);
    l = { curve: curve, line: line, heat: 0, length: curve.getLength() };
    this.links[key] = l;
    return l;
  };

  // Send `count` packets from -> to, one every `gap` seconds, then call `then`.
  City.prototype.send = function (from, to, kind, count, gap, then) {
    var self = this, n = Math.max(1, count || 1);
    if (this.reduced) { n = 1; }
    var l = this.link(from, to);
    var color = TRAFFIC[kind] || C.amber;
    for (var i = 0; i < n; i++) {
      (function (last) {
        self.later(i * (gap || 0.12), function () { self.packet(l, color, last ? then : null); });
      })(i === n - 1);
    }
  };

  City.prototype.packet = function (l, color, then) {
    if (this.packets.length > 220) { if (then) { then(); } return; }
    var head = glow(color, 2.2, 1);
    var core = new THREE.Mesh(new THREE.SphereGeometry(0.22, 8, 6), new THREE.MeshBasicMaterial({ color: 0xffffff }));
    head.add(core);
    var trail = [glow(color, 1.5, 0.55), glow(color, 1.0, 0.35), glow(color, 0.7, 0.2)];
    this.scene.add(head);
    trail.forEach(function (s) { this.scene.add(s); }, this);
    l.heat = 1;
    l.line.material.color.setHex(color);
    this.packets.push({ link: l, head: head, trail: trail, u: 0, dur: 0.9 + l.length / 45, then: then });
  };

  City.prototype.updateTraffic = function (dt) {
    var self = this;
    this.packets = this.packets.filter(function (p) {
      p.u += dt / p.dur;
      var u = Math.min(1, p.u), e = u * u * (3 - 2 * u);
      p.head.position.copy(p.link.curve.getPoint(e));
      p.trail.forEach(function (s, i) { s.position.copy(p.link.curve.getPoint(Math.max(0, e - 0.035 * (i + 1)))); });
      p.link.heat = 1;
      if (p.u < 1) { return true; }
      self.scene.remove(p.head);
      p.trail.forEach(function (s) { self.scene.remove(s); });
      self.flash(p.link.curve.getPoint(1), p.head.material.color.getHex());
      if (p.then) { p.then(); }
      return false;
    });
    Object.keys(this.links).forEach(function (k) {
      var l = self.links[k];
      l.heat = Math.max(0, l.heat - dt * 0.6);
      l.line.material.opacity = 0.1 + l.heat * 0.55;
    });
    this.traffic.idle -= dt;
    if (this.traffic.idle <= 0) {     // a quiet heartbeat keeps the network visible between events
      this.traffic.idle = this.reduced ? 6 : 2.2;
      var keys = ["oracle", "quarantine", "courthouse", "checkpoint", "garage"];
      this.send("tower", keys[Math.floor(Math.random() * keys.length)], "scan", 1);
    }
  };

  City.prototype.flash = function (pos, color) {
    var self = this, s = glow(color, 1.5, 1);
    s.position.copy(pos);
    this.scene.add(s);
    var life = 0.45, item = { update: function (dt) {
      life -= dt; s.scale.multiplyScalar(1 + dt * 5); s.material.opacity = Math.max(0, life / 0.45);
      if (life <= 0) { self.scene.remove(s); item.dead = true; }
    } };
    this.animated.push(item);
  };

  // Delayed actions on the animation clock, so they respect pause and speed.
  City.prototype.later = function (delay, fn) { this.scheduled.push({ at: (this.time || 0) + delay, fn: fn }); };

  City.prototype.runScheduled = function () {
    var now = this.time || 0, due = [];
    this.scheduled = this.scheduled.filter(function (s) { if (s.at <= now) { due.push(s); return false; } return true; });
    due.forEach(function (s) { s.fn(); });
  };

  City.prototype.backendStation = function (bug) { return (bug && bug.backend && BACKEND_STATION[bug.backend]) || "garage"; };

  City.prototype.trafficFor = function (ev) {
    var id = ev.finding, d = ev.data || {}, self = this;
    var bug = id ? this.bugs[id] : null;
    var b = bug ? bug.building : (id && this.findingBuilding[id]) || (d.path ? this.buildings[d.path] : null);
    switch (ev.type) {
      case "run.start":
        Object.keys(this.districts).forEach(function (k, i) {
          self.later(i * 0.15, function () { self.send("tower", self.districts[k].center.clone().setY(2), "scan", 3, 0.15); });
        });
        break;
      case "selftest.result":
        this.send("tower", "quarantine", "sandbox", 2, 0.2, function () {
          self.send("quarantine", "tower", d.passed ? "sandbox" : "fail", 2, 0.2);
        });
        break;
      case "finding.detected":
        if (b) { this.send(b, "tower", "scan", 2, 0.15); }
        break;
      case "stage.enter":
        if (d.stage === "triage") {
          this.send("tower", "oracle", "llm", 4, 0.12, function () { self.send("oracle", "tower", "reply", 2, 0.15); });
        } else if (d.stage === "fix") {
          if (bug && d.backend) { bug.backend = d.backend; }   // the request itself is drawn on fix.attempt
        } else if (d.stage === "verify") {
          this.send("tower", "courthouse", "scan", 3, 0.15);
        }
        break;
      case "fix.attempt":
        if (bug) { bug.backend = d.backend; }
        if (b) { this.send(b, BACKEND_STATION[d.backend] || "garage", "llm", 5, 0.1); }
        break;
      case "fix.result":
        this.send(BACKEND_STATION[d.backend] || "garage", "checkpoint", d.ok ? "reply" : "fail", 3, 0.15);
        break;
      case "policy.verdict":
        this.send("checkpoint", "courthouse", d.ok ? "verdict" : "fail", 2, 0.2);
        break;
      case "sandbox.start":
        this.send("checkpoint", "quarantine", "sandbox", 6, 0.08);
        break;
      case "sandbox.result":
        this.send("quarantine", "courthouse", "sandbox", 3, 0.15);
        break;
      case "verify.result":
        this.send("courthouse", "tower", d.status === "fail" ? "fail" : (d.status === "pass" ? "sandbox" : "verdict"), 1);
        break;
      case "budget.update":
        this.send(this.backendStation(bug), "tower", "verdict", 1);
        break;
      default:
        break;
    }
  };

  City.prototype.updateBugs = function (dt, t) {
    var self = this;
    Object.keys(this.bugs).forEach(function (id) {
      var bug = self.bugs[id];
      bug.body.rotation.y += dt * (bug.type === "glitch" ? 3 : 1);
      bug.body.position.y = 1.2 + Math.abs(Math.sin(t * 4 + bug.phase)) * 0.3;
      if (!bug.target && bug.queue.length) { bug.target = bug.queue.shift(); }
      if (!bug.target) { return; }
      var pos = bug.group.position;
      var to = bug.target.point;
      var dist = Math.hypot(to.x - pos.x, to.z - pos.z);
      var step = dt * 12;
      if (dist <= step) {
        pos.set(to.x, 0, to.z);
        var cb = bug.target.then;
        bug.target = null;
        if (cb) { cb(); }
      } else {
        pos.x += (to.x - pos.x) / dist * step;
        pos.z += (to.z - pos.z) / dist * step;
        bug.group.rotation.y = -Math.atan2(to.z - pos.z, to.x - pos.x);
      }
    });
  };

  // ------------------------------------------------------------------ events

  City.prototype.handle = function (ev) {
    var id = ev.finding, d = ev.data || {};
    var bug = id ? this.bugs[id] : null;
    var self = this;
    switch (ev.type) {
      case "finding.detected": {
        if (this.bugs[id]) { return; }
        var b = this.buildings[d.path];
        if (!b) { b = this.addBuilding(d.district || "annex", d.path); this.buildings[d.path] = b; }
        b.findings.push(id);
        this.findingBuilding[id] = b;
        this.setBuildingState(b, "latent");
        var f = { id: id, path: d.path, severity: d.severity, bug_type: d.bug_type, district: d.district };
        // the command tower's sweep finds the latent bug, then it hatches
        setTimeout(function () {
          self.setBuildingState(b, "infected");
          self.ping(b.group.position);
          self.bugs[id] = self.makeBug(f, b);
        }, 300 + Math.random() * 600);
        break;
      }
      case "stage.enter":
        if (bug && d.stage === "triage") { this.toStation(bug, "oracle"); }
        if (bug && d.stage === "sandbox") { this.toStation(bug, "quarantine"); }
        if (bug && d.stage === "verify") { this.toStation(bug, "courthouse"); }
        break;
      case "fix.attempt":
        if (bug) { this.toStation(bug, BACKEND_STATION[d.backend] || "garage"); }
        break;
      case "policy.verdict":
        if (bug) { this.toStation(bug, "checkpoint"); }
        break;
      case "finding.outcome":
        if (bug) { this.finish(bug, d.outcome); } else if (id) {
          setTimeout(function () { if (self.bugs[id]) { self.finish(self.bugs[id], d.outcome); } }, 1200);
        }
        break;
      case "budget.update":
        this.stats.tokens = d.tokens_used || this.stats.tokens;
        this.notifyStats();
        break;
      default:
        break;
    }
    this.trafficFor(ev);
  };

  City.prototype.finish = function (bug, outcome) {
    var self = this;
    bug.final = outcome;
    if (outcome === "fixed_verified" || outcome === "fixed_unproven") {
      this.walk(bug, bug.home, function () {
        bug.citizen = true;
        bug.body.traverse(function (o) { if (o.material && o.material.color) { o.material = new THREE.MeshBasicMaterial({ color: C.ok }); } });
        if (bug.group.userData.aura) { bug.group.userData.aura.material.color.setHex(C.ok); }
        if (bug.group.userData.beam) { bug.group.remove(bug.group.userData.beam); }
        self.setBuildingState(bug.building, "repair");
        setTimeout(function () {
          var stillInfected = bug.building.findings.some(function (fid) { var o = self.bugs[fid]; return o && !o.citizen; });
          self.setBuildingState(bug.building, stillInfected ? "infected" : "fixed");
        }, 2500 / self.speed);
        self.stats.repaired += 1;
        self.notifyStats();
      });
    } else if (outcome === "inconclusive") {
      this.walk(bug, this.stations.limbo.pos.clone().add(new THREE.Vector3((Math.random() - 0.5) * 6, 0, (Math.random() - 0.5) * 6)), function () {
        bug.body.traverse(function (o) { if (o.material) { o.material = new THREE.MeshBasicMaterial({ color: C.dim, transparent: true, opacity: 0.35 }); } });
        if (bug.group.userData.aura) { bug.group.userData.aura.material.color.setHex(C.dim); bug.group.userData.aura.material.opacity = 0.2; }
        self.stats.limbo += 1;
        self.notifyStats();
      });
    } else {
      this.walk(bug, this.stations.landfill.pos.clone().add(new THREE.Vector3((Math.random() - 0.5) * 6, 0, (Math.random() - 0.5) * 6)), function () {
        bug.group.scale.multiplyScalar(0.7);
        self.stats.landfill += 1;
        self.notifyStats();
      });
    }
  };

  City.prototype.health = function () {
    var total = 0, bad = 0, self = this;
    Object.keys(this.districts).forEach(function (k) { total += self.districts[k].slots; });
    Object.keys(this.buildings).forEach(function (p) {
      var s = self.buildings[p].state;
      if (s === "infected" || s === "repair") { bad += 1; }
    });
    return total ? Math.round(100 * (total - bad) / total) : 100;
  };

  City.prototype.notifyStats = function () {
    if (this.opts.onStats) {
      this.opts.onStats({ health: this.health(), repaired: this.stats.repaired, landfill: this.stats.landfill,
        limbo: this.stats.limbo, tokens: this.stats.tokens });
    }
  };

  City.prototype.describe = function () {
    var infected = 0, fixed = 0, self = this;
    Object.keys(this.buildings).forEach(function (p) {
      if (self.buildings[p].state === "infected") { infected += 1; }
      if (self.buildings[p].state === "fixed") { fixed += 1; }
    });
    return "City health " + this.health() + "%. " + infected + " infected building(s), " + fixed + " repaired, " +
      this.stats.landfill + " bug(s) in the landfill, " + this.stats.limbo + " in limbo.";
  };

  // ------------------------------------------------------------------ input, loop

  City.prototype.bindInput = function () {
    var el = this.renderer.domElement, o = this.orbit, self = this;
    el.addEventListener("pointerdown", function (e) { o.dragging = true; o.moved = 0; o.lastX = e.clientX; o.lastY = e.clientY; });
    window.addEventListener("pointerup", function (e) {
      if (o.dragging && o.moved < 4) { self.pick(e); }
      o.dragging = false;
    });
    window.addEventListener("pointermove", function (e) {
      if (!o.dragging) { return; }
      var dx = e.clientX - o.lastX, dy = e.clientY - o.lastY;
      o.moved += Math.abs(dx) + Math.abs(dy);
      o.azimuth -= dx * 0.005;
      o.polar = Math.min(1.25, Math.max(0.15, o.polar - dy * 0.003));
      o.lastX = e.clientX; o.lastY = e.clientY; o.idle = 0;
    });
    el.addEventListener("wheel", function (e) {
      e.preventDefault();
      o.dist = Math.min(240, Math.max(40, o.dist * (e.deltaY > 0 ? 1.1 : 0.9)));
    }, { passive: false });
    el.addEventListener("keydown", function (e) {
      if (e.key === "ArrowLeft") { o.azimuth += 0.1; }
      if (e.key === "ArrowRight") { o.azimuth -= 0.1; }
      if (e.key === "+" || e.key === "=") { o.dist = Math.max(40, o.dist * 0.9); }
      if (e.key === "-") { o.dist = Math.min(240, o.dist * 1.1); }
    });
  };

  City.prototype.pick = function (e) {
    var rect = this.renderer.domElement.getBoundingClientRect();
    var mouse = new THREE.Vector2(((e.clientX - rect.left) / rect.width) * 2 - 1, -((e.clientY - rect.top) / rect.height) * 2 + 1);
    this.raycaster.setFromCamera(mouse, this.camera);
    var hits = this.raycaster.intersectObjects(this.pickables, true);
    for (var i = 0; i < hits.length; i++) {
      var info = hits[i].object.userData.pick;
      if (info && this.selectCb) { this.selectCb(info); return; }
    }
  };

  City.prototype.onSelect = function (cb) { this.selectCb = cb; };
  City.prototype.setPaused = function (p) { this.paused = p; };
  City.prototype.setSpeed = function (s) { this.speed = s; };

  City.prototype.loop = function () {
    var self = this;
    var frame = function () {
      requestAnimationFrame(frame);
      var raw = Math.min(self.clock.getDelta(), 0.1);
      if (!self.paused) {
        var dt = raw * self.speed;
        self.time = (self.time || 0) + dt;
        var t = self.time;
        self.animated = self.animated.filter(function (a) { return !a.dead; });
        self.animated.forEach(function (a) { a.update(dt, t); });
        self.cars.forEach(function (c) {
          c.angle += c.speed * dt;
          c.mesh.position.set(Math.cos(c.angle) * c.radius, 0.4, Math.sin(c.angle) * c.radius);
          c.mesh.rotation.y = -c.angle + (c.speed > 0 ? -Math.PI / 2 : Math.PI / 2);
        });
        self.runScheduled();
        self.updateTraffic(dt);
        self.updateSmoke(dt);
        self.updateBugs(dt, t);
        if (!self.orbit.dragging && !self.reduced) { self.orbit.idle += raw; self.orbit.azimuth += Math.sin(self.orbit.idle * 0.2) * raw * 0.02; }
      }
      var o = self.orbit;
      self.camera.position.set(Math.sin(o.polar) * Math.cos(o.azimuth) * o.dist, Math.cos(o.polar) * o.dist, Math.sin(o.polar) * Math.sin(o.azimuth) * o.dist);
      self.camera.lookAt(0, 0, 0);
      self.renderer.render(self.scene, self.camera);
    };
    frame();
  };

  window.SiftCity = { available: available, create: function (el, opts) { window.SiftCity.current = new City(el, opts); return window.SiftCity.current; }, TYPES: TYPES, current: null };
})();
