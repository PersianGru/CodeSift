/* CodeSift "living city": a top-down neon night city of the user's project, driven by run events.
   Buildings are files grouped in districts; findings are bug characters that walk to the ops centre
   and come back repaired, go to the landfill (rejected) or to limbo (inconclusive). */
(function () {
  "use strict";
  var THREE = window.THREE;

  var TYPES = {
    sqli: { name: "Syringe leech", color: 0xff3b5c },
    xss: { name: "Mask imp", color: 0xff2fd6 },
    cmdi: { name: "Shell wraith", color: 0xffb52e },
    traversal: { name: "Tunnel worm", color: 0x9b5cff },
    secret: { name: "Key thief", color: 0xffe066 },
    dependency: { name: "Rotten crate", color: 0x7dff4d },
    glitch: { name: "Glitch", color: 0x2ef2ff }
  };
  var DISTRICT_ORDER = ["db", "web", "tools", "uploads", "config", "vendor", "annex"];
  var DISTRICT_NAMES = {
    db: "db/ Data Vault", web: "web/ Neon Market", tools: "tools/ Workshop Row", uploads: "uploads/ Storage Yard",
    config: "config/ Config Bank", vendor: "vendor/ Supply Docks", annex: "Annex"
  };
  var STATE_COLORS = { healthy: 0x2ef2ff, latent: 0x2ef2ff, infected: 0xff3b5c, repair: 0xffb52e, fixed: 0x36ff8a };
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
    ctx.font = "bold 40px system-ui, sans-serif";
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.shadowColor = color; ctx.shadowBlur = 16;
    ctx.fillStyle = color;
    ctx.fillText(String(text).slice(0, 28), 256, 48);
    var tex = new THREE.CanvasTexture(canvas);
    var sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
    var s = scale || 6;
    sprite.scale.set(s, s * 96 / 512, 1);
    return sprite;
  }

  function windowTexture(seed) {
    var canvas = document.createElement("canvas");
    canvas.width = 64; canvas.height = 128;
    var ctx = canvas.getContext("2d");
    ctx.fillStyle = "#0b0a1a"; ctx.fillRect(0, 0, 64, 128);
    var r = seed;
    for (var y = 4; y < 128; y += 10) {
      for (var x = 4; x < 64; x += 10) {
        r = (r * 9301 + 49297) % 233280;
        if (r / 233280 > 0.45) {
          ctx.fillStyle = r % 3 === 0 ? "#ff7ae6" : (r % 3 === 1 ? "#7af6ff" : "#ffe9a8");
          ctx.fillRect(x, y, 5, 5);
        }
      }
    }
    var tex = new THREE.CanvasTexture(canvas);
    tex.wrapS = tex.wrapT = THREE.RepeatWrapping;
    return tex;
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
    this.stats = { repaired: 0, landfill: 0, limbo: 0, tokens: 0 };
    this.container = container;
    this.init();
  }

  City.prototype.init = function () {
    var w = this.container.clientWidth || 800, h = this.container.clientHeight || 600;
    this.renderer = new THREE.WebGLRenderer({ antialias: true });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.setSize(w, h);
    this.renderer.setClearColor(0x07060f);
    this.container.appendChild(this.renderer.domElement);
    this.renderer.domElement.setAttribute("tabindex", "0");
    this.renderer.domElement.setAttribute("aria-label", "3D city view; use the plain dashboard for a text version");
    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.Fog(0x07060f, 120, 260);
    this.camera = new THREE.PerspectiveCamera(45, w / h, 0.5, 600);
    this.orbit = { azimuth: 0.6, polar: 0.42, dist: 150, dragging: false, lastX: 0, lastY: 0, idle: 0 };
    this.scene.add(new THREE.AmbientLight(0x6060a0, 0.55));
    var moon = new THREE.DirectionalLight(0x8899ff, 0.5);
    moon.position.set(-40, 120, 30);
    this.scene.add(moon);
    this.clock = new THREE.Clock();
    this.raycaster = new THREE.Raycaster();
    this.buildGround();
    this.buildRoads();
    this.buildOpsCenter();
    this.buildDistricts();
    this.buildLife();
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

  City.prototype.buildGround = function () {
    var ground = new THREE.Mesh(new THREE.PlaneGeometry(400, 400), new THREE.MeshStandardMaterial({ color: 0x0a0918, roughness: 1 }));
    ground.rotation.x = -Math.PI / 2;
    this.scene.add(ground);
    var grid = new THREE.GridHelper(400, 80, 0x1c1840, 0x120f2c);
    grid.position.y = 0.02;
    this.scene.add(grid);
  };

  City.prototype.road = function (a, b, width, color) {
    var len = a.distanceTo(b);
    var mesh = new THREE.Mesh(new THREE.BoxGeometry(len, 0.1, width), new THREE.MeshStandardMaterial({ color: 0x15132e, emissive: color, emissiveIntensity: 0.08 }));
    mesh.position.copy(a).add(b).multiplyScalar(0.5);
    mesh.position.y = 0.05;
    mesh.rotation.y = -Math.atan2(b.z - a.z, b.x - a.x);
    this.scene.add(mesh);
    var line = new THREE.Mesh(new THREE.BoxGeometry(len, 0.12, 0.15), new THREE.MeshBasicMaterial({ color: color }));
    line.position.copy(mesh.position); line.rotation.copy(mesh.rotation);
    this.scene.add(line);
  };

  City.prototype.buildRoads = function () {
    var i, n = 5;
    for (i = 0; i < n; i++) {   // pentagon ring road around the ops centre
      this.road(polar(RING, i * 2 * Math.PI / n), polar(RING, (i + 1) * 2 * Math.PI / n), 3, 0xff2fd6);
    }
    var seg = 56;
    for (i = 0; i < seg; i++) { // boulevard loop
      this.road(polar(BOULEVARD, i * 2 * Math.PI / seg), polar(BOULEVARD, (i + 1) * 2 * Math.PI / seg), 4, 0x2ef2ff);
    }
    for (i = 0; i < DISTRICT_ORDER.length; i++) { // spokes: districts -> boulevard -> ring
      var a = this.districtAngle(i);
      this.road(polar(RING, a), polar(DISTRICT_R - 8, a), 2.5, 0x6a5cff);
    }
  };

  City.prototype.districtAngle = function (i) { return -Math.PI / 2 + i * 2 * Math.PI / DISTRICT_ORDER.length; };

  City.prototype.station = function (key, title, pos, build) {
    var group = new THREE.Group();
    group.position.copy(pos);
    build.call(this, group);
    var tag = label(title, "#e8e6ff", 7);
    tag.position.set(0, 9, 0);
    group.add(tag);
    group.traverse(function (o) { o.userData.pick = { kind: "station", key: key, title: title }; });
    this.scene.add(group);
    this.pickables.push(group);
    this.stations[key] = { group: group, pos: pos.clone(), title: title, visits: 0 };
    return group;
  };

  function neon(color, intensity) {
    return new THREE.MeshStandardMaterial({ color: 0x14122c, emissive: color, emissiveIntensity: intensity || 0.6, roughness: 0.4 });
  }

  City.prototype.buildOpsCenter = function () {
    var self = this;
    // Command tower: scanner sweep + globe
    this.station("tower", "Command tower", new THREE.Vector3(0, 0, 0), function (g) {
      var tower = new THREE.Mesh(new THREE.CylinderGeometry(1.2, 2.2, 14, 6), neon(0x2ef2ff, 0.5));
      tower.position.y = 7; g.add(tower);
      var globe = new THREE.Mesh(new THREE.SphereGeometry(1.8, 12, 10), new THREE.MeshBasicMaterial({ color: 0x2ef2ff, wireframe: true }));
      globe.position.y = 15.5; g.add(globe);
      var sweep = new THREE.Mesh(new THREE.CircleGeometry(BOULEVARD + 25, 32, 0, 0.35),
        new THREE.MeshBasicMaterial({ color: 0x2ef2ff, transparent: true, opacity: 0.07, side: THREE.DoubleSide, depthWrite: false }));
      sweep.rotation.x = -Math.PI / 2; sweep.position.y = 0.3; g.add(sweep);
      self.animated.push({ update: function (dt) { globe.rotation.y += dt * 0.8; sweep.rotation.z += dt * 0.45; } });
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
    var eye = new THREE.Mesh(new THREE.SphereGeometry(1.6, 16, 12), neon(0xffffff, 0.3));
    var iris = new THREE.Mesh(new THREE.TorusGeometry(0.9, 0.25, 8, 20), new THREE.MeshBasicMaterial({ color: 0xff2fd6 }));
    eye.position.y = 4; iris.position.set(0, 4, 1.45); g.add(eye); g.add(iris);
    this.animated.push({ update: function (dt, t) { eye.position.y = iris.position.y = 4 + Math.sin(t * 1.5) * 0.5; } });
  };
  City.prototype.build_garage = function (g) {
    var box = new THREE.Mesh(new THREE.BoxGeometry(5, 3, 4), neon(0x36ff8a, 0.35));
    box.position.y = 1.5; g.add(box);
    var worker = new THREE.Mesh(new THREE.CylinderGeometry(0.3, 0.3, 1.2, 8), neon(0xffe066, 0.8));
    worker.position.set(0, 0.7, 2.6); g.add(worker);
    this.animated.push({ update: function (dt, t) { worker.position.x = Math.sin(t * 2) * 2; } });
  };
  City.prototype.build_forge = function (g) {
    var box = new THREE.Mesh(new THREE.BoxGeometry(4.5, 3.5, 4), neon(0xff6a2e, 0.4));
    box.position.y = 1.75; g.add(box);
    var chimney = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.7, 3, 8), neon(0xff6a2e, 0.6));
    chimney.position.set(1.2, 5, 0); g.add(chimney);
    var fire = new THREE.PointLight(0xff6a2e, 1.4, 14);
    fire.position.set(1.2, 7, 0); g.add(fire);
    this.animated.push({ update: function (dt, t) { fire.intensity = 1.1 + Math.sin(t * 13) * 0.3 + Math.random() * 0.2; } });
  };
  City.prototype.build_relay = function (g) {
    var mast = new THREE.Mesh(new THREE.ConeGeometry(1.5, 9, 4, 1, true), new THREE.MeshBasicMaterial({ color: 0x9b5cff, wireframe: true }));
    mast.position.y = 4.5; g.add(mast);
    var dish = new THREE.Mesh(new THREE.SphereGeometry(1.2, 12, 8, 0, Math.PI * 2, 0, Math.PI / 3), neon(0x9b5cff, 0.7));
    dish.position.y = 9; dish.rotation.x = Math.PI / 2; g.add(dish);
    this.animated.push({ update: function (dt) { dish.rotation.z += dt * 1.2; } });
  };
  City.prototype.build_checkpoint = function (g) {
    var arch = new THREE.Mesh(new THREE.TorusGeometry(2.5, 0.3, 8, 20, Math.PI), neon(0x2ef2ff, 0.8));
    arch.position.y = 0.2; g.add(arch);
    var boom = new THREE.Mesh(new THREE.BoxGeometry(4, 0.25, 0.25), neon(0xff3b5c, 0.8));
    boom.position.set(0, 1.2, 0.8); g.add(boom);
    var shield = new THREE.Mesh(new THREE.CircleGeometry(1, 6), new THREE.MeshBasicMaterial({ color: 0x2ef2ff, transparent: true, opacity: 0.5, side: THREE.DoubleSide }));
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
    var dome = new THREE.Mesh(new THREE.SphereGeometry(3.2, 14, 8, 0, Math.PI * 2, 0, Math.PI / 2),
      new THREE.MeshBasicMaterial({ color: 0x36ff8a, wireframe: true }));
    g.add(dome);
    var mark = label("NO NETWORK", "#36ff8a", 5);
    mark.position.set(0, 4.2, 0); g.add(mark);
  };
  City.prototype.build_courthouse = function (g) {
    var base = new THREE.Mesh(new THREE.BoxGeometry(5, 1, 4), neon(0xe8e6ff, 0.2));
    base.position.y = 0.5; g.add(base);
    for (var i = -2; i <= 2; i += 1) {
      var col = new THREE.Mesh(new THREE.CylinderGeometry(0.2, 0.2, 3, 6), neon(0xe8e6ff, 0.35));
      col.position.set(i, 2.5, 1.6); g.add(col);
    }
    var beam = new THREE.Group();
    beam.position.y = 5.5;
    var bar = new THREE.Mesh(new THREE.BoxGeometry(4, 0.15, 0.15), neon(0xffe066, 0.8));
    beam.add(bar);
    [-1.8, 1.8].forEach(function (x) {
      var pan = new THREE.Mesh(new THREE.CylinderGeometry(0.6, 0.6, 0.1, 12), neon(0xffe066, 0.8));
      pan.position.set(x, -0.6, 0); beam.add(pan);
    });
    g.add(beam);
    var ring = new THREE.Mesh(new THREE.TorusGeometry(3.4, 0.08, 6, 40), new THREE.MeshBasicMaterial({ color: 0xffe066 }));
    ring.rotation.x = Math.PI / 2; ring.position.y = 0.3; g.add(ring);
    this.animated.push({ update: function (dt, t) { beam.rotation.z = Math.sin(t * 1.3) * 0.15; ring.rotation.z += dt * 0.5; } });
  };
  City.prototype.build_landfill = function (g) {
    var fence = new THREE.Mesh(new THREE.CylinderGeometry(5, 5, 1.5, 12, 1, true), new THREE.MeshBasicMaterial({ color: 0x5a5a6a, wireframe: true }));
    fence.position.y = 0.75; g.add(fence);
    for (var i = 0; i < 4; i++) {
      var pile = new THREE.Mesh(new THREE.ConeGeometry(1.2, 1.2, 6), new THREE.MeshStandardMaterial({ color: 0x2a2433 }));
      pile.position.set(Math.cos(i * 1.7) * 2.5, 0.6, Math.sin(i * 1.7) * 2.5); g.add(pile);
    }
    var fire = new THREE.PointLight(0xff4a1a, 1.2, 12);
    fire.position.set(0, 1.5, 0); g.add(fire);
    var barrel = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.5, 1, 10), neon(0xff4a1a, 0.6));
    barrel.position.set(0, 0.5, 0); g.add(barrel);
    this.animated.push({ update: function (dt, t) { fire.intensity = 0.9 + Math.random() * 0.5; } });
    this.smokeSource(g.position, 0xff8a5a);
  };
  City.prototype.build_limbo = function (g) {
    var fog = new THREE.Mesh(new THREE.CircleGeometry(5, 24), new THREE.MeshBasicMaterial({ color: 0x9a94c7, transparent: true, opacity: 0.12 }));
    fog.rotation.x = -Math.PI / 2; fog.position.y = 0.1; g.add(fog);
  };

  City.prototype.buildDistricts = function () {
    var self = this;
    DISTRICT_ORDER.forEach(function (key, i) {
      var a = self.districtAngle(i);
      var center = polar(DISTRICT_R, a);
      var name = (self.opts.districtNames && self.opts.districtNames[key]) || DISTRICT_NAMES[key];
      var sign = label(name, "#ff2fd6", 12);
      sign.position.set(center.x, 16, center.z);
      self.scene.add(sign);
      var pad = new THREE.Mesh(new THREE.CircleGeometry(15, 6), new THREE.MeshStandardMaterial({ color: 0x0e0c22 }));
      pad.rotation.x = -Math.PI / 2; pad.position.set(center.x, 0.03, center.z);
      self.scene.add(pad);
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
      d.overflow.sign.material.map = label("+" + d.overflowCount + " files", "#e8e6ff").material.map;
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
    var body = new THREE.Mesh(new THREE.BoxGeometry(5, h, 5), new THREE.MeshStandardMaterial({ color: 0x15122e, emissive: 0xffffff, emissiveMap: tex, emissiveIntensity: 0.55, roughness: 0.6 }));
    body.position.y = h / 2;
    group.add(body);
    var edges = new THREE.LineSegments(new THREE.EdgesGeometry(body.geometry), new THREE.LineBasicMaterial({ color: STATE_COLORS.healthy }));
    edges.position.copy(body.position);
    group.add(edges);
    var gear = new THREE.Mesh(new THREE.TorusGeometry(0.8, 0.2, 6, 10), neon(0x6a5cff, 0.6));
    gear.rotation.x = Math.PI / 2; gear.position.y = h + 0.4;
    group.add(gear);
    var beacon = new THREE.Mesh(new THREE.SphereGeometry(0.3, 8, 6), new THREE.MeshBasicMaterial({ color: 0xff3b5c }));
    beacon.position.y = h + 1.4;
    group.add(beacon);
    var name = aggregate ? path : (path ? path.split("/").pop() : "");
    var sign = label(name || "", "#2ef2ff", 5);
    sign.position.set(0, h + 2.6, 0);
    sign.visible = !!name;
    group.add(sign);
    this.scene.add(group);
    var b = { path: path, group: group, body: body, edges: edges, gear: gear, beacon: beacon, sign: sign, height: h,
      state: "healthy", district: d, flag: null, scaffold: null, aggregate: aggregate, findings: [] };
    group.traverse(function (o) { o.userData.pick = { kind: "building", building: b }; });
    this.pickables.push(group);
    var phase = Math.random() * 6;
    this.animated.push({ update: function (dt, t) {
      gear.rotation.z += dt * 0.8;
      beacon.visible = Math.sin(t * 2 + phase) > -0.6 || Math.random() > 0.97;
    } });
    return b;
  };

  City.prototype.setBuildingState = function (b, state) {
    b.state = state;
    b.edges.material.color.setHex(STATE_COLORS[state] || STATE_COLORS.healthy);
    if (state === "infected" && !b.flag) {
      var pole = new THREE.Group();
      var stick = new THREE.Mesh(new THREE.CylinderGeometry(0.08, 0.08, 3, 6), new THREE.MeshBasicMaterial({ color: 0xcccccc }));
      stick.position.y = 1.5;
      var cloth = new THREE.Mesh(new THREE.PlaneGeometry(1.4, 0.9), new THREE.MeshBasicMaterial({ color: 0xff3b5c, side: THREE.DoubleSide }));
      cloth.position.set(0.7, 2.6, 0);
      pole.add(stick); pole.add(cloth);
      pole.position.set(1.8, b.height, 1.8);
      b.group.add(pole);
      b.flag = pole;
      b.smoke = this.smokeSource(b.group.position.clone().setY(b.height), 0x777788);
    }
    if (state !== "infected" && b.flag) { b.group.remove(b.flag); b.flag = null; if (b.smoke) { b.smoke.active = false; } }
    if (state === "repair" && !b.scaffold) {
      b.scaffold = new THREE.Mesh(new THREE.BoxGeometry(6, b.height + 1, 6), new THREE.MeshBasicMaterial({ color: 0xffb52e, wireframe: true }));
      b.scaffold.position.y = (b.height + 1) / 2;
      b.group.add(b.scaffold);
      this.sparks(b.group.position.clone().setY(b.height));
    }
    if (state !== "repair" && b.scaffold) { b.group.remove(b.scaffold); b.scaffold = null; }
    if (state === "fixed") { b.beacon.material.color.setHex(0x36ff8a); }
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
      var car = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.5, 0.8), new THREE.MeshBasicMaterial({ color: lane ? 0xff2fd6 : 0x2ef2ff }));
      car.position.y = 0.4;
      this.scene.add(car);
      this.cars.push({ mesh: car, radius: radius, angle: Math.random() * Math.PI * 2, speed: (lane ? 1 : -1) * (0.1 + Math.random() * 0.12) * (onRing ? 1.8 : 1) });
    }
    var droneCount = this.reduced ? 2 : 7;
    for (var d = 0; d < droneCount; d++) {
      var drone = new THREE.Group();
      drone.add(new THREE.Mesh(new THREE.BoxGeometry(1, 0.2, 1), neon(0x9a94c7, 0.4)));
      var blink = new THREE.Mesh(new THREE.SphereGeometry(0.2, 6, 4), new THREE.MeshBasicMaterial({ color: 0xff3b5c }));
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
    var drops = this.reduced ? 250 : 1500;
    var geo = new THREE.BufferGeometry();
    var arr = new Float32Array(drops * 3);
    for (var r = 0; r < drops; r++) {
      arr[r * 3] = (Math.random() - 0.5) * 260; arr[r * 3 + 1] = Math.random() * 80; arr[r * 3 + 2] = (Math.random() - 0.5) * 260;
    }
    geo.setAttribute("position", new THREE.BufferAttribute(arr, 3));
    var rain = new THREE.Points(geo, new THREE.PointsMaterial({ color: 0x7aa0ff, size: 0.35, transparent: true, opacity: 0.55 }));
    this.scene.add(rain);
    this.animated.push({ update: function (dt) {
      var p = geo.attributes.position.array;
      for (var k = 1; k < p.length; k += 3) { p[k] -= dt * 45; if (p[k] < 0) { p[k] = 80; } }
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
      var s = new THREE.Mesh(new THREE.SphereGeometry(0.12, 4, 3), new THREE.MeshBasicMaterial({ color: 0xffe066 }));
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
      var mask = new THREE.Mesh(new THREE.TorusGeometry(0.55, 0.12, 6, 16), new THREE.MeshBasicMaterial({ color: 0xffffff }));
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
    var tag = label(f.id + " " + TYPES[type].name, "#" + ("000000" + color.toString(16)).slice(-6), 6);
    tag.position.y = 3;
    g.add(tag);
    if (f.severity === "critical") {
      var beam = new THREE.Mesh(new THREE.CylinderGeometry(0.12, 0.12, 30, 6), new THREE.MeshBasicMaterial({ color: 0xff3b5c, transparent: true, opacity: 0.45 }));
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
    var ring = new THREE.Mesh(new THREE.RingGeometry(0.5, 0.8, 24), new THREE.MeshBasicMaterial({ color: 0x2ef2ff, transparent: true, opacity: 0.8, side: THREE.DoubleSide }));
    ring.rotation.x = -Math.PI / 2; ring.position.copy(pos).setY(0.3);
    this.scene.add(ring);
    var life = 1, item = { update: function (dt) {
      life -= dt; ring.scale.multiplyScalar(1 + dt * 3); ring.material.opacity = Math.max(0, life);
      if (life <= 0) { self.scene.remove(ring); item.dead = true; }
    } };
    this.animated.push(item);
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
  };

  City.prototype.finish = function (bug, outcome) {
    var self = this;
    bug.final = outcome;
    if (outcome === "fixed_verified" || outcome === "fixed_unproven") {
      this.walk(bug, bug.home, function () {
        bug.citizen = true;
        bug.body.traverse(function (o) { if (o.material && o.material.color) { o.material = new THREE.MeshBasicMaterial({ color: 0x36ff8a }); } });
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
        bug.body.traverse(function (o) { if (o.material) { o.material = new THREE.MeshBasicMaterial({ color: 0x9a94c7, transparent: true, opacity: 0.35 }); } });
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
      o.polar = Math.min(0.9, Math.max(0.15, o.polar - dy * 0.003));
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
