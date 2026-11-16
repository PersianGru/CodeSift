/* CodeSift UI: the land under the 3D realm. Everything here is scenery built in code (no model files):
   an island with a castle hill, a river with a bridge, roads that join the four places, hills, forest,
   a graveyard, sky and water. It never reads run events - the realm (realm.js) puts the story on top.
   Exposes window.SiftRealmKit. Needs the global THREE (r128). */
(function () {
  "use strict";

  var THREE = window.THREE;
  if (!THREE) { return; }

  // ------------------------------------------------------------------ the map (world units; Y is up)

  var L = {
    size: 224, cell: 2, cx: 0, cz: 0,          // terrain grid: 112 x 112 cells of 2 units
    sea: -0.9,
    core: { x: 0, z: 0, y: 3 },                // the castle hill (flat top)
    gate: { x: 0, z: 10.5 },
    junction: { x: 0, z: 17 },
    bridge: { x: 0, z0: 19.6, z1: 28.4, y: 1.15, hump: 0.75, half: 2.3 },
    wilds: { x: 0, z: 39.5, rx: 17, rz: 8 },   // the project's land: a ruined graveyard
    tower: { x: 34, z: 2, y: 4.6, door: -0.52 },   // door: the way the door faces (rotation about Y)
    dungeon: { x0: -48, x1: -26, z0: -4, z1: 10, y: 3.5, depth: 4 },   // the pit (a hole in the land)
    island: { x: 0, z: -2, r0: 70, r1: 88 }
  };
  L.dungeon.floor = L.dungeon.y - L.dungeon.depth;
  L.dungeon.stairZ = 5; // the stairs come down the east wall, centred on this z

  var RIVER = [[-100, 9], [-72, 15], [-46, 21.5], [-22, 25], [0, 24], [22, 25], [46, 21.5], [72, 15], [100, 9]];
  var ROADS = {
    trunkA: [[0, 9.2], [0, 13], [0, 17], [0, L.bridge.z0 + 0.4]],                 // castle gate -> bridge
    trunkB: [[0, L.bridge.z1 - 0.4], [0, 31.5]],                                // bridge -> the wilds' gate
    wildsW: [[0, 31.5], [-4.5, 35], [-9.5, 37.5], [-13, 41.5]],
    wildsE: [[0, 31.5], [4, 35.5], [8.5, 39], [12, 43]],
    tower: [[0, 17], [8, 18.2], [17, 16.4], [24, 12.6], [28.6, 9.2], [31.2, 6.9]],
    dungeon: [[0, 17], [-8, 18.2], [-15.5, 16.2], [-19.5, 11.5], [-21.2, 7], [-23.4, L.dungeon.stairZ]]
  };
  var HILLS = [[-34, -46, 26, 14], [2, -57, 28, 18], [38, -45, 24, 13], [-63, -15, 17, 10], [63, -13, 18, 9],
    [60, 32, 14, 5], [-58, 38, 15, 5], [-27, 58, 12, 3], [30, 60, 13, 3.5]];

  // ------------------------------------------------------------------ small maths

  function rng(seed) {
    var s = seed >>> 0;
    return function () {
      s = (s + 0x6D2B79F5) >>> 0;
      var t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function lerp(a, b, t) { return a + (b - a) * t; }
  function clamp01(t) { return t < 0 ? 0 : t > 1 ? 1 : t; }
  function smooth(a, b, x) { var t = clamp01((x - a) / (b - a)); return t * t * (3 - 2 * t); }
  function hash2(ix, iz) { var n = Math.sin(ix * 127.1 + iz * 311.7) * 43758.5453; return n - Math.floor(n); }
  function vnoise(x, z) {
    var ix = Math.floor(x), iz = Math.floor(z), fx = x - ix, fz = z - iz;
    fx = fx * fx * (3 - 2 * fx); fz = fz * fz * (3 - 2 * fz);
    return lerp(lerp(hash2(ix, iz), hash2(ix + 1, iz), fx), lerp(hash2(ix, iz + 1), hash2(ix + 1, iz + 1), fx), fz);
  }
  function fbm(x, z) { return vnoise(x, z) * 0.6 + vnoise(x * 2.1 + 7.3, z * 2.1 + 3.1) * 0.28 + vnoise(x * 4.3 + 1.7, z * 4.3 + 9.2) * 0.12; }

  /* A smooth line through the points, as samples about `step` apart: [{x, z}]. */
  function sampleLine(pts, step) {
    var out = [], i, k;
    function cr(p0, p1, p2, p3, t) {
      var t2 = t * t, t3 = t2 * t;
      return 0.5 * ((2 * p1) + (-p0 + p2) * t + (2 * p0 - 5 * p1 + 4 * p2 - p3) * t2 + (-p0 + 3 * p1 - 3 * p2 + p3) * t3);
    }
    for (i = 0; i < pts.length - 1; i++) {
      var a = pts[Math.max(0, i - 1)], b = pts[i], c = pts[i + 1], d = pts[Math.min(pts.length - 1, i + 2)];
      var len = Math.sqrt((c[0] - b[0]) * (c[0] - b[0]) + (c[1] - b[1]) * (c[1] - b[1]));
      var n = Math.max(1, Math.round(len / step));
      for (k = 0; k < n; k++) { out.push({ x: cr(a[0], b[0], c[0], d[0], k / n), z: cr(a[1], b[1], c[1], d[1], k / n) }); }
    }
    var last = pts[pts.length - 1];
    out.push({ x: last[0], z: last[1] });
    return out;
  }
  function nearest(samples, x, z) { // squared distance to the nearest sample, and that sample
    var best = 1e9, at = null;
    for (var i = 0; i < samples.length; i++) {
      var dx = samples[i].x - x, dz = samples[i].z - z, d = dx * dx + dz * dz;
      if (d < best) { best = d; at = samples[i]; }
    }
    return { d: Math.sqrt(best), at: at };
  }

  // ------------------------------------------------------------------ geometry helpers

  /* three.js r128 takes vertex and material colours as linear light: convert the sRGB hex values we write. */
  function lin(hex) { return new THREE.Color(hex).convertSRGBToLinear(); }

  /* Collects simple shapes into one flat-shaded, vertex-coloured geometry (one draw call). */
  function Merger(seed) { this.pos = []; this.col = []; this.rand = rng(seed || 7); this.base = null; }
  /* Everything added after this is placed relative to a spot: at(x, y, z, turn). at() with no arguments resets. */
  Merger.prototype.at = function (x, y, z, ry) { this.base = x === undefined ? null : mat(x, y, z, 0, ry || 0, 0); return this; };
  Merger.prototype.add = function (geo, color, matrix, jitter) {
    var g = geo.index ? geo.toNonIndexed() : geo;
    var p = g.attributes.position, v = new THREE.Vector3(), c = lin(color), j = jitter === undefined ? 0.07 : jitter, k = 1;
    for (var i = 0; i < p.count; i++) {
      if (i % 3 === 0) { k = 1 + (this.rand() - 0.5) * 2 * j; } // one shade per triangle: the hand-cut low-poly look
      v.fromBufferAttribute(p, i);
      if (matrix) { v.applyMatrix4(matrix); }
      if (this.base) { v.applyMatrix4(this.base); }
      this.pos.push(v.x, v.y, v.z);
      this.col.push(c.r * k, c.g * k, c.b * k);
    }
    if (g !== geo) { g.dispose(); }
    geo.dispose();
    return this;
  };
  var M4 = new THREE.Matrix4(), Q = new THREE.Quaternion(), E = new THREE.Euler(), V1 = new THREE.Vector3(), V2 = new THREE.Vector3();
  function mat(x, y, z, rx, ry, rz, sx, sy, sz) {
    E.set(rx || 0, ry || 0, rz || 0);
    Q.setFromEuler(E);
    return new THREE.Matrix4().compose(V1.set(x, y, z), Q, V2.set(sx === undefined ? 1 : sx, sy === undefined ? (sx === undefined ? 1 : sx) : sy, sz === undefined ? (sx === undefined ? 1 : sx) : sz));
  }
  Merger.prototype.box = function (w, h, d, color, x, y, z, ry, rx, rz) { return this.add(new THREE.BoxGeometry(w, h, d), color, mat(x, y, z, rx, ry, rz)); };
  Merger.prototype.cyl = function (rt, rb, h, seg, color, x, y, z, rx, rz, ry) { return this.add(new THREE.CylinderGeometry(rt, rb, h, seg), color, mat(x, y, z, rx, ry, rz)); };
  Merger.prototype.cone = function (r, h, seg, color, x, y, z, ry) { return this.add(new THREE.ConeGeometry(r, h, seg), color, mat(x, y, z, 0, ry)); };
  Merger.prototype.geometry = function () {
    var g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.Float32BufferAttribute(this.pos, 3));
    g.setAttribute("color", new THREE.Float32BufferAttribute(this.col, 3));
    g.computeVertexNormals();
    return g;
  };
  var flatMat = null;
  function flat() {
    if (!flatMat) { flatMat = new THREE.MeshStandardMaterial({ vertexColors: true, flatShading: true, roughness: 0.95, metalness: 0 }); }
    return flatMat;
  }
  Merger.prototype.mesh = function (parent, noShadow) {
    var m = new THREE.Mesh(this.geometry(), flat());
    m.castShadow = !noShadow; m.receiveShadow = true;
    if (parent) { parent.add(m); }
    return m;
  };

  var glowTex = null;
  function glowTexture() {
    if (glowTex) { return glowTex; }
    var c = document.createElement("canvas"); c.width = c.height = 64;
    var g = c.getContext("2d"), grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
    grad.addColorStop(0, "rgba(255,255,255,1)"); grad.addColorStop(0.25, "rgba(255,255,255,0.7)");
    grad.addColorStop(0.6, "rgba(255,255,255,0.16)"); grad.addColorStop(1, "rgba(255,255,255,0)");
    g.fillStyle = grad; g.fillRect(0, 0, 64, 64);
    glowTex = new THREE.CanvasTexture(c);
    return glowTex;
  }
  function glow(color, size, opacity, soft) {
    var m = new THREE.SpriteMaterial({ map: glowTexture(), color: lin(color), transparent: true, opacity: opacity === undefined ? 1 : opacity,
      blending: soft ? THREE.NormalBlending : THREE.AdditiveBlending, depthWrite: false });
    var s = new THREE.Sprite(m); s.scale.set(size, size, 1);
    return s;
  }
  var decalGeo = null;
  /* A pool of light lying on the ground. */
  function decal(color, size, opacity) {
    if (!decalGeo) { decalGeo = new THREE.PlaneGeometry(1, 1); decalGeo.rotateX(-Math.PI / 2); }
    var m = new THREE.Mesh(decalGeo, new THREE.MeshBasicMaterial({ map: glowTexture(), color: lin(color), transparent: true, opacity: opacity === undefined ? 1 : opacity,
      blending: THREE.AdditiveBlending, depthWrite: false, fog: false }));
    m.scale.set(size, 1, size); m.renderOrder = 2;
    return m;
  }

  // ------------------------------------------------------------------ the land

  function Land() {
    var self = this, name;
    this.L = L;
    this.river = sampleLine(RIVER, 1.5);
    this.roads = {}; this.roadSamples = [];
    for (name in ROADS) { this.roads[name] = sampleLine(ROADS[name], 0.9); }
    for (name in this.roads) { this.roads[name].forEach(function (p) { self.roadSamples.push(p); }); }
    // each road sample gets a height: the land under it, evened out along the road, never below the banks
    for (name in this.roads) {
      var r = this.roads[name], raw = r.map(function (p) { return Math.max(0.75, self.base(p.x, p.z)); });
      r.forEach(function (p, i) {
        var sum = 0, n = 0;
        for (var k = Math.max(0, i - 6); k <= Math.min(r.length - 1, i + 6); k++) { sum += raw[k]; n++; }
        p.y = sum / n;
      });
    }
    this.roads.trunkA[0].y = L.core.y; this.roads.trunkA[1].y = L.core.y;
    var endA = this.roads.trunkA, startB = this.roads.trunkB;
    for (var i = 0; i < 4; i++) { endA[endA.length - 1 - i].y = lerp(L.bridge.y, endA[endA.length - 1 - i].y, i / 4); startB[i].y = lerp(L.bridge.y, startB[i].y, i / 4); }
    this.buildHeights();
  }

  /* The land before roads are cut into it. */
  Land.prototype.base = function (x, z) {
    var n = fbm(x * 0.045 + 10, z * 0.045 + 20), d, s, i;
    var h = 0.55 + (n - 0.5) * 2.0 + fbm(x * 0.16, z * 0.16) * 0.5;
    for (i = 0; i < HILLS.length; i++) {
      var hl = HILLS[i], dx = (x - hl[0]) / hl[2], dz = (z - hl[1]) / hl[2], q = dx * dx + dz * dz;
      if (q < 1) { h += hl[3] * (1 - q) * (1 - q) * (0.75 + 0.5 * vnoise(x * 0.12, z * 0.12)); }
    }
    var w = L.wilds, wd = Math.sqrt(((x - w.x) / (w.rx + 5)) * ((x - w.x) / (w.rx + 5)) + ((z - w.z) / (w.rz + 4)) * ((z - w.z) / (w.rz + 4)));
    h = lerp(h, 0.75 + (n - 0.5) * 0.5, (1 - smooth(0.75, 1, wd)) * 0.9);
    d = Math.sqrt(x * x + z * z);
    h = lerp(h, L.core.y, 1 - smooth(15.8, 23, d));
    d = Math.sqrt((x - L.tower.x) * (x - L.tower.x) + (z - L.tower.z) * (z - L.tower.z));
    h = lerp(h, L.tower.y, 1 - smooth(7, 15, d));
    var D = L.dungeon, ox = Math.max(D.x0 - x, 0, x - D.x1), oz = Math.max(D.z0 - z, 0, z - D.z1);
    h = lerp(h, D.y, 1 - smooth(2.5, 9, Math.sqrt(ox * ox + oz * oz)));
    h = lerp(-2.4, h, smooth(1.6, 5.2, nearest(this.river, x, z).d));
    d = Math.sqrt((x - L.island.x) * (x - L.island.x) + (z - L.island.z) * (z - L.island.z));
    return lerp(h, -7, smooth(L.island.r0, L.island.r1, d + (n - 0.5) * 14));
  };

  Land.prototype.buildHeights = function () {
    var n = L.size / L.cell, half = L.size / 2, self = this;
    this.n = n;
    this.h = new Float32Array((n + 1) * (n + 1));
    this.roadW = new Float32Array((n + 1) * (n + 1));
    for (var j = 0; j <= n; j++) {
      for (var i = 0; i <= n; i++) {
        var x = L.cx - half + i * L.cell, z = L.cz - half + j * L.cell;
        var h = self.base(x, z), near = nearest(self.roadSamples, x, z);
        var wgt = 1 - smooth(1.9, 5.0, near.d);
        self.h[j * (n + 1) + i] = lerp(h, near.at.y, wgt);
        self.roadW[j * (n + 1) + i] = 1 - smooth(1.0, 2.6, near.d);
      }
    }
  };

  /* Height of the land at a point (the same triangles the mesh draws, near enough). */
  Land.prototype.height = function (x, z) {
    var n = this.n, fx = (x - L.cx + L.size / 2) / L.cell, fz = (z - L.cz + L.size / 2) / L.cell;
    if (fx < 0 || fz < 0 || fx >= n || fz >= n) { return -7; }
    var i = Math.floor(fx), j = Math.floor(fz), u = fx - i, v = fz - j, w = n + 1;
    return lerp(lerp(this.h[j * w + i], this.h[j * w + i + 1], u), lerp(this.h[(j + 1) * w + i], this.h[(j + 1) * w + i + 1], u), v);
  };

  Land.prototype.deck = function (z) { // the bridge's walking surface
    var b = L.bridge, u = (z - (b.z0 + b.z1) / 2) / ((b.z1 - b.z0) / 2);
    return b.y + b.hump * (1 - u * u);
  };

  /* Where feet stand: the land, the castle courtyard, the bridge deck or the dungeon floor. */
  Land.prototype.ground = function (x, z) {
    var b = L.bridge, D = L.dungeon;
    if (Math.abs(x - b.x) < b.half + 0.3 && z > b.z0 && z < b.z1) { return this.deck(z); }
    if (x > D.x0 && x < D.x1 && z > D.z0 && z < D.z1) { return D.floor; }
    if (Math.abs(x) < 11 && Math.abs(z) < 11) { return L.core.y + 0.1; }
    return this.height(x, z);
  };

  Land.prototype.roadDist = function (x, z) { return nearest(this.roadSamples, x, z).d; };

  Land.prototype.inWilds = function (x, z, grow) {
    var w = L.wilds, g = grow || 0, dx = (x - w.x) / (w.rx + g), dz = (z - w.z) / (w.rz + g);
    return dx * dx + dz * dz < 1;
  };

  /* Waypoints for walking between the castle, the plain and the wilds: through the gate, down the road, over the bridge. */
  var TRUNK = [4.5, 8.8, 13, 17, 20.2, 24, 27.8, 31.5];
  Land.prototype.route = function (from, to) {
    var out = [], lo = Math.min(from.z, to.z), hi = Math.max(from.z, to.z), i;
    var inside = function (p) { return Math.abs(p.x) < 10 && p.z < 10; };
    var south = function (p) { return p.z > 22.5; };
    if (inside(from) !== inside(to) || south(from) !== south(to)) {
      for (i = 0; i < TRUNK.length; i++) { if (TRUNK[i] > lo + 0.3 && TRUNK[i] < hi - 0.3) { out.push(new THREE.Vector3(0, 0, TRUNK[i])); } }
      if (from.z > to.z) { out.reverse(); }
    }
    out.push(new THREE.Vector3(to.x, 0, to.z));
    return out;
  };

  var C = {
    grassA: lin(0x35523a), grassB: lin(0x4f7445), rock: lin(0x676878), rockHi: lin(0x8a8b99),
    sand: lin(0x7a6d54), bed: lin(0x2c3f45), dirt: lin(0x8a6f52), ash: lin(0x45454a),
    pit: lin(0x3a3a44)
  };

  Land.prototype.addTo = function (scene) {
    var n = this.n, w = n + 1, half = L.size / 2, pos = [], col = [], self = this, D = L.dungeon;
    var c = new THREE.Color(), nrm = new THREE.Vector3(), a = new THREE.Vector3(), b = new THREE.Vector3(), cc = new THREE.Vector3();
    function vert(i, j) { return [L.cx - half + i * L.cell, self.h[j * w + i], L.cz - half + j * L.cell]; }
    function tri(p, q, r, road) {
      a.set(q[0] - p[0], q[1] - p[1], q[2] - p[2]); b.set(r[0] - p[0], r[1] - p[1], r[2] - p[2]);
      nrm.crossVectors(a, b).normalize();
      cc.set((p[0] + q[0] + r[0]) / 3, (p[1] + q[1] + r[1]) / 3, (p[2] + q[2] + r[2]) / 3);
      var k = hash2(Math.round(cc.x * 3.1), Math.round(cc.z * 2.7)), slope = 1 - nrm.y;
      c.copy(C.grassA).lerp(C.grassB, clamp01(fbm(cc.x * 0.07, cc.z * 0.07) * 1.5 - 0.25 + (k - 0.5) * 0.35));
      if (self.inWilds(cc.x, cc.z, 3)) { c.lerp(C.ash, self.inWilds(cc.x, cc.z, 0) ? 0.86 : 0.45); }
      if (cc.y > 8) { c.lerp(C.rockHi, smooth(8, 15, cc.y) * 0.6); }
      c.lerp(C.rock, smooth(0.14, 0.34, slope));
      if (cc.y < L.sea + 0.75) { c.lerp(C.sand, 1 - smooth(L.sea + 0.25, L.sea + 0.75, cc.y)); }
      if (cc.y < L.sea - 0.1) { c.lerp(C.bed, smooth(0, 1.2, L.sea - cc.y)); }
      c.lerp(C.dirt, road * (self.inWilds(cc.x, cc.z, 1) ? 0.35 : 0.9));
      var shade = 0.93 + k * 0.14;
      for (var t = 0; t < 3; t++) { var vtx = t === 0 ? p : t === 1 ? q : r; pos.push(vtx[0], vtx[1], vtx[2]); col.push(c.r * shade, c.g * shade, c.b * shade); }
    }
    for (var j = 0; j < n; j++) {
      for (var i = 0; i < n; i++) {
        var p00 = vert(i, j), p10 = vert(i + 1, j), p01 = vert(i, j + 1), p11 = vert(i + 1, j + 1);
        var mx = p00[0] + L.cell / 2, mz = p00[2] + L.cell / 2;
        if (mx > D.x0 && mx < D.x1 && mz > D.z0 && mz < D.z1) { continue; } // the dungeon pit is a hole in the land
        var rd = (self.roadW[j * w + i] + self.roadW[j * w + i + 1] + self.roadW[(j + 1) * w + i] + self.roadW[(j + 1) * w + i + 1]) / 4;
        if ((i + j) % 2) { tri(p00, p01, p10, rd); tri(p10, p01, p11, rd); } else { tri(p00, p01, p11, rd); tri(p00, p11, p10, rd); }
      }
    }
    var g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.Float32BufferAttribute(pos, 3));
    g.setAttribute("color", new THREE.Float32BufferAttribute(col, 3));
    g.computeVertexNormals();
    var mesh = new THREE.Mesh(g, flat());
    mesh.receiveShadow = true; mesh.castShadow = true;
    scene.add(mesh);
    this.mesh = mesh;

    // roads: a ribbon of packed earth with a lighter crown, laid on the cut the land already has
    var rm = new Merger(11), name;
    for (name in this.roads) { this.ribbon(rm, this.roads[name]); }
    var roadMesh = rm.mesh(scene, true);
    roadMesh.material = new THREE.MeshStandardMaterial({ vertexColors: true, flatShading: true, roughness: 1, polygonOffset: true, polygonOffsetFactor: -2, polygonOffsetUnits: -2 });

    // water: one sheet for the sea and the river
    var water = new THREE.Mesh(new THREE.CircleGeometry(520, 48), new THREE.MeshStandardMaterial({ color: 0x1b4868, emissive: 0x07182a, roughness: 0.18, metalness: 0.55,
      transparent: true, opacity: 0.86 }));
    water.rotation.x = -Math.PI / 2; water.position.y = L.sea; water.receiveShadow = true;
    scene.add(water);
    this.water = water;
  };

  Land.prototype.ribbon = function (m, pts) {
    var pos = [], i, edge = lin(0x7d6449), crown = lin(0x9c8160), cols = [];
    for (i = 0; i < pts.length - 1; i++) {
      var p = pts[i], q = pts[i + 1], dx = q.x - p.x, dz = q.z - p.z, len = Math.sqrt(dx * dx + dz * dz) || 1;
      var nx = -dz / len, nz = dx / len, w0 = 1.55 + 0.25 * Math.sin(i * 1.7), w1 = 1.55 + 0.25 * Math.sin((i + 1) * 1.7);
      var y0 = p.y + 0.09, y1 = q.y + 0.09;
      var A = [p.x - nx * w0, y0 - 0.05, p.z - nz * w0], B = [p.x, y0, p.z], Cc = [p.x + nx * w0, y0 - 0.05, p.z + nz * w0];
      var A2 = [q.x - nx * w1, y1 - 0.05, q.z - nz * w1], B2 = [q.x, y1, q.z], C2 = [q.x + nx * w1, y1 - 0.05, q.z + nz * w1];
      [[A, A2, B, 0], [B, A2, B2, 1], [B, B2, Cc, 1], [Cc, B2, C2, 0]].forEach(function (t) {
        var k = 0.92 + m.rand() * 0.16, c = t[3] ? crown : edge;
        for (var s = 0; s < 3; s++) { pos.push(t[s][0], t[s][1], t[s][2]); cols.push(c.r * k, c.g * k, c.b * k); }
      });
    }
    Array.prototype.push.apply(m.pos, pos); Array.prototype.push.apply(m.col, cols);
  };

  // ------------------------------------------------------------------ nature (instanced)

  function pineGeo() {
    var m = new Merger(3);
    m.cyl(0.16, 0.26, 1.3, 5, 0x4a3626, 0, 0.65, 0);
    m.cone(1.55, 2.0, 6, 0x21513c, 0, 2.0, 0); m.cone(1.2, 1.8, 6, 0x286246, 0, 3.1, 0, 0.5); m.cone(0.8, 1.6, 6, 0x337553, 0, 4.2, 0, 1.0);
    return m.geometry();
  }
  function roundTreeGeo() {
    var m = new Merger(4);
    m.cyl(0.18, 0.28, 1.7, 5, 0x4f3a28, 0, 0.85, 0);
    m.add(new THREE.IcosahedronGeometry(1.35, 0), 0x3f7239, mat(0, 2.6, 0, 0, 0, 0, 1, 0.9, 1));
    m.add(new THREE.IcosahedronGeometry(0.95, 0), 0x4b8442, mat(0.7, 3.3, 0.3, 0.4, 0.8, 0));
    m.add(new THREE.IcosahedronGeometry(0.8, 0), 0x376a36, mat(-0.75, 2.2, -0.35, 0.2, 0.3, 0));
    return m.geometry();
  }
  function deadTreeGeo() {
    var m = new Merger(5), c = 0x4b4038;
    m.cyl(0.1, 0.3, 2.8, 5, c, 0, 1.4, 0);
    m.cyl(0.04, 0.11, 1.5, 4, c, 0.45, 2.7, 0, 0, -0.75); m.cyl(0.04, 0.1, 1.3, 4, c, -0.4, 2.4, 0.15, 0.2, 0.8);
    m.cyl(0.03, 0.08, 1.0, 4, c, 0.1, 3.2, -0.3, -0.6, 0.15);
    return m.geometry();
  }
  function rockGeo() {
    var g = new THREE.IcosahedronGeometry(1, 0), p = g.attributes.position, r = rng(9);
    for (var i = 0; i < p.count; i++) { p.setXYZ(i, p.getX(i), p.getY(i) * 0.72, p.getZ(i)); }
    var m = new Merger(6); m.add(g, 0x74768a, mat(0, 0.3, 0, r() * 0.3, 0, r() * 0.3), 0.12);
    return m.geometry();
  }
  function tuftGeo() {
    var m = new Merger(8);
    m.add(new THREE.ConeGeometry(0.1, 0.62, 3), 0x5d8a48, mat(0, 0.3, 0, 0.12, 0, 0.1));
    m.add(new THREE.ConeGeometry(0.09, 0.5, 3), 0x4f7b40, mat(0.14, 0.24, 0.05, -0.2, 1, -0.3));
    m.add(new THREE.ConeGeometry(0.09, 0.46, 3), 0x66934d, mat(-0.13, 0.22, -0.04, 0.2, 2, 0.32));
    return m.geometry();
  }
  function bushGeo() {
    var m = new Merger(12);
    m.add(new THREE.IcosahedronGeometry(0.7, 0), 0x3b6b3a, mat(0, 0.4, 0, 0, 0, 0, 1, 0.75, 1));
    m.add(new THREE.IcosahedronGeometry(0.5, 0), 0x47803f, mat(0.5, 0.35, 0.2, 0.5, 0.5, 0));
    return m.geometry();
  }
  function graveGeo(kind) {
    var m = new Merger(13 + kind), c = 0x7f8192;
    if (kind === 0) { m.box(0.72, 0.9, 0.2, c, 0, 0.45, 0); m.cyl(0.36, 0.36, 0.2, 7, c, 0, 0.9, 0, Math.PI / 2); m.box(0.95, 0.14, 0.42, 0x666878, 0, 0.07, 0); }
    else if (kind === 1) { m.box(0.2, 1.5, 0.2, c, 0, 0.75, 0); m.box(0.82, 0.2, 0.2, c, 0, 1.08, 0); m.box(0.6, 0.14, 0.5, 0x666878, 0, 0.07, 0); }
    else { m.box(0.85, 0.62, 0.24, c, 0, 0.31, 0, 0, 0, 0.08); m.box(0.4, 0.26, 0.24, c, -0.2, 0.74, 0, 0, 0, 0.3); }
    return m.geometry();
  }

  function scatter(scene, geo, items, shadow) {
    if (!items.length) { return null; }
    var mesh = new THREE.InstancedMesh(geo, flat(), items.length), c = new THREE.Color();
    items.forEach(function (it, i) {
      mesh.setMatrixAt(i, mat(it.x, it.y, it.z, it.rx || 0, it.ry || 0, it.rz || 0, it.s, it.sy === undefined ? it.s : it.sy, it.s));
      c.setScalar(it.tint === undefined ? 1 : it.tint); mesh.setColorAt(i, c);
    });
    mesh.castShadow = shadow !== false; mesh.receiveShadow = true;
    scene.add(mesh);
    return mesh;
  }

  /* Trees, rocks and grass, placed by rule (never at random on a road, in the river or inside a place).
     `keep` is a list of {x, z, r} to stay clear of (skeleton and hero spots in the wilds). */
  Land.prototype.plant = function (scene, keep) {
    var r = rng(20261116), self = this, pines = [], rounds = [], rocks = [], tufts = [], bushes = [], dead = [], graves = [[], [], []];
    var D = L.dungeon;
    function clearOf(x, z, pad) {
      if (Math.sqrt(x * x + z * z) < 22 + pad) { return false; }
      if (Math.sqrt((x - L.tower.x) * (x - L.tower.x) + (z - L.tower.z) * (z - L.tower.z)) < 8.5 + pad) { return false; }
      if (x > D.x0 - 4 - pad && x < D.x1 + 5 + pad && z > D.z0 - 4 - pad && z < D.z1 + 4 + pad) { return false; }
      if (nearest(self.roadSamples, x, z).d < 3.4 + pad) { return false; }
      if (Math.abs(x) < 6 && z > 16 && z < 33) { return false; }
      return true;
    }
    function open(x, z, pad) { for (var i = 0; i < keep.length; i++) { var dx = keep[i].x - x, dz = keep[i].z - z; if (dx * dx + dz * dz < (keep[i].r + pad) * (keep[i].r + pad)) { return false; } } return true; }
    var i, x, z, h, tries;
    for (i = 0, tries = 0; i < 330 && tries < 6000; tries++) { // forest: thick on the hills behind, thinning toward the front
      x = (r() - 0.5) * 190; z = (r() - 0.5) * 190 - 2; h = self.height(x, z);
      if (h < L.sea + 0.9 || !clearOf(x, z, 1.2) || self.inWilds(x, z, 5)) { continue; }
      var dens = fbm(x * 0.05 + 3, z * 0.05 + 8) + (z < -16 ? 0.28 : 0) + (Math.abs(x) > 44 ? 0.12 : 0) - (z > 46 ? 0.2 : 0);
      if (dens < 0.58) { continue; }
      var s = 0.8 + r() * 0.75;
      if (z > 30) { s *= 0.75; }
      (r() < (h > 5 || z < -25 ? 0.85 : 0.5) ? pines : rounds).push({ x: x, y: h - 0.1, z: z, ry: r() * 6.3, s: s, sy: s * (0.9 + r() * 0.35), tint: 0.82 + r() * 0.36 });
      i++;
    }
    for (i = 0, tries = 0; i < 110 && tries < 3000; tries++) {
      x = (r() - 0.5) * 180; z = (r() - 0.5) * 180; h = self.height(x, z);
      if (h < L.sea - 0.3 || !clearOf(x, z, -0.6) || !open(x, z, 0.6)) { continue; }
      var big = h > 6 || r() < 0.2;
      rocks.push({ x: x, y: h - 0.15, z: z, rx: r() * 0.5, ry: r() * 6.3, rz: r() * 0.5, s: big ? 1.1 + r() * 1.5 : 0.35 + r() * 0.6, tint: 0.8 + r() * 0.35 });
      i++;
    }
    for (i = 0, tries = 0; i < 620 && tries < 6000; tries++) {
      x = (r() - 0.5) * 150; z = (r() - 0.5) * 150 + 4; h = self.height(x, z);
      if (h < L.sea + 0.35 || h > 7 || nearest(self.roadSamples, x, z).d < 2.1 || (Math.abs(x) < 10.5 && Math.abs(z) < 10.5)) { continue; }
      if (x > D.x0 - 1 && x < D.x1 + 1 && z > D.z0 - 1 && z < D.z1 + 1) { continue; }
      if (r() < 0.12 && clearOf(x, z, 0) && !self.inWilds(x, z, 2)) { bushes.push({ x: x, y: h, z: z, ry: r() * 6.3, s: 0.7 + r() * 0.8, tint: 0.85 + r() * 0.3 }); }
      else { tufts.push({ x: x, y: h, z: z, ry: r() * 6.3, s: 0.8 + r() * 1.1, tint: self.inWilds(x, z, 2) ? 0.6 + r() * 0.2 : 0.85 + r() * 0.35 }); }
      i++;
    }
    var w = L.wilds;
    for (i = 0, tries = 0; i < 34 && tries < 2000; tries++) { // the graveyard
      x = w.x + (r() - 0.5) * 2 * (w.rx + 1.5); z = w.z + (r() - 0.5) * 2 * (w.rz + 1.5);
      if (!self.inWilds(x, z, 1.5) || !open(x, z, 0.9) || nearest(self.roadSamples, x, z).d < 2.2) { continue; }
      graves[Math.floor(r() * 3)].push({ x: x, y: self.height(x, z) - 0.05, z: z, ry: Math.PI + (r() - 0.5) * 0.7, rx: (r() - 0.5) * 0.22, rz: (r() - 0.5) * 0.3, s: 0.9 + r() * 0.5, tint: 0.8 + r() * 0.3 });
      i++;
    }
    for (i = 0, tries = 0; i < 9 && tries < 800; tries++) {
      var ang = r() * 6.3; x = w.x + Math.cos(ang) * (w.rx + 1.5 + r() * 2); z = w.z + Math.sin(ang) * (w.rz + 1.5 + r() * 2);
      if (nearest(self.roadSamples, x, z).d < 4 || !open(x, z, 1.2) || (Math.abs(x) < 5 && z < w.z)) { continue; }
      dead.push({ x: x, y: self.height(x, z) - 0.1, z: z, ry: r() * 6.3, rz: (r() - 0.5) * 0.2, s: 1.1 + r() * 0.7, tint: 0.9 + r() * 0.2 });
      i++;
    }
    scatter(scene, pineGeo(), pines); scatter(scene, roundTreeGeo(), rounds); scatter(scene, rockGeo(), rocks);
    scatter(scene, tuftGeo(), tufts, false); scatter(scene, bushGeo(), bushes); scatter(scene, deadTreeGeo(), dead);
    graves.forEach(function (g, k) { scatter(scene, graveGeo(k), g); });
    this.counts = { trees: pines.length + rounds.length, rocks: rocks.length, tufts: tufts.length };
  };

  // ------------------------------------------------------------------ sky

  function sky(scene) {
    var dome = new THREE.SphereGeometry(460, 32, 16), cols = [], pos = dome.attributes.position, i;
    var top = lin(0x050915), mid = lin(0x13224a), low = lin(0x3d3550);
    for (i = 0; i < pos.count; i++) {
      var h = pos.getY(i) / 460, col = h > 0.12 ? mid.clone().lerp(top, Math.min(1, (h - 0.12) / 0.55)) : low.clone().lerp(mid, clamp01((h + 0.04) / 0.16));
      cols.push(col.r, col.g, col.b);
    }
    dome.setAttribute("color", new THREE.Float32BufferAttribute(cols, 3));
    scene.add(new THREE.Mesh(dome, new THREE.MeshBasicMaterial({ vertexColors: true, side: THREE.BackSide, fog: false, depthWrite: false })));
    var starGeo = new THREE.BufferGeometry(), pts = [], r = rng(42);
    for (i = 0; i < 700; i++) {
      var th = r() * Math.PI * 2, ph = r() * 0.44 * Math.PI, R = 430;
      pts.push(R * Math.sin(ph) * Math.cos(th), R * Math.cos(ph) * 0.9 + 22, R * Math.sin(ph) * Math.sin(th));
    }
    starGeo.setAttribute("position", new THREE.Float32BufferAttribute(pts, 3));
    scene.add(new THREE.Points(starGeo, new THREE.PointsMaterial({ color: 0xcfd8ff, size: 1.5, sizeAttenuation: false, fog: false, transparent: true, opacity: 0.85 })));
    // far mountains: a dark cut-out ring so the island sits in a wider world
    var ring = [], rc = [], seg = 90, near = lin(0x182645), far = lin(0x101a33);
    for (var layer = 0; layer < 2; layer++) {
      var R2 = 330 + layer * 60, c = layer ? far : near, prev = null;
      for (i = 0; i <= seg; i++) {
        var a = i / seg * Math.PI * 2, hgt = (18 + layer * 16) + 46 * fbm(Math.cos(a) * 3 + layer * 9, Math.sin(a) * 3 + 5) * (0.5 + 0.5 * vnoise(i * 0.9, layer));
        var cur = [Math.cos(a) * R2, hgt, Math.sin(a) * R2];
        if (prev) {
          [[prev[0], -12, prev[2]], [cur[0], -12, cur[2]], prev, prev, [cur[0], -12, cur[2]], cur].forEach(function (v) { ring.push(v[0], v[1], v[2]); rc.push(c.r, c.g, c.b); });
        }
        prev = cur;
      }
    }
    var mg = new THREE.BufferGeometry();
    mg.setAttribute("position", new THREE.Float32BufferAttribute(ring, 3));
    mg.setAttribute("color", new THREE.Float32BufferAttribute(rc, 3));
    scene.add(new THREE.Mesh(mg, new THREE.MeshBasicMaterial({ vertexColors: true, side: THREE.DoubleSide, fog: false })));
    var moon = glow(0xe8efff, 70, 1); moon.material.fog = false; moon.position.set(-150, 215, -330); scene.add(moon);
    var halo = glow(0x8fa8ff, 240, 0.28); halo.material.fog = false; halo.position.copy(moon.position); scene.add(halo);
  }

  window.SiftRealmKit = { L: L, Land: Land, Merger: Merger, mat: mat, flat: flat, glow: glow, decal: decal, lin: lin, rng: rng, lerp: lerp, smooth: smooth, clamp01: clamp01, sky: sky };
})();
