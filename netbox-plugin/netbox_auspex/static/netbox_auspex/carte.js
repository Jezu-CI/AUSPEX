/* Carte interactive d'Auspex : zones, actifs observés et flux entre eux.
 *
 * Aucune bibliothèque externe (l'image NetBox se construit hors ligne).
 * Disposition déterministe, lisible pour la microsegmentation : zones IT
 * (tiers) à gauche, zones OT (niveaux Purdue, de 5 à 0) à droite, chaque zone
 * en boîte contenant ses actifs ; les flux sont des courbes, en rouge quand
 * un écart est ouvert sur ce couple.
 */
(function () {
  "use strict";

  var SVG = "http://www.w3.org/2000/svg";
  var BOX_W = 480, PAD = 24, HEAD = 36, CELL = 84, ROW = 58, GAP = 40, COL_GAP = 220;

  function el(name, attrs, parent) {
    var e = document.createElementNS(SVG, name);
    for (var k in attrs) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  function h(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  function kind(n) {
    var t = (n.type || "").toLowerCase();
    if (/automate|plc|rtu|ied|ihm|hmi|scada|historian/.test(t)) return "ot";
    if (/serveur|server|contr[oô]leur|dc|machine virtuelle|vm/.test(t)) return "server";
    if (/poste|workstation|laptop/.test(t)) return "workstation";
    if (/routeur|switch|pare-feu|firewall|commutateur|réseau|reseau/.test(t)) return "network";
    if (!n.type && !n.os) return "unknown";
    return "other";
  }

  function shortLabel(n) {
    if (n.hostname) return n.hostname.length > 13 ? n.hostname.slice(0, 12) + "…" : n.hostname;
    var parts = n.id.split(".");
    return parts.length === 4 ? "." + parts.slice(2).join(".") : n.id;
  }

  /* --- Disposition ------------------------------------------------------------ */
  function layout(data) {
    var byZone = {};
    data.nodes.forEach(function (n) { (byZone[n.zone || ""] = byZone[n.zone || ""] || []).push(n); });
    var cols = { it: [], ot: [] }, known = {};
    data.zones.forEach(function (z) {
      known[z.name || ""] = true;
      if (!(byZone[z.name || ""] || []).length) return;
      cols[z.ot ? "ot" : "it"].push(z);
    });
    // Données incohérentes (actif rattaché à une zone absente de la liste) : regroupées
    // dans un cadre « hors zones » au lieu de faire échouer toute la carte.
    var orphans = [];
    Object.keys(byZone).forEach(function (k) { if (!known[k]) orphans = orphans.concat(byZone[k]); });
    if (orphans.length) {
      if (known[""]) {
        byZone[""] = byZone[""].concat(orphans);
      } else {
        byZone[""] = orphans;
        cols.it.push({ name: null, "class": "", ot: false, assets: orphans.length });
      }
    }
    var boxes = [], pos = {};
    var colX = { it: 0, ot: cols.it.length ? BOX_W + COL_GAP : 0 };
    ["it", "ot"].forEach(function (c) {
      var y = 0;
      cols[c].forEach(function (z) {
        var members = byZone[z.name || ""].slice().sort(function (a, b) {
          return (b.findings - a.findings) || (a.id < b.id ? -1 : 1);
        });
        var perRow = Math.max(1, Math.floor((BOX_W - 2 * PAD) / CELL));
        var rows = Math.ceil(members.length / perRow);
        var height = HEAD + PAD + rows * ROW;
        var box = { zone: z, x: colX[c], y: y, w: BOX_W, h: height };
        boxes.push(box);
        members.forEach(function (n, i) {
          pos[n.id] = { x: box.x + PAD + (i % perRow) * CELL + CELL / 2 - 4,
                        y: box.y + HEAD + Math.floor(i / perRow) * ROW + ROW / 2 };
        });
        y += height + GAP;
      });
    });
    return { boxes: boxes, pos: pos, cols: cols };
  }

  function curve(a, b) {
    var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
    var dx = b.x - a.x, dy = b.y - a.y, len = Math.sqrt(dx * dx + dy * dy) || 1;
    var bend = Math.min(80, len * 0.18);
    var cx = mx - dy / len * bend, cy = my + dx / len * bend;
    return "M" + a.x + " " + a.y + " Q" + cx + " " + cy + " " + b.x + " " + b.y;
  }

  /* --- Rendu -------------------------------------------------------------------- */
  function Map(root, data) {
    this.root = root;
    this.data = data;
    this.nodeById = {};
    var self = this;
    data.zones = data.zones || [];
    data.nodes = (data.nodes || []).filter(function (n) { return n && n.id; });
    data.nodes.forEach(function (n) {
      n.findings = +n.findings || 0;
      n.inventory_findings = Array.isArray(n.inventory_findings) ? n.inventory_findings : [];
      self.nodeById[n.id] = n;
    });
    data.edges = (data.edges || []).filter(function (e) { return e && e.src && e.dst; });
    data.edges.forEach(function (e) { e.findings = e.findings || []; e.ports = e.ports || []; e.count = +e.count || 0; });
    this.L = layout(data);
    this.selected = null;
    this.onlyIssues = false;
    this.build();
  }

  Map.prototype.build = function () {
    var self = this, stage = this.root.querySelector(".auspex-map-stage");
    var svg = el("svg", { class: "auspex-map-svg", role: "img",
                          "aria-label": "Carte des zones, actifs et flux" }, stage);
    var defs = el("defs", {}, svg);
    ["ok", "bad"].forEach(function (k) {
      var m = el("marker", { id: "auspex-arrow-" + k, viewBox: "0 0 10 10", refX: 16, refY: 5,
                             markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, defs);
      el("path", { d: "M0 0 L10 5 L0 10 z", class: "arrow-" + k }, m);
    });
    this.svg = svg;
    this.view = el("g", {}, svg);
    var gz = el("g", { class: "zones" }, this.view);
    this.L.boxes.forEach(function (b) {
      var g = el("g", { class: "zone zone-" + (b.zone.ot ? "ot" : "it"), "data-zone": b.zone.name || "" }, gz);
      el("rect", { x: b.x, y: b.y, width: b.w, height: b.h, rx: 10 }, g);
      var t = el("text", { x: b.x + 14, y: b.y + 22, class: "zone-title" }, g);
      t.textContent = (b.zone.name || "Hors zones déclarées");
      var c = el("text", { x: b.x + b.w - 14, y: b.y + 22, class: "zone-class", "text-anchor": "end" }, g);
      c.textContent = (b.zone["class"] ? b.zone["class"] + " · " : "") + b.zone.assets + " actif" + (b.zone.assets > 1 ? "s" : "");
    });
    this.L.cols.it.length && this.L.cols.ot.length && this.columnTitles();
    var ge = el("g", { class: "edges" }, this.view);
    this.edgeEls = this.data.edges.filter(function (e) {
      return self.L.pos[e.src] && self.L.pos[e.dst];  // extrémité absente : flux ignoré
    }).map(function (e) {
      var a = self.L.pos[e.src], b = self.L.pos[e.dst];
      var bad = e.findings.length > 0;
      var w = Math.min(4.5, 1 + Math.log10(1 + e.count));
      var p = el("path", { d: curve(a, b), class: "edge" + (bad ? " bad" : "") + (e.inter_zone ? " inter" : ""),
                           "stroke-width": w.toFixed(2), "marker-end": "url(#auspex-arrow-" + (bad ? "bad" : "ok") + ")" }, ge);
      p.addEventListener("click", function (ev) { ev.stopPropagation(); self.showEdge(e); });
      return { e: e, p: p };
    });
    var gn = el("g", { class: "nodes" }, this.view);
    this.nodeEls = this.data.nodes.map(function (n) {
      var q = self.L.pos[n.id];
      var g = el("g", { class: "node kind-" + kind(n) + (n.findings ? " has-issue" : "") + (n.silent ? " silent" : ""),
                        transform: "translate(" + q.x + " " + q.y + ")", tabindex: 0, role: "button",
                        "aria-label": (n.hostname || n.id) + (n.findings ? ", " + n.findings + " écart(s)" : "") }, gn);
      el("title", {}, g).textContent = (n.hostname ? n.hostname + " — " : "") + n.id;  // info-bulle : nom complet
      if (n.findings) el("circle", { r: 14, class: "halo" }, g);
      el("circle", { r: 9, class: "dot" }, g);
      var t = el("text", { y: 24, "text-anchor": "middle", class: "label" }, g);
      t.textContent = shortLabel(n);
      g.addEventListener("click", function (ev) { ev.stopPropagation(); self.select(n.id); });
      g.addEventListener("keydown", function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); self.select(n.id); } });
      return { n: n, g: g };
    });
    svg.addEventListener("click", function () { self.clear(); });
    this.enablePanZoom();
    this.fit();
  };

  Map.prototype.columnTitles = function () {
    var it = this.L.boxes.find(function (b) { return !b.zone.ot; });
    var ot = this.L.boxes.find(function (b) { return b.zone.ot; });
    [[it, "Informatique de gestion (tiers)"], [ot, "Industriel (niveaux Purdue)"]].forEach(function (x) {
      var t = el("text", { x: x[0].x, y: -14, class: "col-title" }, this.view);
      t.textContent = x[1];
    }, this);
  };

  /* --- Zoom et déplacement -------------------------------------------------------- */
  Map.prototype.apply = function () {
    this.view.setAttribute("transform", "translate(" + this.tx + " " + this.ty + ") scale(" + this.k + ")");
  };

  Map.prototype.bounds = function () {
    var b = this.L.boxes, x1 = Infinity, y1 = -40, x2 = -Infinity, y2 = -Infinity;
    b.forEach(function (r) { x1 = Math.min(x1, r.x); x2 = Math.max(x2, r.x + r.w); y2 = Math.max(y2, r.y + r.h); });
    return { x: x1 - 20, y: y1, w: (x2 - x1) + 40, h: (y2 - y1) + 20 };
  };

  Map.prototype.fit = function () {
    var r = this.svg.getBoundingClientRect(), b = this.bounds();
    this.k = Math.min(r.width / b.w, r.height / b.h, 1.4);
    this.tx = (r.width - b.w * this.k) / 2 - b.x * this.k;
    this.ty = 10 - b.y * this.k;
    this.apply();
  };

  Map.prototype.zoomAt = function (factor, cx, cy) {
    var k = Math.max(0.15, Math.min(4, this.k * factor));
    factor = k / this.k;
    this.tx = cx - (cx - this.tx) * factor;
    this.ty = cy - (cy - this.ty) * factor;
    this.k = k;
    this.apply();
  };

  Map.prototype.enablePanZoom = function () {
    var self = this, drag = null, moved = false;
    this.svg.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      var r = self.svg.getBoundingClientRect();
      self.zoomAt(ev.deltaY < 0 ? 1.15 : 1 / 1.15, ev.clientX - r.left, ev.clientY - r.top);
    }, { passive: false });
    this.svg.addEventListener("pointerdown", function (ev) {
      drag = { x: ev.clientX, y: ev.clientY, tx: self.tx, ty: self.ty };
      moved = false;
    });
    window.addEventListener("pointermove", function (ev) {
      if (!drag) return;
      var dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
      self.tx = drag.tx + dx;
      self.ty = drag.ty + dy;
      self.apply();
    });
    window.addEventListener("pointerup", function () { drag = null; });
    this.svg.addEventListener("click", function (ev) { if (moved) { ev.stopPropagation(); moved = false; } }, true);
  };

  Map.prototype.centerOn = function (id) {
    var q = this.L.pos[id], r = this.svg.getBoundingClientRect();
    this.k = Math.max(this.k, 1.1);
    this.tx = r.width / 2 - q.x * this.k;
    this.ty = r.height / 2 - q.y * this.k;
    this.apply();
  };

  /* --- Sélection et détails -------------------------------------------------------- */
  Map.prototype.refresh = function () {
    var sel = this.selected, only = this.onlyIssues, linked = {};
    this.edgeEls.forEach(function (x) {
      var touches = sel && (x.e.src === sel || x.e.dst === sel);
      var hidden = (only && !x.e.findings.length) || (sel && !touches);
      x.p.classList.toggle("dim", !!hidden);
      x.p.classList.toggle("hl", !!touches);
      if (touches) { linked[x.e.src] = 1; linked[x.e.dst] = 1; }
    });
    this.nodeEls.forEach(function (x) {
      var dim = (sel && !linked[x.n.id] && x.n.id !== sel) || (only && !sel && !x.n.findings);
      x.g.classList.toggle("dim", !!dim);
      x.g.classList.toggle("selected", x.n.id === sel);
    });
  };

  Map.prototype.clear = function () {
    this.selected = null;
    this.refresh();
    this.panel(null);
  };

  Map.prototype.select = function (id) {
    this.selected = id;
    this.refresh();
    var n = this.nodeById[id], box = h("div");
    box.appendChild(h("div", "auspex-panel-kicker", n.zone || "hors zones"));
    box.appendChild(h("h3", "auspex-panel-title", n.hostname || n.id));
    var dl = h("dl", "auspex-panel-dl");
    [["Adresse", n.id], ["Type", n.type || "inconnu"], ["Système", n.os || "inconnu"],
     ["Fabricant", n.vendor], ["Modèle", n.model], ["Rôles", (n.roles || []).join(", ")],
     ["Vu pour la 1re fois", (n.first_seen || "").slice(0, 10)], ["Dernier passage", (n.last_seen || "").slice(0, 10)]
    ].forEach(function (r) {
      if (!r[1]) return;
      dl.appendChild(h("dt", null, r[0]));
      dl.appendChild(h("dd", null, r[1]));
    });
    box.appendChild(dl);
    if (n.silent) box.appendChild(h("p", "auspex-panel-warn", "Silencieux depuis plus de 7 jours."));
    if (n.findings) box.appendChild(h("p", "auspex-panel-bad", n.findings + " écart(s) de flux concernent cet actif."));
    (n.inventory_findings || []).forEach(function (t) { box.appendChild(h("p", "auspex-panel-warn", "Inventaire : " + t)); });
    var flows = this.data.edges.filter(function (e) { return e.src === id || e.dst === id; })
      .sort(function (a, b) { return (b.findings.length - a.findings.length) || (b.count - a.count); });
    box.appendChild(h("h4", "auspex-panel-sub", "Flux (" + flows.length + ")"));
    var ul = h("ul", "auspex-panel-flows");
    var self = this;
    flows.slice(0, 20).forEach(function (e) {
      var li = h("li", e.findings.length ? "bad" : "");
      var other = e.src === id ? e.dst : e.src, on = self.nodeById[other];
      var a = h("button", "auspex-link", (e.src === id ? "→ " : "← ") + ((on && on.hostname) || other));
      a.type = "button";
      a.addEventListener("click", function () { self.select(other); self.centerOn(other); });
      li.appendChild(a);
      li.appendChild(h("span", "auspex-panel-ports", e.ports.join(", ")));
      if (e.findings.length) li.appendChild(h("span", "auspex-panel-issue", e.findings.join(" · ")));
      ul.appendChild(li);
    });
    box.appendChild(ul);
    this.panel(box);
  };

  Map.prototype.showEdge = function (e) {
    this.selected = null;
    this.refresh();
    var self = this;
    this.edgeEls.forEach(function (x) { x.p.classList.toggle("hl", x.e === e); x.p.classList.toggle("dim", x.e !== e); });
    var s = this.nodeById[e.src], d = this.nodeById[e.dst], box = h("div");
    box.appendChild(h("div", "auspex-panel-kicker", e.inter_zone ? "Flux entre zones" : "Flux dans la zone"));
    box.appendChild(h("h3", "auspex-panel-title", ((s && s.hostname) || e.src) + " → " + ((d && d.hostname) || e.dst)));
    var dl = h("dl", "auspex-panel-dl");
    [["Source", e.src + (s && s.zone ? " (" + s.zone + ")" : "")], ["Destination", e.dst + (d && d.zone ? " (" + d.zone + ")" : "")],
     ["Ports", e.ports.join(", ")], ["Connexions", e.count], ["Dernier passage", (e.last_seen || "").slice(0, 10)]
    ].forEach(function (r) { dl.appendChild(h("dt", null, r[0])); dl.appendChild(h("dd", null, r[1])); });
    box.appendChild(dl);
    box.appendChild(e.findings.length ? h("p", "auspex-panel-bad", "Écart : " + e.findings.join(" · "))
                                      : h("p", "auspex-panel-ok", "Aucun écart ouvert sur ce flux."));
    [e.src, e.dst].forEach(function (id) {
      var b = h("button", "auspex-link", "Voir " + id);
      b.type = "button";
      b.addEventListener("click", function () { self.select(id); self.centerOn(id); });
      box.appendChild(b);
    });
    this.panel(box);
  };

  Map.prototype.panel = function (content) {
    var p = this.root.querySelector(".auspex-map-panel");
    p.textContent = "";
    if (content) { p.appendChild(content); p.hidden = false; }
    else { p.appendChild(h("p", "auspex-panel-hint", "Cliquez un actif ou un flux pour voir le détail.")); }
  };

  /* --- Contrôles ------------------------------------------------------------------------ */
  Map.prototype.search = function (q) {
    q = (q || "").trim().toLowerCase();
    if (!q) return false;
    var hit = this.data.nodes.find(function (n) {
      return n.id === q || (n.hostname || "").toLowerCase() === q;
    }) || this.data.nodes.find(function (n) {
      return n.id.indexOf(q) === 0 || (n.hostname || "").toLowerCase().indexOf(q) !== -1;
    });
    if (!hit) return false;
    this.select(hit.id);
    this.centerOn(hit.id);
    return true;
  };

  function boot(root) {
    var status = root.querySelector(".auspex-map-status");
    fetch(root.getAttribute("data-src"), { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) {
        if (!r.ok) throw new Error(r.status === 404 ? "Aucune donnée : le service Auspex n'a pas encore produit la carte."
                                                    : "Lecture des données impossible (HTTP " + r.status + ").");
        return r.json();
      })
      .then(function (data) {
        if (!data.nodes.length) { status.textContent = "Aucun actif observé pour l'instant."; return; }
        var m = new Map(root, data);
        m.panel(null);
        var issues = data.edges.filter(function (e) { return e.findings.length; }).length;
        status.textContent = data.nodes.length + " actifs, " + data.edges.length + " flux dont " + issues +
          " en écart" + (data.truncated.nodes || data.truncated.edges
            ? " (carte limitée : " + data.truncated.nodes + " actifs et " + data.truncated.edges + " flux non affichés)" : "") +
          " · données du " + data.generated_at.slice(0, 16).replace("T", " ") + " UTC";
        root.querySelector("[data-action=fit]").addEventListener("click", function () { m.fit(); });
        root.querySelector("[data-action=zoom-in]").addEventListener("click", function () {
          var r = m.svg.getBoundingClientRect(); m.zoomAt(1.25, r.width / 2, r.height / 2); });
        root.querySelector("[data-action=zoom-out]").addEventListener("click", function () {
          var r = m.svg.getBoundingClientRect(); m.zoomAt(0.8, r.width / 2, r.height / 2); });
        var only = root.querySelector("[data-action=issues]");
        only.addEventListener("change", function () { m.onlyIssues = only.checked; m.refresh(); });
        var form = root.querySelector("form.auspex-map-search"), input = form.querySelector("input");
        form.addEventListener("submit", function (ev) {
          ev.preventDefault();
          input.setCustomValidity(m.search(input.value) ? "" : "Aucun actif ne correspond.");
          input.reportValidity();
        });
        input.addEventListener("input", function () { input.setCustomValidity(""); });
        window.addEventListener("resize", function () { m.fit(); });
        root.classList.add("ready");
        window.auspexMap = m;  // pour les tests et les captures
      })
      .catch(function (err) { status.textContent = err.message; status.classList.add("text-danger"); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var root = document.getElementById("auspex-map");
    if (root) boot(root);
  });
})();
