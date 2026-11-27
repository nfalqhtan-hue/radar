/* Tech Radar: threat map. map.json = incidents whose article states a country's role (attributed origin or victim location),
   with the matched words as evidence, plus security news that could not be placed. world.json = country borders (Natural Earth).
   Markers are aggregated per country (one cluster per country), sized by the number of incidents. */
(function () {
  "use strict";
  var R = window.Radar, $ = R.$, el = R.el, svg = R.svg, nf = R.nf, L = R.L;
  var M = null, W = null, st = { days: "30", role: "", cat: "", sev: "", sel: "" };
  var CATS = { ransomware: L("فدية", "Ransomware"), espionage: L("تجسس", "Espionage"), breach: L("اختراق وتسريب بيانات", "Breach and data leak"),
    malware: L("برمجيات خبيثة", "Malware"), phishing: L("تصيّد", "Phishing"), exploitation: L("استغلال ثغرات", "Vulnerability exploitation"), other: L("أخرى", "Other") };
  var ROLE = { origin: L("منسوب إليها حسب المصدر", "Attributed to, per the source"), victim: L("مكان الجهة المستهدفة", "Where the targets are") };
  var SEV = { critical: R.RISK.critical, high: R.RISK.high, medium: R.RISK.medium, low: R.RISK.low, unknown: L("غير معروفة", "Unknown") };
  function str(v, n) { return typeof v === "string" ? v.slice(0, n || 400) : ""; }
  function cname(code) { var c = M.countries[code]; return c ? (R.en ? c.en : c.ar) : code; }

  function inPeriod(x) { var t = Date.parse(x.date); return t && (Date.parse(M.generated_at) - t) <= (+st.days) * 864e5; }
  function passes(x) { return inPeriod(x) && (!st.cat || x.category === st.cat) && (!st.sev || x.severity === st.sev); }
  function places(x) { return (x.places || []).filter(function (p) { return M.countries[p.code] && (!st.role || p.role === st.role); }); }
  function aggregate() {
    var by = {};
    M.incidents.forEach(function (x) {
      if (!passes(x)) return;
      places(x).forEach(function (p) {
        var a = by[p.code] || (by[p.code] = { code: p.code, n: 0, origin: 0, victim: 0, items: [] });
        a.n++; a[p.role]++; a.items.push({ x: x, p: p });
      });
    });
    return by;
  }

  function project(lat, lon) { return [(lon + 180) / 360 * W.w, (W.lat[0] - lat) / (W.lat[0] - W.lat[1]) * W.h]; }

  function drawMap(by) {
    var box = $("map"); box.textContent = "";
    var s = svg("svg", { viewBox: "0 0 " + W.w + " " + W.h, class: "m-svg", role: "img" });
    var codes = Object.keys(by);
    s.setAttribute("aria-label", codes.length ? L("خريطة العالم، دول عليها حوادث: ", "World map; countries with incidents: ") + codes.map(cname).join(R.comma) : L("خريطة العالم، لا حوادث بموقع في هذه الفترة", "World map; no located incidents in this period"));
    var g = svg("g", { class: "land" });
    W.countries.forEach(function (c) { g.appendChild(svg("path", { d: c.d })); });
    s.appendChild(g);
    var max = 1; codes.forEach(function (k) { max = Math.max(max, by[k].n); });
    codes.sort(function (a, b) { return by[b].n - by[a].n; }).forEach(function (k) {
      var a = by[k], c = M.countries[k], xy = project(c.lat, c.lon), r = 13 + 17 * Math.sqrt(a.n / max);
      var grp = svg("g", { class: "mk" + (st.sel === k ? " on" : ""), tabindex: "0", role: "button" });
      grp.setAttribute("aria-label", cname(k) + ": " + R.countL(a.n, ["حادثة", "حادثتان", "حوادث", "حادثة"], ["incident", "incidents"]));
      // two roles at one place: outer ring = attributed origin, inner disc = targets located there
      if (a.origin) grp.appendChild(svg("circle", { cx: xy[0], cy: xy[1], r: r, class: "ring" }));
      if (a.victim) grp.appendChild(svg("circle", { cx: xy[0], cy: xy[1], r: a.origin ? r * 0.55 : r, class: "disc" }));
      var t = svg("text", { x: xy[0], y: xy[1] + 4, class: "mk-n", "text-anchor": "middle" }); t.textContent = nf.format(a.n); grp.appendChild(t);
      grp.appendChild(svg("circle", { cx: xy[0], cy: xy[1], r: Math.max(r, 22), class: "hit" }));
      var pick = function () { st.sel = k; render(); var pn = $("panel"); if (matchMedia("(max-width: 900px)").matches) pn.scrollIntoView({ behavior: R.reduced ? "auto" : "smooth", block: "start" }); };
      grp.addEventListener("click", pick);
      grp.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
      s.appendChild(grp);
    });
    box.appendChild(s);
  }

  function itemLi(x, p) {
    var li = el("li");
    var top = el("div", "m-top");
    top.appendChild(el("span", "pill", CATS[x.category] || CATS.other));
    if (p) { var rp = el("span", "m-role " + p.role, ROLE[p.role]); top.appendChild(rp); }
    if (x.severity && x.severity !== "unknown") { var sv = el("span", "pill", SEV[x.severity] + (x.cve ? " · " + x.cve : "")); sv.style.setProperty("--c", "var(--s-" + x.severity + ")"); top.appendChild(sv); }
    var tm = el("time", null, R.fmtDate(x.date)); tm.dateTime = str(x.date, 40); top.appendChild(tm);
    li.appendChild(top);
    var u = R.safeUrl(x.link), a = el(u ? "a" : "span", null, str(x.title, 300)); if (u) R.link(a, u); a.setAttribute("dir", "auto"); li.appendChild(a);
    if (p && p.evidence) { var q = el("blockquote", "m-ev"); q.setAttribute("dir", "ltr"); q.setAttribute("lang", "en"); q.textContent = str(p.evidence, 300); li.appendChild(q); }
    li.appendChild(el("small", null, L("المصدر: ", "Source: ") + R.srcName(str(x.source, 80))));
    return li;
  }

  function drawPanel(by) {
    var pn = $("panel"); pn.textContent = "";
    var a = st.sel && by[st.sel];
    if (!a) {
      var codes = Object.keys(by);
      pn.appendChild(el("h2", null, L("اختر دولة على الخريطة", "Pick a country on the map")));
      pn.appendChild(el("p", "m-note", codes.length ? L("كل دائرة تجمع حوادث دولة واحدة، ويكبر حجمها بعددها.", "Each circle groups one country's incidents and grows with their number.")
        : L("لا حوادث بموقع مذكور صراحة في هذه الفترة وبهذه التصفية.", "No incidents with an explicitly stated location for this period and filter.")));
      if (codes.length) {
        var ol = el("ol", "m-rank");
        codes.sort(function (x, y) { return by[y].n - by[x].n; }).forEach(function (k) {
          var li = el("li"), b = el("button", null, null); b.type = "button";
          b.appendChild(el("span", null, cname(k))); b.appendChild(el("b", null, nf.format(by[k].n)));
          b.onclick = function () { st.sel = k; render(); }; li.appendChild(b); ol.appendChild(li);
        });
        pn.appendChild(ol);
      }
      return;
    }
    var h = el("div", "m-ph"); h.appendChild(el("h2", null, cname(st.sel)));
    var x = el("button", "icon-btn", "×"); x.type = "button"; x.setAttribute("aria-label", L("إغلاق", "Close")); x.onclick = function () { st.sel = ""; render(); }; h.appendChild(x);
    pn.appendChild(h);
    var cats = {}; a.items.forEach(function (it) { cats[it.x.category] = (cats[it.x.category] || 0) + 1; });
    var facts = el("dl", "m-facts");
    function f(k, v) { var d = el("div"); d.appendChild(el("dt", null, k)); d.appendChild(el("dd", null, v)); facts.appendChild(d); }
    f(L("الحوادث", "Incidents"), nf.format(a.n));
    f(L("منسوبة إليها", "Attributed to it"), nf.format(a.origin));
    f(L("الجهات المستهدفة فيها", "Targets located there"), nf.format(a.victim));
    f(L("التصنيفات", "Categories"), Object.keys(cats).map(function (c) { return (CATS[c] || c) + " (" + nf.format(cats[c]) + ")"; }).join(R.comma));
    var ds = a.items.map(function (it) { return Date.parse(it.x.date); }).filter(Boolean).sort();
    if (ds.length) f(L("التواريخ", "Dates"), R.fmtDate(new Date(ds[0]).toISOString()) + (ds.length > 1 ? L(" إلى ", " to ") + R.fmtDate(new Date(ds[ds.length - 1]).toISOString()) : ""));
    pn.appendChild(facts);
    var ul = el("ul", "m-list");
    a.items.sort(function (p, q) { return Date.parse(q.x.date) - Date.parse(p.x.date); }).forEach(function (it) { ul.appendChild(itemLi(it.x, it.p)); });
    pn.appendChild(ul);
  }

  function drawTable(by) {
    var box = $("t-countries"); box.textContent = "";
    var t = el("table"), hr = el("tr");
    [L("الدولة", "Country"), L("الحوادث", "Incidents"), L("منسوبة إليها", "Attributed"), L("مستهدَفة فيها", "Targets there")].forEach(function (x) { hr.appendChild(el("th", null, x)); });
    var th = el("thead"); th.appendChild(hr); t.appendChild(th);
    var tb = el("tbody");
    Object.keys(by).sort(function (x, y) { return by[y].n - by[x].n; }).forEach(function (k) {
      var tr = el("tr"); [cname(k), by[k].n, by[k].origin, by[k].victim].forEach(function (v) { tr.appendChild(el("td", null, typeof v === "number" ? nf.format(v) : v)); }); tb.appendChild(tr);
    });
    if (!tb.children.length) { var tr0 = el("tr"), td0 = el("td", null, L("لا توجد بيانات.", "No data.")); td0.colSpan = 4; tr0.appendChild(td0); tb.appendChild(tr0); }
    t.appendChild(tb); box.appendChild(t);
  }

  function render() {
    var by = aggregate();
    if (st.sel && !by[st.sel]) st.sel = "";
    ["days", "role"].forEach(function (k) { document.querySelectorAll("#f-" + k + " button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.v === st[k])); }); });
    drawMap(by); drawPanel(by); drawTable(by);
    var n = M.incidents.filter(passes).length, un = M.unlocated.filter(passes);
    $("map-note").textContent = R.en
      ? n + " located " + (n === 1 ? "incident" : "incidents") + " and " + un.length + " unlocated in this period. Location is never inferred: it comes from the article's own words, quoted under each incident."
      : R.count(n, "حادثة واحدة", "حادثتان", "حوادث", "حادثة") + " بموقع، و" + R.count(un.length, "واحدة", "اثنتان", "حوادث", "حادثة") + " بلا موقع في هذه الفترة. الموقع لا يُستنتج أبداً: مصدره كلمات الخبر نفسه، ومقتبسة تحت كل حادثة.";
    var ul = $("unloc"); ul.textContent = "";
    un.slice(0, 60).forEach(function (x) { ul.appendChild(itemLi(x, null)); });
    if (!un.length) ul.appendChild(el("li", "m-note", L("لا شيء في هذه الفترة.", "Nothing in this period.")));
    var p = new URLSearchParams();
    if (st.days !== "30") p.set("d", st.days); if (st.role) p.set("role", st.role); if (st.cat) p.set("cat", st.cat); if (st.sev) p.set("sev", st.sev); if (st.sel) p.set("c", st.sel);
    R.setHash(p);
  }

  function legend() {
    var lg = $("legend"); lg.textContent = "";
    [["ring", L("دائرة مفرغة: هجمات منسوبة إلى جهات مرتبطة بالدولة (حسب المصدر)", "Hollow ring: attacks attributed to actors linked to the country (per the source)")],
     ["disc", L("دائرة ممتلئة: الجهات المستهدفة في الدولة", "Filled disc: the targeted organisations are in the country")]].forEach(function (x) {
      var it = el("span"); var sw = svg("svg", { width: 16, height: 16, viewBox: "0 0 16 16", "aria-hidden": "true" });
      sw.appendChild(svg("circle", { cx: 8, cy: 8, r: 6, class: x[0] })); it.appendChild(sw); it.appendChild(document.createTextNode(x[1])); lg.appendChild(it);
    });
  }
  function selects() {
    var c = $("f-cat"), s = $("f-sev");
    [["", L("الكل", "All")]].concat(Object.keys(CATS).map(function (k) { return [k, CATS[k]]; })).forEach(function (o) { var e = el("option", null, o[1]); e.value = o[0]; c.appendChild(e); });
    [["", L("الكل", "All")]].concat(["critical", "high", "medium", "low", "unknown"].map(function (k) { return [k, SEV[k]]; })).forEach(function (o) { var e = el("option", null, o[1]); e.value = o[0]; s.appendChild(e); });
    s.title = L("الخطورة معروفة فقط حين يذكر الخبر ثغرة CVE يتابعها الرادار (درجة خطرها).", "Severity is known only when the story cites a CVE the radar tracks (its risk score).");
    c.value = st.cat; s.value = st.sev;
    c.onchange = function () { st.cat = c.value; st.sel = ""; render(); };
    s.onchange = function () { st.sev = s.value; st.sel = ""; render(); };
    ["days", "role"].forEach(function (k) { document.querySelectorAll("#f-" + k + " button").forEach(function (b) { b.onclick = function () { st[k] = b.dataset.v; st.sel = ""; render(); }; }); });
  }

  R.status("loading");
  $("map").appendChild(el("span", "skel m-skel"));
  Promise.all([fetch("map.json", { cache: "no-cache" }), fetch("assets/world.json")]).then(function (rs) {
    rs.forEach(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); });
    return Promise.all(rs.map(function (r) { return r.json(); }));
  }).then(function (d) {
    M = d[0]; W = d[1];
    if (!M || !Array.isArray(M.incidents) || !Array.isArray(M.unlocated) || !M.countries || !W || !Array.isArray(W.countries)) throw new Error("bad-format");
    R.status("ok", Date.parse(M.generated_at) || Date.now());
    var p = R.hashParams();
    st.days = ({ "1": 1, "7": 1, "30": 1 })[p.get("d")] ? p.get("d") : "30";
    st.role = ({ origin: 1, victim: 1 })[p.get("role")] ? p.get("role") : "";
    st.cat = CATS[p.get("cat")] ? p.get("cat") : ""; st.sev = SEV[p.get("sev")] ? p.get("sev") : ""; st.sel = M.countries[p.get("c")] ? p.get("c") : "";
    legend(); selects(); render();
  }).catch(function (e) { R.status("error"); $("map").textContent = ""; R.errorNotice($("state"), e, function () { location.reload(); }); });
})();
