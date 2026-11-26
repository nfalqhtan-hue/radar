/* رادار التقنية: الصفحة الرئيسية (الرادار، «ما يحتاج انتباهك الآن»، الخلاصة والتصفية) */
(function () {
  "use strict";
  var R = window.Radar, $ = R.$, el = R.el, svg = R.svg, nf = R.nf;
  var TYPES = R.TYPES, SEV = R.SEV, SEV_ORDER = R.SEV_ORDER, sevOf = R.sevOf, rank = R.rank;
  var PAGE = 40, WINDOW_H = 24, SWEEP_MS = 7000;

  var all = [], byId = {}, genAt = null, lastVisit = null, topIds = {};
  var st = { type: "", sev: "", q: "", sort: "new", newOnly: false, shown: PAGE };
  var FIRST_VISIT_H = 6;   // في أول زيارة لا يوجد «منذ آخر زيارة»، فيُعد جديداً ما وصل في آخر 6 ساعات
  function baseline() { return lastVisit || (genAt - FIRST_VISIT_H * 36e5); }
  function isNew(it) { return it.t > baseline(); }
  function ageH(it) { return (genAt - it.t) / 36e5; }
  // الملخص القالبي («ثغرة أمنية خطورتها متوسطة...») يكرر الشارة والنظام، فلا نعرضه
  function hasText(it) { return !!it.summary && !/^ثغرة أمنية خطورتها/.test(it.summary); }
  function hash(s) { var h = 2166136261; for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967296; }
  function scrollTo(node, block) { node.scrollIntoView({ behavior: R.reduced ? "auto" : "smooth", block: block || "start" }); }
  function filtering() { return !!(st.type || st.sev || st.q || st.newOnly); }

  // ---------- الحالة في الرابط (لمشاركة نتيجة تصفية)
  function readHash() {
    var p = new URLSearchParams(location.hash.slice(1));
    st.type = TYPES[p.get("type")] ? p.get("type") : "";
    st.sev = (SEV[p.get("sev")] || p.get("sev") === "kev") ? p.get("sev") : "";
    st.q = (p.get("q") || "").slice(0, 80);
    st.sort = p.get("sort") === "imp" ? "imp" : "new";
    st.newOnly = p.get("new") === "1";
    $("q").value = st.q;
  }
  function writeHash() {
    var p = new URLSearchParams();
    if (st.type) p.set("type", st.type);
    if (st.sev) p.set("sev", st.sev);
    if (st.q) p.set("q", st.q);
    if (st.sort !== "new") p.set("sort", st.sort);
    if (st.newOnly) p.set("new", "1");
    var v = R.hashParams().get("v"); if (v) p.set("v", v);   // نافذة تفاصيل مفتوحة تبقى في الرابط
    R.setHash(p);
  }

  // ---------- التصفية والترتيب
  function match(it, skip) {
    if (skip !== "new" && st.newOnly && !isNew(it)) return false;
    if (skip !== "type" && st.type && it.type !== st.type) return false;
    if (skip !== "sev" && st.sev) {
      if (st.sev === "kev") { if (!it.kev) return false; }
      else if (sevOf(it) !== st.sev) return false;
    }
    if (st.q) {
      var hay = (it.title + " " + (it.summary || "") + " " + (it.system || "") + " " + R.srcName(it.source)).toLowerCase();
      if (hay.indexOf(st.q.toLowerCase()) === -1) return false;
    }
    return true;
  }
  function sorted(list) {
    return list.slice().sort(st.sort === "imp"
      ? function (a, b) { return rank(b) - rank(a) || b.t - a.t; }
      : function (a, b) { return b.t - a.t; });
  }

  // ---------- عنصر في الخلاصة
  function item(it) {
    var sv = sevOf(it), cv = R.splitCve(it);
    var art = el("article", "item" + (hasText(it) ? "" : " compact"));
    art.id = "i-" + it.id; art.style.setProperty("--c", sv ? "var(--s-" + sv + ")" : "var(--s-news)");
    art.appendChild(el("div", "rail"));
    var body = el("div");
    var top = el("div", "item-top");
    top.appendChild(el("span", "tag", TYPES[it.type] || "أخرى"));
    if (cv.id) { var c = el("bdi", "cve", cv.id); top.appendChild(c); }
    if (sv) top.appendChild(el("span", "pill", SEV[sv] + (it.score != null ? " " + Number(it.score).toFixed(1) : "")));
    if (it.kev) top.appendChild(el("span", "pill kev", "ثبت استغلالها"));
    if (lastVisit && it.t > lastVisit) top.appendChild(el("span", "new", "جديد منذ زيارتك"));
    var tm = el("time", "time", R.timeF.format(it.t)); tm.dateTime = new Date(it.t).toISOString(); top.appendChild(tm);
    body.appendChild(top);

    var h = el("h3"); h.setAttribute("dir", "auto");
    var url = R.safeUrl(it.link), text = cv.rest || it.title;
    if (it.type === "vul") {
      // عنوان الثغرة يفتح نافذة التفاصيل، ورابط NVD يبقى في أسفل العنصر
      var da = el("a", null, text); da.href = "#v=" + encodeURIComponent(it.id);
      da.onclick = function (e) { e.preventDefault(); R.openDetail(it); };
      h.appendChild(da);
    } else if (url) h.appendChild(R.link(el("a", null, text), url)); else h.textContent = text;
    body.appendChild(h);
    if (hasText(it)) { var p = el("p", "sum", it.summary); p.setAttribute("dir", "auto"); body.appendChild(p); }
    if (it.advice && R.isCrit(it)) {
      var ad = el("p", "advice"); ad.appendChild(el("b", null, "ماذا تفعل: ")); ad.appendChild(document.createTextNode(it.advice)); body.appendChild(ad);
    }
    var foot = el("div", "item-foot");
    if (it.system) { var s = el("span"); s.appendChild(document.createTextNode("النظام المتأثر: ")); s.appendChild(el("bdi", null, it.system)); foot.appendChild(s); }
    var src = el("span"); src.appendChild(document.createTextNode("المصدر: ")); src.appendChild(el("bdi", null, R.srcName(it.source))); foot.appendChild(src);
    if (url) foot.appendChild(R.link(el("a", null, it.type === "vul" ? "التفاصيل في NVD" : "اقرأ الخبر كاملاً"), url));
    body.appendChild(foot);
    art.appendChild(body);
    return art;
  }

  // ---------- الشريط الجانبي
  function renderSide() {
    var box = $("types"); box.textContent = "";
    var base = all.filter(function (it) { return match(it, "type"); }), cnt = {};
    base.forEach(function (it) { cnt[it.type] = (cnt[it.type] || 0) + 1; });
    [["", "الكل", base.length]].concat(R.TYPE_ORDER.filter(function (t) { return cnt[t]; }).map(function (t) { return [t, TYPES[t], cnt[t]]; }))
      .forEach(function (o) {
        var b = el("button", "filter"); b.type = "button"; b.setAttribute("aria-pressed", String(st.type === o[0]));
        b.appendChild(el("span", null, o[1])); b.appendChild(el("span", "n", nf.format(o[2])));
        b.onclick = function () { st.type = o[0]; if (o[0] && o[0] !== "vul") st.sev = ""; update(); };
        box.appendChild(b);
      });

    var vul = all.filter(function (it) { return it.type === "vul" && match(it, "sev"); }), sc = {};
    vul.forEach(function (it) { var s = sevOf(it); sc[s] = (sc[s] || 0) + 1; });
    // الشريط للعرض فقط، والأزرار هي صفوف المفتاح (أهداف لمس أكبر من شريط ارتفاعه 12px)
    var bar = $("sevbar"), lg = $("sevlegend"); bar.textContent = ""; lg.textContent = "";
    bar.classList.toggle("picking", !!st.sev && st.sev !== "kev");
    SEV_ORDER.forEach(function (s) {
      if (!sc[s]) return;
      var seg = el("span", st.sev === s ? "on" : null); seg.style.setProperty("--c", "var(--s-" + s + ")"); seg.style.flex = String(sc[s]); bar.appendChild(seg);
      var li = el("li"), b = el("button", "sev-btn"); b.type = "button"; b.style.setProperty("--c", "var(--s-" + s + ")");
      b.setAttribute("aria-pressed", String(st.sev === s));
      b.appendChild(el("span", null, SEV[s])); b.appendChild(el("span", "n", nf.format(sc[s])));
      b.onclick = function () { st.sev = st.sev === s ? "" : s; if (st.sev) st.type = "vul"; update(); };
      li.appendChild(b); lg.appendChild(li);
    });
    var kev = vul.filter(function (it) { return it.kev; }).length;
    if (kev) { var li = el("li", "kev-note"); li.appendChild(el("span", null, "منها ثبت استغلالها")); li.appendChild(el("span", "num", nf.format(kev))); lg.appendChild(li); }
    $("sev-box").hidden = !vul.length;
    $("clear-wrap").hidden = !filtering();
    var n = (st.type ? 1 : 0) + (st.sev ? 1 : 0) + (st.newOnly ? 1 : 0);
    $("filters-on").textContent = n ? (n === 1 ? "تصفية واحدة فعّالة" : n === 2 ? "تصفيتان فعّالتان" : nf.format(n) + " تصفيات فعّالة") : "";
  }

  // ---------- الخلاصة
  function renderFeed() {
    var list = sorted(all.filter(function (it) { return match(it); }));
    var feed = $("feed"); feed.textContent = ""; feed.setAttribute("aria-busy", "false");
    $("result").textContent = filtering() ? ("النتائج: " + nf.format(list.length) + " من " + nf.format(all.length)) : "";
    if (!list.length) {
      var e = el("div", "empty");
      if (!all.length) {
        e.appendChild(el("b", null, "لا توجد عناصر في ملف البيانات بعد. "));
        e.appendChild(document.createTextNode("ستظهر هنا بعد أول دورة تحديث ناجحة للرادار."));
      } else if (st.newOnly && !(st.type || st.sev || st.q)) {
        e.appendChild(el("b", null, lastVisit ? "لا جديد منذ زيارتك الأخيرة. " : "لم يصل شيء في آخر " + R.count(FIRST_VISIT_H, "ساعة", "ساعتين", "ساعات", "ساعة") + ". "));
        e.appendChild(document.createTextNode("الرادار يتحدث كل ساعة، أو أطفئ «الجديد فقط» لترى كل ما رصدناه."));
      } else {
        e.appendChild(el("b", null, "لا توجد نتائج مطابقة. "));
        e.appendChild(document.createTextNode("جرّب كلمة أخرى، أو اضغط «إلغاء التصفية»."));
      }
      feed.appendChild(e);
    }
    renderNewSwitch();
    var lastDay = null, frag = document.createDocumentFragment();
    list.slice(0, st.shown).forEach(function (it) {
      if (st.sort === "new") { var d = R.dayLabel(it.t); if (d !== lastDay) { frag.appendChild(el("h3", "day", d)); lastDay = d; } }
      frag.appendChild(item(it));
    });
    feed.appendChild(frag);
    var more = $("more"), rest = list.length - st.shown;
    more.hidden = rest <= 0; more.textContent = "عرض المزيد (" + nf.format(rest) + " متبقية)";
    document.querySelectorAll(".sort button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.sort === st.sort)); });
  }

  // ---------- مفتاح «الجديد فقط»
  function renderNewSwitch() {
    var n = all.filter(function (it) { return isNew(it) && match(it, "new"); }).length;
    var b = $("newonly");
    b.setAttribute("aria-checked", String(st.newOnly));
    $("newonly-count").textContent = "(" + nf.format(n) + ")";
    b.title = lastVisit
      ? "ما وصل منذ زيارتك السابقة الساعة " + R.timeF.format(lastVisit) + " (" + R.dayLabel(lastVisit) + ")"
      : "أول زيارة لك: نعرض ما وصل في آخر " + R.count(FIRST_VISIT_H, "ساعة", "ساعتين", "ساعات", "ساعة");
    b.disabled = !st.newOnly && n === 0;
  }

  function update(keepShown) { if (!keepShown) st.shown = PAGE; renderSide(); renderFeed(); writeHash(); }

  // ---------- الانتقال إلى عنصر (من الرادار أو قائمة «الآن»)
  function focusItem(id) {
    var it = byId[id]; if (!it) return;
    if (!match(it)) { st.type = ""; st.sev = ""; st.q = ""; st.newOnly = false; $("q").value = ""; }
    var idx = sorted(all.filter(function (x) { return match(x); })).indexOf(it);
    if (idx >= st.shown) st.shown = Math.ceil((idx + 1) / PAGE) * PAGE;
    update(true);
    var node = $("i-" + id); if (!node) return;
    scrollTo(node, "center");
    node.classList.remove("flash"); void node.offsetWidth; node.classList.add("flash");
    var a = node.querySelector("h3 a"); if (a) a.focus({ preventScroll: true });
  }

  // ---------- قائمة «ما يحتاج انتباهك الآن»
  function renderNow() {
    var c = all.filter(R.isCrit).sort(function (a, b) { return rank(b) - rank(a) || b.t - a.t; });
    // الخطورة (درجة CVSS) وثبوت الاستغلال (قائمة CISA) أمران مستقلان، فنعدّ كلاً منهما وحده
    var crit = c.filter(function (it) { return it.severity === "critical"; }).length;
    var kev = c.filter(function (it) { return it.kev; }).length;
    var lede = $("lede"); lede.textContent = "";
    if (c.length) {
      if (crit) lede.appendChild(el("strong", null, R.count(crit, "ثغرة حرجة واحدة", "ثغرتان حرجتان", "ثغرات حرجة", "ثغرة حرجة")));
      if (crit && kev) lede.appendChild(document.createTextNode(" حسب درجتها، و"));
      if (kev) lede.appendChild(el("strong", null, R.count(kev, "ثغرة واحدة", "ثغرتان", "ثغرات", "ثغرة") + " ثبت أن المهاجمين استغلوها"));
      lede.appendChild(document.createTextNode((kev ? " بحسب وكالة CISA" : " حسب درجتها") + ". ابدأ بهذه."));
    } else lede.textContent = "لا توجد ثغرات حرجة أو مستغلة في بيانات الرادار الآن. آخر الأخبار في الأسفل.";
    var ol = $("now"); ol.textContent = ""; topIds = {};
    if (!c.length) { ol.appendChild(el("li", "now-empty", "لا شيء عاجل الآن.")); }
    c.slice(0, 4).forEach(function (it) {
      topIds[it.id] = true;
      var li = el("li"), a = el("a", "now-item"); a.href = "#i-" + it.id;
      a.href = "#v=" + encodeURIComponent(it.id);
      a.onclick = function (e) { e.preventDefault(); R.openDetail(it); };
      var sc = el("span", "score" + (it.kev ? " kev" : ""), it.score != null ? Number(it.score).toFixed(1) : "؟");
      sc.appendChild(el("small", null, it.kev ? "مستغلة" : "CVSS"));
      a.appendChild(sc);
      var cv = R.splitCve(it);
      var tx = el("span"); var t = el("span", "now-title", cv.rest || it.title); t.setAttribute("dir", "auto"); tx.appendChild(t);
      var meta = el("span", "now-meta");
      if (cv.id) { meta.appendChild(el("bdi", null, cv.id)); meta.appendChild(document.createTextNode("، ")); }
      if (it.system) { meta.appendChild(el("bdi", null, it.system)); meta.appendChild(document.createTextNode("، ")); }
      meta.appendChild(document.createTextNode(R.ago(it.t)));
      tx.appendChild(meta);
      a.appendChild(tx); li.appendChild(a); ol.appendChild(li);
    });
    var more = $("now-more");
    more.hidden = c.length <= 4;
    if (c.length > 4) more.textContent = "افتح مركز التنبيهات";
  }

  // ---------- شاشة الرادار
  function radarGrid() {
    var g = $("grid"); g.textContent = "";
    g.appendChild(svg("circle", { r: 108, "class": "bezel" }));
    // علامات الإطار كل 10 درجات، وأطول كل 30
    for (var d = 0; d < 360; d += 10) {
      var a = d * Math.PI / 180, r1 = d % 30 ? 104 : 101;
      g.appendChild(svg("line", { x1: (r1 * Math.sin(a)).toFixed(2), y1: (-r1 * Math.cos(a)).toFixed(2), x2: (107 * Math.sin(a)).toFixed(2), y2: (-107 * Math.cos(a)).toFixed(2), "class": "tick" }));
    }
    [[3, "3 س"], [6, "6 س"], [12, "12 س"], [24, "24 س"]].forEach(function (r) {
      var rr = 100 * Math.sqrt(r[0] / WINDOW_H);
      g.appendChild(svg("circle", { r: rr, "class": "ring" + (r[0] === 24 ? " outer" : "") }));
      var t = svg("text", { x: 2, y: (-rr - 1.5).toFixed(1), "class": "ring-label" }); t.textContent = r[1]; g.appendChild(t);
    });
    g.appendChild(svg("line", { x1: -100, y1: 0, x2: 100, y2: 0, "class": "axis" }));
    g.appendChild(svg("line", { x1: 0, y1: -100, x2: 0, y2: 100, "class": "axis" }));
  }
  function renderRadar() {
    var bl = $("blips"); bl.textContent = "";
    var ld = $("radar-load"); if (ld) ld.remove();
    var pts = all.filter(function (it) { var a = ageH(it); return a >= -0.5 && a <= WINDOW_H; });
    pts.sort(function (a, b) { return rank(a) - rank(b); });   // الأخطر يُرسم أخيراً فيظهر فوق غيره
    var tip = $("tip"), box = $("radar");
    // نربط توهج كل نقطة بلحظة مرور الشعاع عليها: نقرأ موضع دوران الشعاع الحالي ونؤخر حركة كل نقطة حسب زاويتها
    var sw = document.querySelector(".radar .sweep"), now = 0;
    try { var an = sw.getAnimations && sw.getAnimations()[0]; if (an && an.currentTime != null) now = an.currentTime % SWEEP_MS; } catch (e) {}
    pts.forEach(function (it) {
      // عناصر الدورة الواحدة تصل بالوقت نفسه فتتراص على قوس واحد، لذا نزيح كل نقطة قليلاً (ثابتاً لكل عنصر) عن نصف قطرها
      var sv = sevOf(it), ang = hash(it.id) * Math.PI * 2;
      var r = 100 * Math.sqrt(Math.min(Math.max(ageH(it), 0.05), WINDOW_H) / WINDOW_H) + (hash(it.id + "#r") - 0.5) * 9;
      r = Math.min(Math.max(r, 7), 100);
      var x = r * Math.sin(ang), y = -r * Math.cos(ang);
      var col = sv ? R.RADAR_SEV[sv] : "#D7AE6E";
      var size = !sv ? 1.7 : sv === "critical" ? 3.6 : sv === "high" ? 2.7 : 2.1;
      var grp = svg("g", { "class": "blip", transform: "translate(" + x.toFixed(2) + " " + y.toFixed(2) + ")" });
      if (topIds[it.id]) grp.appendChild(svg("circle", { r: size, fill: col, "class": "pulse" }));   // النبض فقط لما في قائمة «الآن»
      var core = svg("circle", { r: size, fill: col, "class": "core" + (sv === "critical" ? "" : " fade") });
      if (sv !== "critical") {
        var phase = ang / (Math.PI * 2) * SWEEP_MS;
        core.style.animationDelay = (((phase - now) % SWEEP_MS + SWEEP_MS) % SWEEP_MS - SWEEP_MS) + "ms";
      }
      grp.appendChild(core);
      if (it.kev) grp.appendChild(svg("circle", { r: size + 2, stroke: col, "class": "kev-ring" }));
      grp.appendChild(svg("circle", { r: Math.max(size + 3, 6), fill: "transparent" }));   // مساحة لمس أكبر للجوال
      function show() {
        tip.textContent = "";
        var b = el("b", null, it.title); b.setAttribute("dir", "auto"); tip.appendChild(b);
        tip.appendChild(document.createTextNode((sv ? SEV[sv] + (it.score != null ? " " + Number(it.score).toFixed(1) : "") : TYPES[it.type]) + (it.kev ? "، ثبت استغلالها" : "") + "، " + R.ago(it.t)));
        var bb = box.getBoundingClientRect(), pb = grp.getBoundingClientRect();
        var cx = pb.left - bb.left + pb.width / 2, cy = pb.top - bb.top;
        tip.style.left = Math.min(Math.max(cx - 130, 0), Math.max(bb.width - 260, 0)) + "px";
        tip.classList.add("show"); grp.classList.add("on");
        tip.style.top = Math.max(cy - tip.offsetHeight - 10, 0) + "px";
      }
      function hide() { tip.classList.remove("show"); grp.classList.remove("on"); }
      grp.addEventListener("mouseenter", show); grp.addEventListener("mouseleave", hide);
      grp.addEventListener("click", function () { hide(); if (it.type === "vul") R.openDetail(it); else focusItem(it.id); });
      bl.appendChild(grp);
    });
    var crit = pts.filter(function (it) { return sevOf(it) === "critical"; }).length;
    $("radar-count").textContent = nf.format(pts.length) + " عنصراً في آخر 24 ساعة" + (crit ? "، منها " + nf.format(crit) + " حرجة" : "");
    $("radar-cap").textContent = "خريطة رادار فيها " + nf.format(pts.length) + " عنصراً من آخر 24 ساعة، الأحدث في المركز. القائمة المجاورة تعرض الأخطر منها.";
  }

  // ---------- الأحداث
  var deb;
  $("q").addEventListener("input", function (e) { clearTimeout(deb); deb = setTimeout(function () { st.q = e.target.value.trim().slice(0, 80); update(); }, 160); });
  $("q").addEventListener("keydown", function (e) { if (e.key === "Escape" && this.value) { this.value = ""; st.q = ""; update(); } });
  $("clear").onclick = function () { st.type = ""; st.sev = ""; st.q = ""; st.newOnly = false; $("q").value = ""; update(); };
  $("newonly").onclick = function () { st.newOnly = !st.newOnly; update(); };
  $("more").onclick = function () { st.shown += PAGE; update(true); };
  document.querySelectorAll(".sort button").forEach(function (b) { b.onclick = function () { st.sort = b.dataset.sort; update(); }; });
  var ft = $("filters-toggle"), fp = $("filter-panel");
  ft.onclick = function () { var open = ft.getAttribute("aria-expanded") !== "true"; ft.setAttribute("aria-expanded", String(open)); fp.classList.toggle("closed", !open); };
  window.addEventListener("hashchange", function () {
    if (!all.length || location.hash.indexOf("#i-") === 0) return;
    if (!R.openFromHash(byId)) R.closeDetail();
    readHash(); update();
  });

  // ---------- التحميل
  radarGrid();
  function start() {
    $("feed").setAttribute("aria-busy", "true");
    R.load().then(function (d) {
      genAt = d.genAt; all = d.items; byId = {};
      all.forEach(function (it) { byId[it.id] = it; });
      // «آخر زيارة» تُثبَّت طوال الجلسة: إعادة تحميل الصفحة لا تمسح علامات «جديد»
      var base = null;
      try { base = sessionStorage.getItem("radar-visit-base"); } catch (e) {}
      if (base === null) {
        base = R.store("radar-last-visit") || "0";
        try { sessionStorage.setItem("radar-visit-base", base); } catch (e) {}
      }
      lastVisit = Number(base) > 0 ? Number(base) : null;
      R.store("radar-last-visit", String(Date.now()));
      readHash(); renderNow(); renderRadar(); update(true);
      // إذا فُتحت الصفحة برابط عنصر (#i-...) ننتقل إليه
      if (location.hash.indexOf("#i-") === 0) focusItem(decodeURIComponent(location.hash.slice(3)));
      else R.openFromHash(byId);   // رابط مشارَك لثغرة (#v=CVE-...)
    }).catch(function (err) {
      $("now").textContent = ""; $("lede").textContent = "تعذّر تحميل آخر البيانات.";
      var ld = $("radar-load"); if (ld) ld.textContent = "لا توجد بيانات";
      R.errorNotice($("feed"), err, function () { location.reload(); });
    });
  }
  start();
})();
