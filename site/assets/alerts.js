/* رادار التقنية: مركز التنبيهات */
(function () {
  "use strict";
  var R = window.Radar, $ = R.$, el = R.el, nf = R.nf, L = R.L;
  var PAGE = 50;
  // كل تبويب قاعدة مستقلة: الاستغلال من CISA، والحرجة والعالية من درجة CVSS وحدها
  var TABS = [
    { k: "all", label: L("كل التنبيهات", "All alerts"), c: "var(--brass)", test: function (it) { return it.kev || it.severity === "critical" || it.severity === "high"; },
      explain: L("كل ثغرة ثبت استغلالها، أو درجتها 7 فأكثر.", "Every known-exploited vulnerability, or any scored 7 or higher.") },
    { k: "kev", label: L("ثبت استغلالها", "Known exploited"), c: "var(--s-critical)", test: function (it) { return it.kev; },
      explain: L("أدرجتها وكالة CISA الأمريكية في قائمة الثغرات التي ثبت أن المهاجمين استغلوها فعلاً. أياً كانت درجتها، هذه أولوية التحديث الأولى.", "Listed by the US agency CISA as vulnerabilities attackers have actually exploited. Whatever their score, these are the first to patch.") },
    { k: "critical", label: L("حرجة (CVSS 9 فأكثر)", "Critical (CVSS 9+)"), c: "var(--s-critical)", test: function (it) { return it.severity === "critical"; },
      explain: L("درجتها في NVD من 9 إلى 10. لا يعني هذا أنها مستغلة، راجع عمود «الاستغلال».", "Scored 9 to 10 by NVD. That does not mean it is exploited; check the Exploitation column.") },
    { k: "high", label: L("عالية (CVSS 7 إلى 8.9)", "High (CVSS 7 to 8.9)"), c: "var(--s-high)", test: function (it) { return it.severity === "high"; },
      explain: L("أولوية عالية: درجتها في NVD من 7 إلى 8.9.", "High priority: scored 7 to 8.9 by NVD.") }
  ];
  var all = [], byId = {}, st = { tab: "all", sort: "new", shown: PAGE };

  function readHash() {
    var p = R.hashParams();
    st.tab = TABS.some(function (t) { return t.k === p.get("tab"); }) ? p.get("tab") : "all";
    st.sort = p.get("sort") === "imp" ? "imp" : "new";
  }
  function writeHash() {
    var p = new URLSearchParams();
    if (st.tab !== "all") p.set("tab", st.tab);
    if (st.sort !== "new") p.set("sort", st.sort);
    var v = R.hashParams().get("v"); if (v) p.set("v", v);
    R.setHash(p);
  }
  function tabOf(k) { return TABS.filter(function (t) { return t.k === k; })[0]; }

  function renderTabs() {
    var box = $("tabs"); box.textContent = "";
    TABS.forEach(function (t) {
      var n = all.filter(t.test).length;
      var b = el("button", "a-tab"); b.type = "button"; b.style.setProperty("--c", t.c);
      b.setAttribute("aria-pressed", String(st.tab === t.k));
      b.appendChild(el("b", null, nf.format(n))); b.appendChild(el("span", null, t.label));
      b.onclick = function () { st.tab = t.k; update(); };
      box.appendChild(b);
    });
    $("explain").textContent = tabOf(st.tab).explain;
  }

  function row(it) {
    var sv = R.sevOf(it), cv = R.splitCve(it), tr = el("tr", "row");
    tr.style.setProperty("--c", "var(--s-" + sv + ")");
    tr.onclick = function (e) { if (e.target.closest("a")) return; R.openDetail(it); };
    var td = el("td", "c-id"), a = el("a", null, null);
    a.appendChild(el("bdi", null, cv.id || it.id)); a.href = "#v=" + encodeURIComponent(it.id);
    a.onclick = function (e) { e.preventDefault(); R.openDetail(it); };
    td.appendChild(a);
    var p = el("p", null, !R.en && it.summary && it.sumSrc === "llm" ? it.summary : (cv.rest || "")); p.setAttribute("dir", "auto"); td.appendChild(p);
    tr.appendChild(td);
    function cell(cls, label, content) {
      var c = el("td", cls); c.dataset.label = label;
      if (typeof content === "string") c.textContent = content; else c.appendChild(content);
      tr.appendChild(c); return c;
    }
    cell("c-sys", L("المنتج", "Product"), el("bdi", it.system && it.system !== R.UNSPEC ? null : "muted", R.sysName(it.system)));
    cell("c-score", "CVSS", it.score != null ? Number(it.score).toFixed(1) : "—");
    cell("c-sev", L("الخطورة", "Severity"), el("span", "pill", R.SEV[sv])).firstChild.style.setProperty("--c", "var(--s-" + sv + ")");
    cell("c-kev", L("الاستغلال", "Exploitation"), it.kev ? el("span", "pill kev", L("ثبت استغلالها", "Known exploited")) : el("span", "muted", L("لا دليل منشور", "No published evidence")));
    cell("c-src", L("المصدر", "Source"), el("bdi", null, R.srcName(it.source)));
    var d = el("time", null, R.fmtDate(it.date) || "—"); if (it.t) d.dateTime = new Date(it.t).toISOString();
    // لعناصر قائمة CISA التاريخ هو تاريخ إدراجها في القائمة
    d.title = R.dateLabel(it);
    cell("c-date", R.dateLabel(it), d);
    return tr;
  }

  function renderRows() {
    var t = tabOf(st.tab);
    var list = all.filter(t.test).sort(st.sort === "imp"
      ? function (a, b) { return R.rank(b) - R.rank(a) || b.t - a.t; }
      : function (a, b) { return b.t - a.t; });
    var body = $("rows"), state = $("state"); body.textContent = ""; state.textContent = "";
    $("cap").textContent = R.en ? t.label + ", " + list.length + " vulnerabilities, sorted by " + (st.sort === "imp" ? "severity" : "date")
      : t.label + "، " + nf.format(list.length) + " ثغرة، مرتبة حسب " + (st.sort === "imp" ? "الخطورة" : "التاريخ");
    if (!list.length) {
      var e = el("div", "empty"); e.appendChild(el("b", null, L("لا توجد ثغرات في هذا التصنيف الآن. ", "No vulnerabilities in this category right now. ")));
      e.appendChild(document.createTextNode(L("الرادار يتحدث كل ساعة.", "The radar updates hourly.")));
      state.appendChild(e);
    }
    var frag = document.createDocumentFragment();
    list.slice(0, st.shown).forEach(function (it) { frag.appendChild(row(it)); });
    body.appendChild(frag);
    if (list.length > st.shown) {
      var m = el("button", "btn a-more", L("عرض المزيد (", "Show more (") + nf.format(list.length - st.shown) + L(" متبقية)", " left)")); m.type = "button";
      m.onclick = function () { st.shown += PAGE; renderRows(); };
      state.appendChild(m);
    }
    document.querySelectorAll(".sort button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.sort === st.sort)); });
  }

  function update() { st.shown = PAGE; renderTabs(); renderRows(); writeHash(); }

  // ---------- سجل الرسائل المرسلة (من events.json)
  function renderSent() {
    var box = $("sent");
    fetch("events.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); }).then(function (d) {
      var evs = (d && Array.isArray(d.events) ? d.events : []).filter(function (e) { return e && e.kind === "alert" && typeof e.ts === "string"; });
      // الرسالة الواحدة قد تذكر عدة ثغرات (رسالة الملخص)، فنجمع الأحداث المتقاربة في الوقت نفسه
      var groups = [];
      evs.forEach(function (e) {
        var t = Date.parse(e.ts); if (!t) return;
        var g = groups[groups.length - 1];
        if (g && Math.abs(g.t - t) < 5 * 6e4) g.ids.push(e.id); else groups.push({ t: t, ids: [e.id] });
      });
      box.textContent = "";
      if (!groups.length) {
        var since = Date.parse(d && d.logged_since);
        box.appendChild(el("li", "empty", L("لم يُرسل أي تنبيه", "No alert has been sent") + (since ? L(" منذ بدأنا تسجيل التنبيهات في ", " since we started logging alerts on ") + R.dateF.format(since) : "") + "."));
        return;
      }
      groups.slice(0, 15).forEach(function (g) {
        var li = el("li"), tm = el("time", null, R.at(g.t)); tm.dateTime = new Date(g.t).toISOString();
        li.appendChild(tm);
        var ids = el("div", "ids");
        g.ids.slice(0, 12).forEach(function (id) {
          var it = byId[id], a = el("a", null, null); a.appendChild(el("bdi", null, id));
          if (it) { a.href = "#v=" + encodeURIComponent(id); a.onclick = function (e) { e.preventDefault(); R.openDetail(it); }; }
          else R.link(a, "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(id));
          ids.appendChild(a);
        });
        if (g.ids.length > 12) ids.appendChild(el("span", "muted", L("و", "and ") + nf.format(g.ids.length - 12) + L(" أخرى", " more")));
        li.appendChild(ids); box.appendChild(li);
      });
    }).catch(function () {
      box.textContent = ""; box.appendChild(el("li", "empty", L("تعذّر تحميل سجل الرسائل.", "Could not load the message log.")));
    });
  }

  document.querySelectorAll(".sort button").forEach(function (b) { b.onclick = function () { st.sort = b.dataset.sort; update(); }; });
  var genAt = null;
  $("export").onclick = function () {
    var t = tabOf(st.tab), list = all.filter(t.test).sort(st.sort === "imp"
      ? function (a, b) { return R.rank(b) - R.rank(a) || b.t - a.t; } : function (a, b) { return b.t - a.t; });
    R.printReport(list, { genAt: genAt, title: L("تقرير التنبيهات الأمنية", "Security alerts report"),
      scope: t.label + R.comma + (st.sort === "imp" ? L("مرتبة حسب الخطورة", "sorted by severity") : L("الأحدث أولاً", "newest first")) });
  };
  window.addEventListener("hashchange", function () { if (!all.length) return; if (!R.openFromHash(byId)) R.closeDetail(); readHash(); update(); });

  R.load().then(function (d) {
    genAt = d.genAt;
    all = d.items.filter(function (it) { return it.type === "vul"; });
    all.forEach(function (it) { byId[it.id] = it; });
    readHash(); update(); R.openFromHash(byId); renderSent();
  }).catch(function (err) {
    $("rows").textContent = ""; $("tabs").textContent = "";
    R.errorNotice($("state"), err, function () { location.reload(); });
    $("sent").textContent = "";
  });
})();
