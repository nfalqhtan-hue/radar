/* Tech Radar: security updates page (pillar 3). Data: items of type "upd" in data.json, built by the pipeline from
   official vendor feeds. Nothing here is inferred: empty version fields stay empty and say "see the bulletin". */
(function () {
  "use strict";
  var R = window.Radar, $ = R.$, el = R.el, nf = R.nf, L = R.L;
  var PAGE = 40;
  var TABS = [
    { k: "all", label: L("كل التحديثات", "All updates"), c: "var(--brass)", test: function () { return true; },
      explain: L("كل ما نشرته المصادر الرسمية في آخر 30 يوماً، الأحدث أولاً.", "Everything the official sources published in the last 30 days, newest first.") },
    { k: "action", label: L("تحتاج تصرفاً الآن", "Act now"), c: "var(--s-critical)", test: function (u) { return u.action; },
      explain: L("تحديثات تصلح ثغرة أدرجتها CISA في قائمة الثغرات المستغلة، أو ذكرت الشركة نفسها أنها مستغلة. طبّقها أولاً.",
        "Updates that fix a vulnerability CISA lists as exploited, or that the vendor itself says is exploited. Apply these first.") },
    { k: "patch", label: R.UTYPE.patch, c: "var(--s-high)", test: function (u) { return u.utype === "patch"; },
      explain: L("إصدارات تصلح ثغرات أمنية: حدّث المنتج إلى الإصدار المذكور.", "Releases that fix security vulnerabilities: update the product to the stated version.") },
    { k: "advisory", label: R.UTYPE.advisory, c: "var(--s-medium)", test: function (u) { return u.utype === "advisory"; },
      explain: L("بيانات من الشركة عن منتجات متأثرة بثغرات، وقد تتضمن إصلاحاً أو حلاً مؤقتاً. افتح النشرة لمعرفة ما يخص إصدارك.",
        "Vendor bulletins about affected products; they may include a fix or a workaround. Open the bulletin to see what applies to your version.") },
    { k: "release", label: R.UTYPE.release, c: "var(--s-unknown)", test: function (u) { return u.utype === "release"; },
      explain: L("تحديثات برمجية لا تذكر الشركة فيها إصلاحات أمنية.", "Software updates in which the vendor lists no security fixes.") }
  ];
  var all = [], vulnIds = {}, st = { tab: "all", vendor: "", shown: PAGE };

  function readHash() {
    var p = R.hashParams();
    st.tab = TABS.some(function (t) { return t.k === p.get("tab"); }) ? p.get("tab") : "all";
    st.vendor = (p.get("vendor") || "").slice(0, 60);
  }
  function writeHash() {
    var p = new URLSearchParams();
    if (st.tab !== "all") p.set("tab", st.tab);
    if (st.vendor) p.set("vendor", st.vendor);
    R.setHash(p);
  }
  function tabOf(k) { return TABS.filter(function (t) { return t.k === k; })[0]; }
  function byVendor(u) { return !st.vendor || u.system === st.vendor; }

  function renderTabs() {
    var box = $("tabs"); box.textContent = "";
    TABS.forEach(function (t) {
      var n = all.filter(function (u) { return byVendor(u) && t.test(u); }).length;
      var b = el("button", "a-tab"); b.type = "button"; b.style.setProperty("--c", t.c);
      b.setAttribute("aria-pressed", String(st.tab === t.k));
      b.appendChild(el("b", null, nf.format(n))); b.appendChild(el("span", null, t.label));
      b.onclick = function () { st.tab = t.k; update(); };
      box.appendChild(b);
    });
    $("explain").textContent = tabOf(st.tab).explain;
  }
  function renderVendors() {
    var box = $("vendors"); box.textContent = "";
    var t = tabOf(st.tab), cnt = {};
    all.filter(t.test).forEach(function (u) { cnt[u.system] = (cnt[u.system] || 0) + 1; });
    function chip(on, label, n, fn) {
      var b = el("button", "filter"); b.type = "button"; b.setAttribute("aria-pressed", String(on));
      b.appendChild(el("bdi", null, label)); b.appendChild(el("span", "n", nf.format(n))); b.onclick = fn; box.appendChild(b);
    }
    chip(!st.vendor, L("كل الشركات", "All vendors"), all.filter(t.test).length, function () { st.vendor = ""; update(); });
    Object.keys(cnt).sort(function (a, b) { return cnt[b] - cnt[a] || a.localeCompare(b); }).forEach(function (v) {
      chip(st.vendor === v, v, cnt[v], function () { st.vendor = st.vendor === v ? "" : v; update(); });
    });
    if (st.vendor && !cnt[st.vendor]) chip(true, st.vendor, 0, function () { st.vendor = ""; update(); });
  }

  function row(u) {
    var tr = el("tr", "row u-row"), url = R.safeUrl(u.link);
    tr.style.setProperty("--c", u.action ? "var(--s-critical)" : u.utype === "patch" ? "var(--s-high)" : u.utype === "advisory" ? "var(--s-medium)" : "var(--s-unknown)");
    function cell(cls, label, content) {
      var c = el("td", cls); c.dataset.label = label;
      if (typeof content === "string") c.textContent = content; else if (content) c.appendChild(content);
      tr.appendChild(c); return c;
    }
    var main = el("div");
    var top = el("div", "u-top");
    top.appendChild(el("bdi", "u-vendor", u.system));
    if (u.product && u.product.toLowerCase() !== String(u.system).toLowerCase()) top.appendChild(el("bdi", "u-prod", u.product));
    main.appendChild(top);
    var a = el("a", null, u.title); a.setAttribute("dir", "auto");
    if (url) R.link(a, url); main.appendChild(a);
    if (u.action) {
      var why = el("p", "u-act");
      why.textContent = u.kev && u.vendorExploited ? L("تصلح ثغرة مستغلة فعلياً (CISA، والشركة تؤكد)", "Fixes an exploited vulnerability (CISA, confirmed by the vendor)")
        : u.kev ? L("تصلح ثغرة مدرجة في قائمة CISA للثغرات المستغلة", "Fixes a vulnerability in CISA's exploited list")
        : L("الشركة تذكر أن ثغرة واحدة على الأقل مستغلة فعلياً", "The vendor says at least one vulnerability is exploited");
      main.appendChild(why);
    }
    cell("c-id u-main", L("التحديث", "Update"), main);
    var tp = el("span", "pill", R.UTYPE[u.utype]); tp.style.setProperty("--c", "inherit");
    cell("c-type", L("النوع", "Type"), tp);
    var fx = el("bdi", u.fixed ? "u-ver" : "muted", u.fixed || L("راجع النشرة", "See the bulletin")); fx.setAttribute("dir", "ltr");
    cell("c-fixed", L("الإصدار المصحح", "Fixed version"), fx);
    var af = el("bdi", u.affected ? "u-ver" : "muted", u.affected || L("راجع النشرة", "See the bulletin")); af.setAttribute("dir", "ltr"); if (u.affected) af.title = u.affected;
    cell("c-aff", L("المتأثر", "Affected"), af);
    var cv = el("div", "u-cves");
    if (!u.cveN) cv.appendChild(el("span", "muted", "—"));
    u.cves.slice(0, 3).forEach(function (id) {
      var l = el("a", null, null); l.appendChild(el("bdi", null, id));
      if (vulnIds[id]) l.href = "./#v=" + encodeURIComponent(id); else R.link(l, "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(id));
      cv.appendChild(l);
    });
    if (u.cveN > 3) cv.appendChild(el("span", "muted", L("و", "+") + nf.format(u.cveN - 3) + L(" أخرى", " more")));
    cell("c-cves", L("الثغرات", "Vulnerabilities"), cv);
    var d = el("time", null, R.fmtDate(u.date) || "—"); if (u.t) d.dateTime = new Date(u.t).toISOString();
    var dc = cell("c-date", L("التاريخ", "Date"), d);
    dc.appendChild(el("small", "u-src", R.srcName(u.source)));
    tr.onclick = function (e) { if (e.target.closest("a") || !url) return; window.open(url, "_blank", "noopener"); };
    return tr;
  }

  function renderRows() {
    var t = tabOf(st.tab);
    var list = all.filter(function (u) { return byVendor(u) && t.test(u); }).sort(function (a, b) { return b.t - a.t; });
    var body = $("rows"), state = $("state"); body.textContent = ""; state.textContent = "";
    $("cap").textContent = t.label + R.comma + nf.format(list.length);
    if (!list.length) {
      var e = el("div", "empty");
      e.appendChild(el("b", null, all.length ? L("لا توجد تحديثات بهذا التصنيف الآن. ", "No updates in this category right now. ")
        : L("لم تصل تحديثات بعد. ", "No updates yet. ")));
      e.appendChild(document.createTextNode(L("الرادار يجلبها من المصادر الرسمية كل ساعة.", "The radar fetches them from the official sources every hour.")));
      state.appendChild(e);
    }
    var frag = document.createDocumentFragment();
    list.slice(0, st.shown).forEach(function (u) { frag.appendChild(row(u)); });
    body.appendChild(frag);
    if (list.length > st.shown) {
      var m = el("button", "btn a-more", L("عرض المزيد (", "Show more (") + nf.format(list.length - st.shown) + L(" متبقية)", " left)")); m.type = "button";
      m.onclick = function () { st.shown += PAGE; renderRows(); };
      state.appendChild(m);
    }
  }
  function update() { st.shown = PAGE; renderTabs(); renderVendors(); renderRows(); writeHash(); }

  // Source health from events.json: a failed vendor feed is disclosed, not hidden
  function renderSources() {
    fetch("events.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); }).then(function (d) {
      var s = d && d.sources && d.sources.upd; if (!s) return;
      var ok = Date.parse(s.last_ok), bad = Date.parse(s.last_fail);
      $("src-note").textContent = L("المصادر: Chrome Releases، وUbuntu، وDebian، وCisco، وFortinet، وOracle. ", "Sources: Chrome Releases, Ubuntu, Debian, Cisco, Fortinet and Oracle. ")
        + (ok ? L("آخر جلب ناجح ", "Last successful fetch ") + R.ago(ok) + ". " : "")
        + (bad && (!ok || bad > ok) ? L("آخر محاولة فشلت: ", "The last attempt failed: ") + (s.error || "") : "");
    }).catch(function () {});
  }

  window.addEventListener("hashchange", function () { if (!all.length) return; readHash(); update(); });
  R.load().then(function (d) {
    all = d.items.filter(function (it) { return it.type === "upd"; });
    d.items.forEach(function (it) { if (it.type === "vul") vulnIds[it.id] = 1; });
    readHash(); update(); renderSources();
  }).catch(function (err) {
    $("rows").textContent = ""; $("tabs").textContent = "";
    R.errorNotice($("state"), err, function () { location.reload(); });
  });
})();
