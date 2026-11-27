/* رادار التقنية: الصفحة الرئيسية (الرادار، «ما يحتاج انتباهك الآن»، الخلاصة والبحث والتصفية) */
(function () {
  "use strict";
  var R = window.Radar, $ = R.$, el = R.el, svg = R.svg, nf = R.nf, L = R.L;
  var TYPES = R.TYPES, SEV = R.SEV, SEV_ORDER = R.SEV_ORDER, sevOf = R.sevOf, rank = R.rank;
  var PAGE = 40, WINDOW_H = 24, SWEEP_MS = 7000;
  // فلتر التاريخ: حسب تاريخ النشر (ولعناصر قائمة CISA تاريخ إدراجها)
  var RANGES = [["", L("الكل", "Any time"), 0], ["24h", L("آخر 24 ساعة", "Last 24 hours"), 24], ["7d", L("آخر 7 أيام", "Last 7 days"), 168], ["30d", L("آخر 30 يوماً", "Last 30 days"), 720]];
  var SORTS = { "new": 1, old: 1, imp: 1, risk: 1 };

  var all = [], byId = {}, det = null, genAt = null, lastVisit = null, topIds = {};
  var st = { type: "", sev: "", risk: "", q: "", since: "", sort: "new", newOnly: false, shown: PAGE };
  var FIRST_VISIT_H = 6;   // في أول زيارة لا يوجد «منذ آخر زيارة»، فيُعد جديداً ما وصل في آخر 6 ساعات
  function baseline() { return lastVisit || (genAt - FIRST_VISIT_H * 36e5); }
  function isNew(it) { return it.t > baseline(); }
  function ageH(it) { return (genAt - it.t) / 36e5; }
  // النص المعروض تحت العنوان: بالعربية الملخص (والقالبي يكرر الشارة والنظام فلا نعرضه)، وبالإنجليزية نص المصدر الأصلي
  function bodyText(it) { return parts(it).body; }
  // بالإنجليزية: عنوان ثغرات NVD هو أول 90 حرفاً من الوصف، فنجعل الجملة الأولى عنواناً والباقي نصاً بدل تكرار البداية مرتين
  function parts(it) {
    var cv = R.splitCve(it), title = cv.rest || it.title;
    if (!R.en) return { title: title, body: it.summary && !/^ثغرة أمنية خطورتها/.test(it.summary) ? it.summary : "" };
    var x = det && det[it.id], t = x && x.text ? x.text.trim() : "";
    var lead = (cv.raw || "").replace(/\s+$/, "");
    if (t && lead && t.indexOf(lead) === 0) {
      var i = t.indexOf(". ", Math.min(lead.length, 40));
      if (i > 0 && i < 260) { title = t.slice(0, i + 1); t = t.slice(i + 2); } else { title = t.length > 200 ? t.slice(0, 190).replace(/\s+\S*$/, "") + "…" : t; t = ""; }
    }
    if (t.length > 320) t = t.slice(0, 300).replace(/\s+\S*$/, "") + "…";
    return { title: title, body: t };
  }
  function hash(s) { var h = 2166136261; for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967296; }
  function scrollTo(node, block) { node.scrollIntoView({ behavior: R.reduced ? "auto" : "smooth", block: block || "start" }); }
  function filtering() { return !!(st.type || st.sev || st.risk || st.q || st.since || st.newOnly); }

  // ---------- الحالة في الرابط (لمشاركة نتيجة بحث أو تصفية)
  function readHash() {
    var p = R.hashParams();
    st.type = TYPES[p.get("type")] ? p.get("type") : "";
    st.sev = (SEV[p.get("sev")] || p.get("sev") === "kev") ? p.get("sev") : "";
    st.risk = R.RISK[p.get("r")] ? p.get("r") : "";
    st.q = (p.get("q") || "").replace(/[\u0000-\u001f<>]/g, "").slice(0, 80);
    st.since = RANGES.some(function (r) { return r[0] && r[0] === p.get("d"); }) ? p.get("d") : "";
    st.sort = SORTS[p.get("sort")] ? p.get("sort") : "new";
    st.newOnly = p.get("new") === "1";
    $("q").value = st.q;
  }
  function writeHash() {
    var p = new URLSearchParams();
    if (st.type) p.set("type", st.type);
    if (st.sev) p.set("sev", st.sev);
    if (st.risk) p.set("r", st.risk);
    if (st.q) p.set("q", st.q);
    if (st.since) p.set("d", st.since);
    if (st.sort !== "new") p.set("sort", st.sort);
    if (st.newOnly) p.set("new", "1");
    var v = R.hashParams().get("v"); if (v) p.set("v", v);   // نافذة تفاصيل مفتوحة تبقى في الرابط
    R.setHash(p);
  }

  // ---------- البحث: كل كلمة يجب أن تظهر (رقم CVE، اسم منتج، كلمة من العنوان أو الملخص أو الوصف الأصلي)
  function hay(it) {
    if (it._hay == null || (det && !it._hayDet)) {
      var x = det && det[it.id];
      it._hay = R.norm([it.id, it.title, it.summary, it.system, R.srcName(it.source), it.source, TYPES[it.type], x ? x.text : ""].join(" "));
      it._hayDet = !!det;
    }
    return it._hay;
  }
  function terms() { return R.norm(st.q).split(/\s+/).filter(Boolean); }

  // ---------- التصفية والترتيب
  function match(it, skip, tq) {
    if (skip !== "new" && st.newOnly && !isNew(it)) return false;
    if (skip !== "type" && st.type && it.type !== st.type) return false;
    if (skip !== "sev" && st.sev) {
      if (st.sev === "kev") { if (!it.kev) return false; }
      else if (sevOf(it) !== st.sev) return false;
    }
    if (skip !== "risk" && st.risk && it.riskLevel !== st.risk) return false;
    if (skip !== "date" && st.since) {
      var hrs = RANGES.filter(function (r) { return r[0] === st.since; })[0][2];
      if (ageH(it) > hrs) return false;
    }
    if (st.q) {
      var h = hay(it), ts = tq || terms();
      for (var i = 0; i < ts.length; i++) if (h.indexOf(ts[i]) === -1) return false;
    }
    return true;
  }
  function filtered(skip) { var tq = terms(); return all.filter(function (it) { return match(it, skip, tq); }); }
  function sorted(list) {
    return list.slice().sort(st.sort === "risk" ? function (a, b) { return R.riskRank(b) - R.riskRank(a) || rank(b) - rank(a) || b.t - a.t; }
      : st.sort === "imp" ? function (a, b) { return rank(b) - rank(a) || b.t - a.t; }
      : st.sort === "old" ? function (a, b) { return a.t - b.t; } : function (a, b) { return b.t - a.t; });
  }

  // ---------- عنصر في الخلاصة
  function item(it) {
    var sv = sevOf(it), cv = R.splitCve(it), pp = parts(it), text = pp.body;
    var art = el("article", "item" + (text ? "" : " compact"));
    art.id = "i-" + it.id; art.style.setProperty("--c", sv ? "var(--s-" + sv + ")" : "var(--s-news)");
    art.appendChild(el("div", "rail"));
    var body = el("div");
    var top = el("div", "item-top");
    top.appendChild(el("span", "tag", TYPES[it.type] || L("أخرى", "Other")));
    if (cv.id) top.appendChild(el("bdi", "cve", cv.id));
    if (sv) top.appendChild(el("span", "pill", SEV[sv] + (it.score != null ? " " + Number(it.score).toFixed(1) : "")));
    if (it.kev) top.appendChild(el("span", "pill kev", L("ثبت استغلالها", "Known exploited")));
    if (sv) top.appendChild(R.riskBadge(it));
    if (lastVisit && it.t > lastVisit) top.appendChild(el("span", "new", L("جديد منذ زيارتك", "New since your visit")));
    var tm = el("time", "time", R.timeF.format(it.t)); tm.dateTime = new Date(it.t).toISOString(); top.appendChild(tm);
    body.appendChild(top);

    var h = el("h3"); h.setAttribute("dir", "auto");
    var url = R.safeUrl(it.link), title = pp.title;
    if (it.type === "vul") {
      // عنوان الثغرة يفتح نافذة التفاصيل، ورابط المصدر يبقى في أسفل العنصر
      var da = el("a", null, title); da.href = "#v=" + encodeURIComponent(it.id);
      da.onclick = function (e) { e.preventDefault(); R.openDetail(it); };
      h.appendChild(da);
    } else if (url) h.appendChild(R.link(el("a", null, title), url)); else h.textContent = title;
    body.appendChild(h);
    if (text) {
      var p = el("p", "sum"); p.setAttribute("dir", "auto"); if (R.en) p.setAttribute("lang", "en");
      // مصدر النص ظاهر دائماً: ملخص آلي بالعربية، أو نص المصدر الأصلي بالإنجليزية
      if (!R.en && it.sumSrc === "llm") { var tg = el("span", "src-tag", "ملخص آلي"); tg.title = "كتبه نموذج لغوي (Qwen3) واجتاز فحص الجودة، وقد يخطئ"; p.appendChild(tg); }
      p.appendChild(document.createTextNode(text)); body.appendChild(p);
    } else if (it.sumSrc === "failed" && !R.en) {
      var nf2 = el("p", "sum-failed", "لا يوجد ملخص عربي موثوق لهذا العنصر، فاعتمد على المصدر."); nf2.title = "رفض فحص الجودة الملخص المقترح"; body.appendChild(nf2);
    }
    if (it.advice && R.isCrit(it)) {
      var ad = el("p", "advice"); ad.appendChild(el("b", null, L("ماذا تفعل: ", "What to do: "))); ad.appendChild(document.createTextNode(R.ADVICE)); body.appendChild(ad);
    }
    var foot = el("div", "item-foot");
    if (it.system) { var s = el("span"); s.appendChild(document.createTextNode(L("النظام المتأثر: ", "Affected: "))); s.appendChild(el("bdi", null, R.sysName(it.system))); foot.appendChild(s); }
    var src = el("span"); src.appendChild(document.createTextNode(L("المصدر: ", "Source: "))); src.appendChild(el("bdi", null, R.srcName(it.source))); foot.appendChild(src);
    if (url) foot.appendChild(R.link(el("a", null, it.type === "vul" ? L("التفاصيل في NVD", "Details in NVD") : L("اقرأ الخبر كاملاً", "Read the full story")), url));
    body.appendChild(foot);
    art.appendChild(body);
    return art;
  }

  // ---------- الشريط الجانبي (كل عدّاد يحترم بقية الفلاتر، فالأرقام تتطابق مع ما ستراه)
  function chip(box, on, label, n, onclick) {
    var b = el("button", "filter"); b.type = "button"; b.setAttribute("aria-pressed", String(on));
    b.appendChild(el("span", null, label)); if (n != null) b.appendChild(el("span", "n", nf.format(n)));
    b.onclick = onclick; box.appendChild(b);
  }
  function renderSide() {
    var box = $("types"); box.textContent = "";
    var base = filtered("type"), cnt = {};
    base.forEach(function (it) { cnt[it.type] = (cnt[it.type] || 0) + 1; });
    chip(box, !st.type, L("الكل", "All"), base.length, function () { st.type = ""; update(); });
    R.TYPE_ORDER.filter(function (t) { return cnt[t] || st.type === t; }).forEach(function (t) {
      chip(box, st.type === t, TYPES[t], cnt[t] || 0, function () { st.type = t; if (t !== "vul") { st.sev = ""; st.risk = ""; } update(); });
    });

    var db = $("dates"); db.textContent = "";
    var dbase = filtered("date");
    RANGES.forEach(function (r) {
      var n = r[2] ? dbase.filter(function (it) { return ageH(it) <= r[2]; }).length : dbase.length;
      chip(db, st.since === r[0], r[1], n, function () { st.since = r[0]; update(); });
    });

    var vul = filtered("sev").filter(function (it) { return it.type === "vul"; }), sc = {};
    vul.forEach(function (it) { var s = sevOf(it); sc[s] = (sc[s] || 0) + 1; });
    // الشريط للعرض فقط، والأزرار هي صفوف المفتاح (أهداف لمس أكبر من شريط ارتفاعه 12px)
    var bar = $("sevbar"), lg = $("sevlegend"); bar.textContent = ""; lg.textContent = "";
    bar.classList.toggle("picking", !!st.sev && st.sev !== "kev");
    SEV_ORDER.forEach(function (s) {
      if (!sc[s] && st.sev !== s) return;
      var seg = el("span", st.sev === s ? "on" : null); seg.style.setProperty("--c", "var(--s-" + s + ")"); seg.style.flex = String(sc[s] || 0); bar.appendChild(seg);
      var li = el("li"), b = el("button", "sev-btn"); b.type = "button"; b.style.setProperty("--c", "var(--s-" + s + ")");
      b.setAttribute("aria-pressed", String(st.sev === s));
      b.appendChild(el("span", null, SEV[s])); b.appendChild(el("span", "n", nf.format(sc[s] || 0)));
      b.onclick = function () { st.sev = st.sev === s ? "" : s; if (st.sev) st.type = "vul"; update(); };
      li.appendChild(b); lg.appendChild(li);
    });
    var kev = vul.filter(function (it) { return it.kev; }).length;
    if (kev || st.sev === "kev") {
      var li = el("li"), b = el("button", "sev-btn kev-btn"); b.type = "button"; b.style.setProperty("--c", "var(--s-critical)");
      b.setAttribute("aria-pressed", String(st.sev === "kev"));
      b.appendChild(el("span", null, L("ثبت استغلالها (CISA)", "Known exploited (CISA)"))); b.appendChild(el("span", "n", nf.format(kev)));
      b.onclick = function () { st.sev = st.sev === "kev" ? "" : "kev"; if (st.sev) st.type = "vul"; update(); };
      li.appendChild(b); lg.appendChild(li);
    }
    $("sev-box").hidden = !vul.length && !st.sev;
    // [CTI] risk-level filter: each count respects the other filters
    var rb = $("risks"); rb.textContent = "";
    var rv = filtered("risk").filter(function (it) { return it.type === "vul"; }), rc = {};
    rv.forEach(function (it) { rc[it.riskLevel] = (rc[it.riskLevel] || 0) + 1; });
    R.RISK_ORDER.forEach(function (k) {
      if (!rc[k] && st.risk !== k) return;
      chip(rb, st.risk === k, R.RISK[k], rc[k] || 0, function () { st.risk = st.risk === k ? "" : k; if (st.risk) st.type = "vul"; update(); });
    });
    $("risk-box").hidden = !rv.length && !st.risk;
    $("clear-wrap").hidden = !filtering();
    var n = (st.type ? 1 : 0) + (st.sev ? 1 : 0) + (st.risk ? 1 : 0) + (st.since ? 1 : 0) + (st.newOnly ? 1 : 0);
    $("filters-on").textContent = n ? (R.en ? n + " active" : n === 1 ? "تصفية واحدة فعّالة" : n === 2 ? "تصفيتان فعّالتان" : nf.format(n) + " تصفيات فعّالة") : "";
  }

  // ---------- الخلاصة
  function renderFeed() {
    var list = sorted(filtered());
    var feed = $("feed"); feed.textContent = ""; feed.setAttribute("aria-busy", "false");
    $("result").textContent = filtering() ? (L("النتائج: ", "Results: ") + nf.format(list.length) + L(" من ", " of ") + nf.format(all.length)) : "";
    if (!list.length) {
      var e = el("div", "empty");
      if (!all.length) {
        e.appendChild(el("b", null, L("لا توجد عناصر في ملف البيانات بعد. ", "No items in the data file yet. ")));
        e.appendChild(document.createTextNode(L("ستظهر هنا بعد أول دورة تحديث ناجحة للرادار.", "They will appear after the radar's first successful update.")));
      } else if (st.newOnly && !(st.type || st.sev || st.q || st.since)) {
        e.appendChild(el("b", null, lastVisit ? L("لا جديد منذ زيارتك الأخيرة. ", "Nothing new since your last visit. ")
          : L("لم يصل شيء في آخر ", "Nothing arrived in the last ") + R.countL(FIRST_VISIT_H, ["ساعة", "ساعتين", "ساعات", "ساعة"], ["hour", "hours"]) + ". "));
        e.appendChild(document.createTextNode(L("الرادار يتحدث كل ساعة، أو أطفئ «الجديد فقط» لترى كل ما رصدناه.", "The radar updates hourly. Turn off “New only” to see everything.")));
      } else {
        e.appendChild(el("b", null, L("لا توجد نتائج مطابقة. ", "No matching results. ")));
        e.appendChild(document.createTextNode(st.q
          ? L("جرّب كلمة أقل أو أعم، أو رقم CVE كاملاً، أو اضغط «إلغاء التصفية».", "Try fewer or broader words, a full CVE number, or press “Clear filters”.")
          : L("وسّع نطاق التاريخ أو اضغط «إلغاء التصفية».", "Widen the date range or press “Clear filters”.")));
      }
      feed.appendChild(e);
    }
    renderNewSwitch();
    var lastDay = null, frag = document.createDocumentFragment();
    list.slice(0, st.shown).forEach(function (it) {
      if (st.sort !== "imp" && st.sort !== "risk") { var d = R.dayLabel(it.t); if (d !== lastDay) { frag.appendChild(el("h3", "day", d)); lastDay = d; } }
      frag.appendChild(item(it));
    });
    feed.appendChild(frag);
    var more = $("more"), rest = list.length - st.shown;
    more.hidden = rest <= 0; more.textContent = L("عرض المزيد (", "Show more (") + nf.format(rest) + L(" متبقية)", " left)");
    document.querySelectorAll(".sort button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.sort === st.sort)); });
  }

  // ---------- مفتاح «الجديد فقط»
  function renderNewSwitch() {
    var tq = terms(), n = all.filter(function (it) { return isNew(it) && match(it, "new", tq); }).length;
    var b = $("newonly");
    b.setAttribute("aria-checked", String(st.newOnly));
    $("newonly-count").textContent = "(" + nf.format(n) + ")";
    b.title = lastVisit
      ? L("ما وصل منذ زيارتك السابقة: ", "What arrived since your previous visit: ") + R.at(lastVisit)
      : L("أول زيارة لك: نعرض ما وصل في آخر ", "First visit: showing what arrived in the last ") + R.countL(FIRST_VISIT_H, ["ساعة", "ساعتين", "ساعات", "ساعة"], ["hour", "hours"]);
    b.disabled = !st.newOnly && n === 0;
  }

  function update(keepShown) { if (!keepShown) st.shown = PAGE; renderSide(); renderFeed(); writeHash(); }

  // ---------- الانتقال إلى عنصر (من الرادار)
  function focusItem(id) {
    var it = byId[id]; if (!it) return;
    if (!match(it)) { st.type = ""; st.sev = ""; st.risk = ""; st.q = ""; st.since = ""; st.newOnly = false; $("q").value = ""; }
    var idx = sorted(filtered()).indexOf(it);
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
    if (c.length && R.en) {
      if (crit) lede.appendChild(el("strong", null, crit + " critical " + (crit === 1 ? "vulnerability" : "vulnerabilities")));
      if (crit && kev) lede.appendChild(document.createTextNode(" by score, and "));
      if (kev) lede.appendChild(el("strong", null, kev + (kev === 1 ? " that attackers are known to have exploited" : " that attackers are known to have exploited")));
      lede.appendChild(document.createTextNode((kev ? ", per CISA" : " by score") + ". Start with these."));
    } else if (c.length) {
      if (crit) lede.appendChild(el("strong", null, R.count(crit, "ثغرة حرجة واحدة", "ثغرتان حرجتان", "ثغرات حرجة", "ثغرة حرجة")));
      if (crit && kev) lede.appendChild(document.createTextNode(" حسب درجتها، و"));
      if (kev) lede.appendChild(el("strong", null, R.count(kev, "ثغرة واحدة", "ثغرتان", "ثغرات", "ثغرة") + " ثبت أن المهاجمين استغلوها"));
      lede.appendChild(document.createTextNode((kev ? " بحسب وكالة CISA" : " حسب درجتها") + ". ابدأ بهذه."));
    } else lede.textContent = L("لا توجد ثغرات حرجة أو مستغلة في بيانات الرادار الآن. آخر الأخبار في الأسفل.", "No critical or exploited vulnerabilities in the radar's data right now. The latest news is below.");
    var ol = $("now"); ol.textContent = ""; topIds = {};
    if (!c.length) ol.appendChild(el("li", "now-empty", L("لا شيء عاجل الآن.", "Nothing urgent right now.")));
    c.slice(0, 4).forEach(function (it) {
      topIds[it.id] = true;
      var li = el("li"), a = el("a", "now-item"); a.href = "#v=" + encodeURIComponent(it.id);
      a.onclick = function (e) { e.preventDefault(); R.openDetail(it); };
      var sc = el("span", "score" + (it.kev ? " kev" : ""), it.score != null ? Number(it.score).toFixed(1) : "?");
      sc.appendChild(el("small", null, it.kev ? L("مستغلة", "Exploited") : "CVSS"));
      a.appendChild(sc);
      var cv = R.splitCve(it);
      var tx = el("span"); var t = el("span", "now-title", cv.rest || it.title); t.setAttribute("dir", "auto"); tx.appendChild(t);
      var meta = el("span", "now-meta");
      if (cv.id) { meta.appendChild(el("bdi", null, cv.id)); meta.appendChild(document.createTextNode(R.comma)); }
      if (it.system) { meta.appendChild(el("bdi", null, R.sysName(it.system))); meta.appendChild(document.createTextNode(R.comma)); }
      meta.appendChild(document.createTextNode(R.ago(it.t)));
      tx.appendChild(meta);
      a.appendChild(tx); li.appendChild(a); ol.appendChild(li);
    });
    var more = $("now-more");
    more.hidden = c.length <= 4;
    more.textContent = L("افتح مركز التنبيهات", "Open the alerts center");
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
    [3, 6, 12, 24].forEach(function (hh) {
      var rr = 100 * Math.sqrt(hh / WINDOW_H);
      g.appendChild(svg("circle", { r: rr, "class": "ring" + (hh === 24 ? " outer" : "") }));
      var t = svg("text", { x: 2, y: (-rr - 1.5).toFixed(1), "class": "ring-label" }); t.textContent = hh + L(" س", "h"); g.appendChild(t);
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
        tip.appendChild(document.createTextNode((sv ? SEV[sv] + (it.score != null ? " " + Number(it.score).toFixed(1) : "") : TYPES[it.type])
          + (it.kev ? R.comma + L("ثبت استغلالها", "known exploited") : "") + R.comma + R.ago(it.t)));
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
    $("radar-count").textContent = R.en
      ? pts.length + " items in the last 24 hours" + (crit ? ", " + crit + " critical" : "")
      : nf.format(pts.length) + " عنصراً في آخر 24 ساعة" + (crit ? "، منها " + nf.format(crit) + " حرجة" : "");
    $("radar-cap").textContent = R.en
      ? "Radar map with " + pts.length + " items from the last 24 hours, newest at the center. The list beside it shows the most serious."
      : "خريطة رادار فيها " + nf.format(pts.length) + " عنصراً من آخر 24 ساعة، الأحدث في المركز. القائمة المجاورة تعرض الأخطر منها.";
  }

  // ---------- الأحداث
  var deb;
  $("q").addEventListener("input", function (e) {
    clearTimeout(deb);
    deb = setTimeout(function () {
      st.q = e.target.value.replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, 80);
      if (st.q) loadDet();   // البحث يشمل الوصف الأصلي، فنحمّله عند أول بحث
      update();
    }, 160);
  });
  $("q").addEventListener("keydown", function (e) { if (e.key === "Escape" && this.value) { this.value = ""; st.q = ""; update(); } });
  $("clear").onclick = function () { st.type = ""; st.sev = ""; st.risk = ""; st.q = ""; st.since = ""; st.newOnly = false; $("q").value = ""; update(); };
  $("newonly").onclick = function () { st.newOnly = !st.newOnly; update(); };
  $("more").onclick = function () { st.shown += PAGE; update(true); };
  document.querySelectorAll(".sort button").forEach(function (b) { b.onclick = function () { st.sort = b.dataset.sort; update(); }; });
  // تصدير النتائج المعروضة حالياً (بكل فلاترها وترتيبها) إلى تقرير PDF
  function scopeText() {
    var p = [];
    if (st.type) p.push(TYPES[st.type]);
    if (st.sev) p.push(st.sev === "kev" ? L("ثبت استغلالها", "Known exploited") : L("الخطورة: ", "Severity: ") + SEV[st.sev]);
    if (st.risk) p.push(R.RISK[st.risk]);
    if (st.since) p.push(RANGES.filter(function (r) { return r[0] === st.since; })[0][1]);
    if (st.q) p.push(L("بحث: «", "Search: “") + st.q + L("»", "”"));
    if (st.newOnly) p.push(L("الجديد فقط", "New only"));
    p.push(st.sort === "risk" ? L("مرتبة حسب درجة الخطر", "sorted by risk score") : st.sort === "imp" ? L("مرتبة حسب الخطورة", "sorted by severity") : st.sort === "old" ? L("الأقدم أولاً", "oldest first") : L("الأحدث أولاً", "newest first"));
    return (filtering() ? "" : L("كل ما في الموقع، ", "Everything on the site, ")) + p.join(R.comma);
  }
  $("export").onclick = function () {
    var list = sorted(filtered());
    if (!list.length) { $("result").textContent = L("لا توجد نتائج لتصديرها.", "There are no results to export."); return; }
    R.printReport(list, { genAt: genAt, scope: scopeText(),
      title: list.every(function (it) { return it.type === "vul"; }) ? L("تقرير الثغرات الأمنية", "Security vulnerability report") : L("تقرير نتائج البحث", "Search results report") });
  };
  var ft = $("filters-toggle"), fp = $("filter-panel");
  ft.onclick = function () { var open = ft.getAttribute("aria-expanded") !== "true"; ft.setAttribute("aria-expanded", String(open)); fp.classList.toggle("closed", !open); };
  window.addEventListener("hashchange", function () {
    if (!all.length || location.hash.indexOf("#i-") === 0) return;
    if (!R.openFromHash(byId)) R.closeDetail();
    readHash(); if (st.q) loadDet(); update();
  });

  // التفاصيل (الوصف الأصلي): للبحث، وهي نص العنصر بالإنجليزية
  var detLoading = false;
  function loadDet() {
    if (det || detLoading) return;
    detLoading = true;
    R.loadDetails().then(function (d) { det = d; update(true); }).catch(function () { detLoading = false; });
  }

  // ---------- التحميل
  radarGrid();
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
    if (R.en || st.q) loadDet();
    // إذا فُتحت الصفحة برابط عنصر (#i-...) ننتقل إليه
    if (location.hash.indexOf("#i-") === 0) focusItem(decodeURIComponent(location.hash.slice(3)));
    else R.openFromHash(byId);   // رابط مشارَك لثغرة (#v=CVE-...)
  }).catch(function (err) {
    $("now").textContent = ""; $("lede").textContent = L("تعذّر تحميل آخر البيانات.", "Could not load the latest data.");
    var ld = $("radar-load"); if (ld) ld.textContent = L("لا توجد بيانات", "No data");
    R.errorNotice($("feed"), err, function () { location.reload(); });
  });
})();
