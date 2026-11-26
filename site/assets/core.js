/* رادار التقنية: الكود المشترك بين الصفحات (تحميل البيانات، الأدوات، الوضع الليلي، حالة التحديث) */
(function () {
  "use strict";
  var R = window.Radar = {};

  R.TYPES = { vul: "ثغرة", gen: "أخبار تقنية وأمنية", ai: "ذكاء اصطناعي", fix: "مشكلة محلولة", os: "أنظمة التشغيل", dev: "أجهزة وجوالات" };
  R.TYPE_ORDER = ["vul", "gen", "ai", "fix", "os", "dev"];
  R.SEV = { critical: "حرجة", high: "عالية", medium: "متوسطة", low: "منخفضة", unknown: "غير مقيّمة بعد" };
  R.SEV_ORDER = ["critical", "high", "medium", "low", "unknown"];
  R.RADAR_SEV = { critical: "#FF6B66", high: "#FF9F4D", medium: "#E8C547", low: "#5FCB8D", unknown: "#A3ADBF" };
  R.SOURCES = { "feeds.feedburner.com": "The Hacker News", "feeds.arstechnica.com": "Ars Technica", "www.theverge.com": "The Verge",
    "techcrunch.com": "TechCrunch", "www.bleepingcomputer.com": "BleepingComputer" };

  R.nf = new Intl.NumberFormat("ar-SA-u-nu-latn");
  R.dayF = new Intl.DateTimeFormat("ar-SA-u-nu-latn-ca-gregory", { weekday: "long", day: "numeric", month: "long" });
  R.dateF = new Intl.DateTimeFormat("ar-SA-u-nu-latn-ca-gregory", { day: "numeric", month: "long", year: "numeric" });
  R.timeF = new Intl.DateTimeFormat("ar-SA-u-nu-latn-ca-gregory", { hour: "numeric", minute: "2-digit" });
  R.reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  R.$ = function (id) { return document.getElementById(id); };
  R.store = function (k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } };
  R.el = function (tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  R.svg = function (tag, attrs) { var e = document.createElementNS("http://www.w3.org/2000/svg", tag); for (var k in attrs) e.setAttribute(k, attrs[k]); return e; };
  // روابط المصادر تمر على هذا الفحص: http/https فقط (يمنع javascript: وغيرها)
  R.safeUrl = function (u) { try { var x = new URL(u); return /^https?:$/.test(x.protocol) ? x.href : null; } catch (e) { return null; } };
  R.link = function (a, url) { a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; return a; };
  R.srcName = function (s) { return R.SOURCES[s] || String(s || "").replace(/^www\./, ""); };
  R.sevOf = function (it) { return it.type === "vul" ? (it.severity || "unknown") : null; };
  R.isCrit = function (it) { return it.type === "vul" && (it.severity === "critical" || it.kev); };
  R.rank = function (it) {
    var s = R.sevOf(it);
    return (it.kev ? 100 : 0) + (s ? (5 - R.SEV_ORDER.indexOf(s)) * 10 + (it.score || 0) : 0);
  };
  // العنوان يصل بصيغة «CVE-2026-1234: وصف»، فنفصل الرقم عن الوصف للعرض
  R.splitCve = function (it) {
    var m = /^(CVE-\d{4}-\d{4,})\s*:\s*(.*)$/.exec(it.title || "");
    return m ? { id: m[1], rest: m[2] } : { id: null, rest: it.title };
  };
  // العدد مع المعدود بالعربية: 1 دقيقة، 2 دقيقتين، 3-10 دقائق، 11+ دقيقة
  R.count = function (n, one, two, few, many) { return n === 1 ? one : n === 2 ? two : R.nf.format(n) + " " + (n <= 10 ? few : many); };
  R.ago = function (d) {
    var m = Math.max(0, Math.round((Date.now() - d) / 6e4));
    if (m < 1) return "الآن";
    if (m < 60) return "قبل " + R.count(m, "دقيقة", "دقيقتين", "دقائق", "دقيقة");
    var h = Math.round(m / 60); if (h < 24) return "قبل " + R.count(h, "ساعة", "ساعتين", "ساعات", "ساعة");
    var dd = Math.round(h / 24); return "قبل " + R.count(dd, "يوم", "يومين", "أيام", "يوماً");
  };
  R.dayLabel = function (t) {
    var x = new Date(t); x.setHours(0, 0, 0, 0);
    var today = new Date(); today.setHours(0, 0, 0, 0);
    var diff = Math.round((today - x) / 864e5);
    return diff === 0 ? "اليوم" : diff === 1 ? "أمس" : R.dayF.format(t);
  };

  // ---------- الوضع الليلي/الفاتح (القيمة المحفوظة تُطبَّق مبكراً من سطر في <head>)
  var tb = R.$("theme");
  if (tb) tb.onclick = function () {
    var cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    var next = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next; R.store("radar-theme", next);
  };

  // ---------- حالة التحديث في الرأس
  R.status = function (state, genAt) {
    var s = R.$("status"), t = R.$("status-text"); if (!s) return;
    s.classList.remove("loading", "stale", "down");
    if (state === "loading") { s.classList.add("loading"); t.textContent = "جارٍ التحميل"; s.title = ""; return; }
    if (state === "error") { s.classList.add("down"); t.textContent = "تعذّر التحميل"; s.title = "لم نتمكن من قراءة ملف البيانات."; return; }
    var h = (Date.now() - genAt) / 36e5;
    t.textContent = "آخر تحديث " + R.ago(genAt);
    s.title = "يتحدث كل ساعة. آخر تحديث الساعة " + R.timeF.format(genAt);
    if (h > 2) {
      s.classList.add("stale"); t.textContent += " (متأخر عن موعده)";
      s.title = "يتحدث عادةً كل ساعة، وآخر تحديث وصل الساعة " + R.timeF.format(genAt) + " (" + R.dayLabel(genAt) + "). قد يكون جهاز الرادار مطفأً.";
    }
  };

  // ---------- تحميل البيانات والتحقق منها
  // البيانات تأتي من ملف ينتجه الوكيل، ومع ذلك نتحقق من كل حقل: نص يبقى نصاً، والدرجة رقم بين 0 و10، والخطورة من القيم المعروفة
  function str(v, max) { return typeof v === "string" ? v.slice(0, max || 2000) : ""; }
  function clean(it, genAt) {
    if (!it || typeof it !== "object") return null;
    var o = {
      id: str(it.id, 64), type: R.TYPES[it.type] ? it.type : "gen", title: str(it.title, 300), summary: str(it.summary, 1200),
      system: str(it.system, 200), source: str(it.source, 120), link: str(it.link, 600), date: str(it.date, 40),
      advice: str(it.advice, 400), kev: it.kev === true,
      sumSrc: ({ llm: 1, template: 1, failed: 1, pending: 1 })[it.sum_src] ? it.sum_src : ""
    };
    // ملفات قديمة: الملخص القالبي يُعرف من بدايته
    if (!o.sumSrc && /^ثغرة أمنية خطورتها/.test(o.summary)) o.sumSrc = "template";
    if (!o.id || !o.title) return null;
    var sc = typeof it.score === "number" && isFinite(it.score) && it.score >= 0 && it.score <= 10 ? it.score : null;
    o.score = sc;
    o.severity = o.type === "vul" ? (R.SEV[it.severity] ? it.severity : "unknown") : null;
    o.t = Date.parse(o.date) || genAt;
    return o;
  }
  // cache: "no-cache" يسمح للمتصفح بإعادة استخدام نسخته إذا لم يتغير الملف (رد 304) بدل تنزيله كاملاً كل مرة
  R.load = function () {
    R.status("loading");
    return fetch("data.json", { cache: "no-cache" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (d) {
        if (!d || !Array.isArray(d.items)) throw new Error("bad-format");
        var genAt = Date.parse(d.generated_at) || Date.now(), seen = {}, items = [];
        d.items.forEach(function (raw) { var it = clean(raw, genAt); if (it && !seen[it.id]) { seen[it.id] = 1; items.push(it); } });
        R.status("ok", genAt);
        return { genAt: genAt, items: items, raw: d };
      })
      .catch(function (err) { R.status("error"); throw err; });
  };

  // ---------- معاملات الرابط بعد # (الفلاتر و«v» لنافذة التفاصيل)
  R.hashParams = function () { return new URLSearchParams(location.hash.slice(1)); };
  R.setHash = function (p) {
    var h = p.toString();
    try { history.replaceState(null, "", h ? "#" + h : location.pathname + location.search); } catch (e) {}
  };

  // ---------- نافذة تفاصيل الثغرة
  // التفاصيل (الوصف الأصلي، تاريخ آخر تحديث، بيانات CISA) في ملف منفصل يُحمَّل عند أول فتح فقط
  var detailsP = null;
  R.loadDetails = function () {
    if (!detailsP) detailsP = fetch("details.json", { cache: "no-cache" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (d) { return (d && d.items && typeof d.items === "object") ? d.items : {}; })
      .catch(function (e) { detailsP = null; throw e; });
    return detailsP;
  };
  var SUM_NOTE = {
    llm: "ملخص آلي كتبه نموذج لغوي (Qwen3) يعمل على جهاز الرادار. قد يخطئ، والوصف الأصلي أعلاه هو المرجع.",
    template: "ملخص مبني من بيانات الثغرة نفسها (الدرجة والمنتج)، بلا نموذج لغوي."
  };
  R.cisaUrl = function (id) { return "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + encodeURIComponent(id); };
  R.fmtDate = function (s) { var t = Date.parse(s); return t ? R.dateF.format(t) : ""; };

  var dlg = null, dlgItem = null;
  function fact(dl, label, node, note) {
    var row = R.el("div", "fact");
    row.appendChild(R.el("dt", null, label));
    var dd = R.el("dd"); if (typeof node === "string") dd.textContent = node; else dd.appendChild(node);
    if (note) dd.appendChild(R.el("small", null, note));
    row.appendChild(dd); dl.appendChild(row);
    return dd;
  }
  function ensureDialog() {
    if (dlg) return dlg;
    dlg = R.el("dialog", "detail"); dlg.setAttribute("aria-labelledby", "d-title");
    dlg.addEventListener("close", function () {
      var p = R.hashParams(); p.delete("v"); R.setHash(p); dlgItem = null;
    });
    // الضغط خارج الصندوق يغلق النافذة
    dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });
    document.body.appendChild(dlg);
    return dlg;
  }
  R.openDetail = function (it) {
    var d = ensureDialog(); dlgItem = it; d.textContent = "";
    var sv = R.sevOf(it), cv = R.splitCve(it), id = cv.id || it.id;
    var box = R.el("article", "d-box"); box.style.setProperty("--c", "var(--s-" + sv + ")");
    var head = R.el("header", "d-head");
    var close = R.el("button", "icon-btn d-close"); close.type = "button"; close.setAttribute("aria-label", "إغلاق");
    close.appendChild(R.svg("svg", { width: 18, height: 18, viewBox: "0 0 24 24", "aria-hidden": "true" })).appendChild(R.svg("path", { d: "M6 6l12 12M18 6 6 18", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round" }));
    close.onclick = function () { d.close(); };
    var h = R.el("h2", "d-id"); h.id = "d-title"; h.appendChild(R.el("bdi", null, id)); head.appendChild(h);
    var tags = R.el("div", "d-tags");
    tags.appendChild(R.el("span", "pill", "الخطورة: " + R.SEV[sv]));
    var kp = R.el("span", "pill " + (it.kev ? "kev" : "nokev"), it.kev ? "ثبت استغلالها" : "لا دليل منشور على استغلالها");
    tags.appendChild(kp); head.appendChild(tags); head.appendChild(close);
    box.appendChild(head);

    // الدرجة: رقم كبير + مقياس من 10
    var scoreBox = R.el("section", "d-score");
    var big = R.el("div", "d-num");
    big.appendChild(R.el("b", "num", it.score != null ? Number(it.score).toFixed(1) : "؟"));
    big.appendChild(R.el("span", null, it.score != null ? "من 10 (CVSS)" : "لم تُقيَّم بعد في NVD"));
    scoreBox.appendChild(big);
    var meter = R.el("div", "d-meter"); meter.setAttribute("aria-hidden", "true");
    var fill = R.el("span"); fill.style.width = (it.score != null ? it.score * 10 : 0) + "%"; meter.appendChild(fill);
    ["4", "7", "9"].forEach(function (x) { var tk = R.el("i"); tk.style.insetInlineStart = (x * 10) + "%"; meter.appendChild(tk); });
    scoreBox.appendChild(meter);
    var scale = R.el("div", "d-scale"); scale.setAttribute("aria-hidden", "true");
    ["منخفضة", "متوسطة 4+", "عالية 7+", "حرجة 9+"].forEach(function (x) { scale.appendChild(R.el("span", null, x)); });
    scoreBox.appendChild(scale);
    box.appendChild(scoreBox);

    var desc = R.el("section", "d-sec");
    desc.appendChild(R.el("h3", null, "وصف الثغرة"));
    var title = R.el("p", "d-title-text", cv.rest || it.title); title.setAttribute("dir", "auto"); desc.appendChild(title);
    var orig = R.el("div", "d-orig"); orig.appendChild(R.el("span", "skel"));
    desc.appendChild(orig);
    box.appendChild(desc);

    var sum = R.el("section", "d-sec");
    sum.appendChild(R.el("h3", null, "الملخص بالعربية"));
    var hasSum = it.summary && (it.sumSrc === "llm" || it.sumSrc === "template");
    if (hasSum) {
      var sp = R.el("p", "d-sum", it.summary); sp.setAttribute("dir", "auto"); sum.appendChild(sp);
      sum.appendChild(R.el("p", "d-note", SUM_NOTE[it.sumSrc]));
    } else {
      var n = R.el("div", "notice"); n.style.setProperty("--c", "var(--s-medium)");
      n.appendChild(R.el("b", null, it.sumSrc === "failed" ? "تعذّر إنشاء ملخص عربي موثوق" : "الملخص العربي لم يُكتب بعد"));
      n.appendChild(R.el("p", null, it.sumSrc === "failed"
        ? "رفض فحص الجودة الملخص المقترح (لغة أو أرقام لا تطابق المصدر)، فلم ننشره. اعتمد على الوصف الأصلي."
        : "سيُضاف في إحدى دورات التحديث القادمة. حتى ذلك الحين اعتمد على الوصف الأصلي."));
      sum.appendChild(n);
    }
    box.appendChild(sum);

    var facts = R.el("section", "d-sec");
    facts.appendChild(R.el("h3", null, "البيانات"));
    var dl = R.el("dl", "facts");
    fact(dl, "التصنيف", R.SEV[sv], it.score != null ? "حسب سلّم NVD لدرجة CVSS" : "تظهر الدرجة حين تقيّمها NVD");
    fact(dl, "تاريخ النشر", R.fmtDate(it.date) || "غير متوفر");
    var mod = fact(dl, "آخر تحديث في NVD", "…");
    var seen = fact(dl, "رصدها الرادار", "…");
    var sysNode = R.el("bdi", null, it.system && it.system !== "غير محدد" ? it.system : "غير محدد");
    fact(dl, "المنتج المتأثر", sysNode, it.source === "CISA KEV" ? "من بيانات CISA" : "مستخرج آلياً من نص الوصف، تحقق منه في المصدر");
    var expl = fact(dl, "حالة الاستغلال", it.kev ? "ثبت استغلالها بحسب CISA" : "لا دليل منشور على استغلالها",
      it.kev ? null : "ليست في قائمة CISA للثغرات المستغلة حتى آخر تحديث، وهذا لا يعني أنها آمنة");
    fact(dl, "مصدر الرصد", R.srcName(it.source));
    var vec = fact(dl, "متجه CVSS", "…"); vec.parentNode.hidden = true;
    facts.appendChild(dl);
    box.appendChild(facts);

    var kevSec = R.el("section", "d-sec d-kev"); kevSec.hidden = true; box.appendChild(kevSec);

    if (it.advice) {
      var adv = R.el("section", "d-sec");
      adv.appendChild(R.el("h3", null, "ماذا تفعل"));
      adv.appendChild(R.el("p", null, it.advice));
      box.appendChild(adv);
    }

    var links = R.el("footer", "d-links");
    var nvd = "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(id);
    var srcUrl = it.source === "CISA KEV" ? R.cisaUrl(id) : R.safeUrl(it.link);
    if (srcUrl) links.appendChild(R.link(R.el("a", "btn primary", it.source === "CISA KEV" ? "المصدر الأصلي (CISA)" : "المصدر الأصلي (NVD)"), srcUrl));
    if (it.source === "CISA KEV") links.appendChild(R.link(R.el("a", "btn", "صفحة الثغرة في NVD"), nvd));
    var share = R.el("button", "btn", "نسخ رابط هذه الصفحة"); share.type = "button";
    share.onclick = function () {
      var u = location.href;
      (navigator.clipboard ? navigator.clipboard.writeText(u) : Promise.reject()).then(function () { share.textContent = "نُسخ الرابط"; },
        function () { share.textContent = "انسخه من شريط العنوان"; });
      setTimeout(function () { share.textContent = "نسخ رابط هذه الصفحة"; }, 2500);
    };
    links.appendChild(share);
    box.appendChild(links);
    d.appendChild(box);

    var p = R.hashParams(); p.set("v", it.id); R.setHash(p);
    if (!d.open) { if (d.showModal) d.showModal(); else d.setAttribute("open", ""); }
    close.focus({ preventScroll: true }); d.scrollTop = 0;

    R.loadDetails().then(function (all) {
      if (dlgItem !== it) return;
      var x = all[it.id] || {};
      orig.textContent = "";
      if (x.text) {
        // عنوان ثغرات NVD هو أول 90 حرفاً من الوصف نفسه، فلا نكرره
        if (cv.rest && x.text.indexOf(cv.rest.replace(/\s+$/, "")) === 0) title.hidden = true;
        orig.appendChild(R.el("span", "d-label", it.source === "CISA KEV" ? "الوصف الأصلي من CISA" : "الوصف الأصلي من NVD"));
        var t = R.el("p", "d-en", x.text); t.setAttribute("dir", "ltr"); t.setAttribute("lang", "en"); orig.appendChild(t);
      } else orig.appendChild(R.el("p", "d-note", "الوصف الأصلي غير متوفر في بياناتنا. افتح المصدر للاطلاع عليه."));
      mod.textContent = x.modified ? R.fmtDate(x.modified) : "لم نسجّله بعد";
      if (!x.modified) mod.appendChild(R.el("small", null, "يُجلب تدريجياً في دورات التحديث"));
      seen.textContent = x.seen ? R.fmtDate(x.seen) + "، الساعة " + R.timeF.format(Date.parse(x.seen)) : "غير مسجّل";
      if (x.vector) { vec.textContent = ""; var vb = R.el("bdi", "d-vec", (x.cvss_ver ? "v" + x.cvss_ver + " " : "") + x.vector); vb.setAttribute("dir", "ltr"); vec.appendChild(vb); vec.parentNode.hidden = false; }
      if (it.kev) {
        if (x.kev_added) { expl.textContent = "ثبت استغلالها: أضافتها CISA إلى قائمتها في " + R.fmtDate(x.kev_added); }
        kevSec.hidden = false; kevSec.textContent = "";
        kevSec.appendChild(R.el("h3", null, "بيانات الاستغلال من CISA"));
        var kd = R.el("dl", "facts");
        if (x.kev_ransom) fact(kd, "حملات الفدية", x.kev_ransom === "Known" ? "استُخدمت في حملات فدية معروفة" : "غير معروف إن استُخدمت في حملات فدية");
        if (x.kev_due) fact(kd, "الموعد النهائي للإصلاح", R.fmtDate(x.kev_due), "حددته CISA للجهات الحكومية الأمريكية");
        if (x.kev_action) { var ka = R.el("span", "d-en", x.kev_action); ka.setAttribute("dir", "ltr"); ka.setAttribute("lang", "en"); fact(kd, "الإجراء المطلوب", ka); }
        if (!kd.children.length) kd.appendChild(R.el("p", "d-note", "تفاصيل CISA لهذه الثغرة لم تُسجَّل بعد."));
        kevSec.appendChild(kd);
      }
    }).catch(function () {
      if (dlgItem !== it) return;
      orig.textContent = ""; orig.appendChild(R.el("p", "d-note", "تعذّر تحميل التفاصيل الإضافية (الوصف الأصلي وتاريخ التحديث). البيانات أعلاه من الملف الرئيسي."));
      mod.textContent = "غير متوفر"; seen.textContent = "غير متوفر";
    });
  };
  R.closeDetail = function () { if (dlg && dlg.open) dlg.close(); };
  // فتح التفاصيل من رابط مشارَك (#v=CVE-...)
  R.openFromHash = function (byId) {
    var v = R.hashParams().get("v");
    if (v && byId[v] && byId[v].type === "vul") { R.openDetail(byId[v]); return true; }
    return false;
  };

  // ---------- رسالة خطأ موحدة مع زر إعادة المحاولة
  R.errorNotice = function (box, err, retry) {
    box.textContent = "";
    var n = R.el("div", "notice error"); n.setAttribute("role", "alert");
    n.appendChild(R.el("b", null, "تعذّر تحميل البيانات"));
    var local = location.protocol === "file:";
    n.appendChild(R.el("p", null, local
      ? "فتحت الصفحة كملف من جهازك، والمتصفح يمنع قراءة البيانات بهذه الطريقة. شغّلها عبر خادم محلي (python -m http.server داخل مجلد site)."
      : (String(err && err.message) === "bad-format"
        ? "ملف البيانات وصل بصيغة غير متوقعة. سيُصلَح مع التحديث القادم."
        : "تحقق من اتصالك بالإنترنت ثم أعد المحاولة.")));
    if (retry && !local) {
      var b = R.el("button", "btn", "أعد المحاولة"); b.type = "button";
      b.onclick = retry; n.appendChild(b);
    }
    box.appendChild(n);
  };
})();
