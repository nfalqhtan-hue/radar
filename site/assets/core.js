/* رادار التقنية: الكود المشترك بين الصفحات (اللغة، تحميل البيانات، الأدوات، الوضع الليلي، حالة التحديث، نافذة التفاصيل) */
(function () {
  "use strict";
  var R = window.Radar = {};

  // ---------- اللغة: العربية افتراضياً، والاختيار يُحفظ في المتصفح فيبقى عند التنقل بين الصفحات (ويقبل ?lang=en للمشاركة)
  var qLang = null;
  try { qLang = new URLSearchParams(location.search).get("lang"); } catch (e) {}
  R.store = function (k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } };
  if (qLang === "en" || qLang === "ar") R.store("radar-lang", qLang);
  R.lang = (qLang || R.store("radar-lang")) === "en" ? "en" : "ar";
  R.en = R.lang === "en";
  document.documentElement.lang = R.lang; document.documentElement.dir = R.en ? "ltr" : "rtl";
  // النص باللغتين في مكان استخدامه: L("حرجة", "Critical")
  R.L = function (ar, en) { return R.en ? en : ar; };
  var L = R.L;

  R.TYPES = R.en
    ? { vul: "Vulnerability", upd: "Security updates", sec: "Security news", gen: "Tech news", ai: "AI", fix: "Fixed issue", os: "Operating systems", dev: "Devices & phones" }
    : { vul: "ثغرة", upd: "تحديثات أمنية", sec: "أخبار أمنية", gen: "أخبار تقنية", ai: "ذكاء اصطناعي", fix: "مشكلة محلولة", os: "أنظمة التشغيل", dev: "أجهزة وجوالات" };
  R.TYPE_ORDER = ["vul", "upd", "sec", "gen", "ai", "fix", "os", "dev"];
  // [CTI] pillar 3: kinds of vendor update, kept apart from vulnerability disclosures
  R.UTYPE = R.en ? { patch: "Security patch", advisory: "Security advisory", release: "General update" }
    : { patch: "تحديث أمني", advisory: "نشرة أمنية", release: "تحديث عام" };
  R.SEV = R.en
    ? { critical: "Critical", high: "High", medium: "Medium", low: "Low", unknown: "Not scored yet" }
    : { critical: "حرجة", high: "عالية", medium: "متوسطة", low: "منخفضة", unknown: "غير مقيّمة بعد" };
  R.SEV_ORDER = ["critical", "high", "medium", "low", "unknown"];
  R.RADAR_SEV = { critical: "#FF6B66", high: "#FF9F4D", medium: "#E8C547", low: "#5FCB8D", unknown: "#A3ADBF" };
  R.SOURCES = { "feeds.feedburner.com": "The Hacker News", "feeds.arstechnica.com": "Ars Technica", "www.theverge.com": "The Verge",
    "techcrunch.com": "TechCrunch", "www.bleepingcomputer.com": "BleepingComputer",
    "chromereleases.googleblog.com": "Chrome Releases", "ubuntu.com": "Ubuntu Security Notices", "lists.debian.org": "Debian Security",
    "sec.cloudapps.cisco.com": "Cisco PSIRT", "fortiguard.fortinet.com": "Fortinet PSIRT", "www.oracle.com": "Oracle Security Alerts" };
  R.ADVICE = L("حدّث النظام أو البرنامج المتأثر إلى أحدث إصدار من المصدر الرسمي، وراجع نشرة الشركة لتفاصيل الإصلاح.",
    "Update the affected system or software to the latest version from the official source, and check the vendor advisory for fix details.");
  R.UNSPEC = "غير محدد";
  R.sysName = function (s) { return s && s !== R.UNSPEC ? s : L("غير محدد", "Unspecified"); };

  var loc = R.en ? "en-US" : "ar-SA-u-nu-latn-ca-gregory";
  R.nf = new Intl.NumberFormat(R.en ? "en-US" : "ar-SA-u-nu-latn");
  R.dayF = new Intl.DateTimeFormat(loc, { weekday: "long", day: "numeric", month: "long" });
  R.dateF = new Intl.DateTimeFormat(loc, { day: "numeric", month: "long", year: "numeric" });
  R.timeF = new Intl.DateTimeFormat(loc, { hour: "numeric", minute: "2-digit" });
  R.reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  R.comma = L("، ", ", ");

  R.$ = function (id) { return document.getElementById(id); };
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
  // ---------- [CTI] Risk score (0-100) computed by the pipeline from CVSS, CISA KEV, public-exploit evidence, age/exposure, patch.
  // It is a priority for action, separate from CVSS severity. Labels say «خطر» so they never read as the CVSS rating.
  R.RISK = R.en
    ? { critical: "Critical risk", high: "High risk", medium: "Medium risk", low: "Low risk", unknown: "Not enough data" }
    : { critical: "خطر حرج", high: "خطر عالٍ", medium: "خطر متوسط", low: "خطر منخفض", unknown: "بيانات غير كافية" };
  R.RISK_ORDER = ["critical", "high", "medium", "low", "unknown"];
  R.riskRank = function (it) { return it.risk != null ? it.risk + (it.kev ? 0.5 : 0) : -1; };
  R.riskBadge = function (it) {
    var lv = it.riskLevel || "unknown", b = R.el("span", "risk-b");
    b.style.setProperty("--c", "var(--s-" + lv + ")");
    var m = R.el("i"); m.setAttribute("aria-hidden", "true"); m.style.setProperty("--p", (it.risk != null ? it.risk : 0) + "%"); b.appendChild(m);
    b.appendChild(R.el("span", null, it.risk != null ? L("خطر ", "Risk ") + it.risk : R.RISK.unknown));
    b.title = (it.risk != null ? R.RISK[lv] + L(": ", ": ") + it.risk + L(" من 100", "/100") : L("لا درجة CVSS ولا إدراج في قائمة CISA بعد", "No CVSS score and no CISA listing yet"))
      + L(". أولوية التصرف، وتختلف عن خطورة CVSS.", ". Priority for action, separate from CVSS severity.");
    return b;
  };
  // العنوان يصل بصيغة «CVE-2026-1234: وصف»، فنفصل الرقم عن الوصف للعرض
  R.splitCve = function (it) {
    var m = /^(CVE-\d{4}-\d{4,})\s*:\s*(.*)$/.exec(it.title || "");
    if (!m) return { id: null, rest: it.title, raw: it.title };
    // عنوان ثغرات NVD هو أول 90 حرفاً من الوصف، فنُظهر أنه مقطوع بدل أن ينتهي وسط كلمة
    var rest = m[2], cut = it.source === "NVD" && rest.length >= 85 && !/[.!?)]$/.test(rest);
    return { id: m[1], rest: cut ? rest.replace(/\s+\S{0,12}$/, "") + "…" : rest, raw: rest };
  };
  // العدد مع المعدود. العربية: 1 دقيقة، 2 دقيقتين، 3-10 دقائق، 11+ دقيقة. الإنجليزية: 1 minute، 2 minutes
  R.count = function (n, one, two, few, many) { return n === 1 ? one : n === 2 ? two : R.nf.format(n) + " " + (n <= 10 ? few : many); };
  R.countL = function (n, ar, en) { return R.en ? R.nf.format(n) + " " + (n === 1 ? en[0] : en[1]) : R.count(n, ar[0], ar[1], ar[2], ar[3]); };
  R.ago = function (d) {
    var m = Math.max(0, Math.round((Date.now() - d) / 6e4));
    if (m < 1) return L("الآن", "just now");
    if (m < 60) return R.en ? R.countL(m, null, ["minute", "minutes"]) + " ago" : "قبل " + R.count(m, "دقيقة", "دقيقتين", "دقائق", "دقيقة");
    var h = Math.round(m / 60); if (h < 24) return R.en ? R.countL(h, null, ["hour", "hours"]) + " ago" : "قبل " + R.count(h, "ساعة", "ساعتين", "ساعات", "ساعة");
    var dd = Math.round(h / 24); return R.en ? R.countL(dd, null, ["day", "days"]) + " ago" : "قبل " + R.count(dd, "يوم", "يومين", "أيام", "يوماً");
  };
  R.dayLabel = function (t) {
    var x = new Date(t); x.setHours(0, 0, 0, 0);
    var today = new Date(); today.setHours(0, 0, 0, 0);
    var diff = Math.round((today - x) / 864e5);
    return diff === 0 ? L("اليوم", "Today") : diff === 1 ? L("أمس", "Yesterday") : R.dayF.format(t);
  };
  R.at = function (t) { return R.dayLabel(t) + L("، الساعة ", ", ") + R.timeF.format(t); };
  // تطبيع للبحث: حروف صغيرة، بلا تشكيل، وتوحيد الألف والياء والتاء المربوطة
  R.norm = function (s) {
    return String(s || "").toLowerCase().replace(/[ً-ْـ]/g, "").replace(/[أإآ]/g, "ا").replace(/ى/g, "ي").replace(/ة/g, "ه");
  };

  // ---------- نصوص الصفحة الثابتة بالإنجليزية: data-en (النص)، data-en-placeholder، data-en-aria-label، data-en-title، data-en-content
  function applyStatic() {
    if (!R.en) return;
    document.querySelectorAll("[data-en]").forEach(function (e) { e.textContent = e.getAttribute("data-en"); });
    ["placeholder", "aria-label", "title", "content"].forEach(function (a) {
      document.querySelectorAll("[data-en-" + a + "]").forEach(function (e) { e.setAttribute(a, e.getAttribute("data-en-" + a)); });
    });
  }
  applyStatic();

  // ---------- مفتاح اللغة: يحفظ الاختيار ويعيد تحميل الصفحة نفسها (مع الفلاتر في الرابط)
  var lb = R.$("lang");
  if (lb) {
    lb.textContent = R.en ? "ع" : "EN";
    lb.setAttribute("aria-label", R.en ? "التبديل إلى العربية" : "Switch to English");
    lb.setAttribute("lang", R.en ? "ar" : "en");
    lb.onclick = function () {
      R.store("radar-lang", R.en ? "ar" : "en");
      var u = new URL(location.href); u.searchParams.delete("lang");
      location.replace(u.href);
    };
  }

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
    if (state === "loading") { s.classList.add("loading"); t.textContent = L("جارٍ التحميل", "Loading"); s.title = ""; return; }
    if (state === "error") { s.classList.add("down"); t.textContent = L("تعذّر التحميل", "Could not load"); s.title = L("لم نتمكن من قراءة ملف البيانات.", "The data file could not be read."); return; }
    var h = (Date.now() - genAt) / 36e5;
    t.textContent = L("آخر تحديث ", "Updated ") + R.ago(genAt);
    s.title = L("يتحدث كل ساعة. آخر تحديث الساعة ", "Updates every hour. Last update at ") + R.timeF.format(genAt);
    if (h > 2) {
      s.classList.add("stale"); t.textContent += L(" (متأخر عن موعده)", " (overdue)");
      s.title = L("يتحدث عادةً كل ساعة، وآخر تحديث وصل ", "Usually updates every hour; the last update arrived ") + R.at(genAt)
        + L(". قد يكون جهاز الرادار مطفأً.", ". The radar machine may be switched off.");
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
    var rs = typeof it.risk === "number" && isFinite(it.risk) && it.risk >= 0 && it.risk <= 100 ? Math.round(it.risk) : null;
    o.risk = o.type === "vul" ? rs : null;
    o.riskLevel = o.type === "vul" ? (rs != null && R.RISK[it.risk_level] && it.risk_level !== "unknown" ? it.risk_level : "unknown") : null;
    o.t = Date.parse(o.date) || genAt;
    if (o.type === "upd") {   // [CTI] security update fields, validated like the rest
      o.utype = R.UTYPE[it.utype] ? it.utype : "advisory";
      o.product = str(it.product, 120); o.fixed = str(it.fixed, 120); o.affected = str(it.affected, 200);
      o.cves = Array.isArray(it.cves) ? it.cves.filter(function (c) { return typeof c === "string" && /^CVE-\d{4}-\d{4,}$/.test(c); }).slice(0, 12) : [];
      o.cveN = typeof it.cve_n === "number" && it.cve_n >= 0 ? Math.min(it.cve_n, 999) : o.cves.length;
      o.vendorExploited = it.vendor_exploited === true; o.action = it.action === true;
    }
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

  // ---------- التفاصيل (الوصف الأصلي، تاريخ آخر تحديث، بيانات CISA) في ملف منفصل يُحمَّل عند الحاجة فقط
  var detailsP = null;
  R.loadDetails = function () {
    if (!detailsP) detailsP = fetch("details.json", { cache: "no-cache" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (d) {
        var items = (d && d.items && typeof d.items === "object") ? d.items : {};
        Object.keys(items).forEach(function (k) { var x = items[k]; if (!x || typeof x !== "object") delete items[k]; else if (typeof x.text !== "string") x.text = ""; });
        return items;
      })
      .catch(function (e) { detailsP = null; throw e; });
    return detailsP;
  };
  R.cisaUrl = function (id) { return "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + encodeURIComponent(id); };
  R.fmtDate = function (s) { var t = Date.parse(s); return t ? R.dateF.format(t) : ""; };
  // تاريخ العنصر: لعناصر قائمة CISA هو تاريخ إدراجها في القائمة لا تاريخ نشر الثغرة
  R.dateLabel = function (it) { return it.source === "CISA KEV" ? L("أُدرجت في قائمة CISA", "Added to CISA list") : L("تاريخ النشر", "Published"); };

  // ---------- نافذة تفاصيل الثغرة
  var dlg = null, dlgItem = null;
  function fact(dl, label, node, note) {
    var row = R.el("div", "fact");
    row.appendChild(R.el("dt", null, label));
    var dd = R.el("dd"); if (typeof node === "string") dd.textContent = node; else dd.appendChild(node);
    if (note) dd.appendChild(R.el("small", null, note));
    row.appendChild(dd); dl.appendChild(row);
    return dd;
  }
  function afterClose() {
    var p = R.hashParams();
    if (p.has("v")) { p.delete("v"); R.setHash(p); }
    dlgItem = null;
  }
  function closeDlg() { if (dlg && dlg.open) dlg.close(); afterClose(); }
  function ensureDialog() {
    if (dlg) return dlg;
    dlg = R.el("dialog", "detail"); dlg.setAttribute("aria-labelledby", "d-title");
    // تنظيف الرابط عند الإغلاق: حدث close لا يصل دائماً (في بعض المتصفحات والتبويبات الخلفية)، فننظفه أيضاً في كل طريق إغلاق نتحكم به
    dlg.addEventListener("close", afterClose);
    dlg.addEventListener("cancel", function () { setTimeout(afterClose, 0); });   // زر Esc
    // الضغط خارج الصندوق يغلق النافذة
    dlg.addEventListener("click", function (e) { if (e.target === dlg) closeDlg(); });
    document.body.appendChild(dlg);
    return dlg;
  }
  R.openDetail = function (it) {
    var d = ensureDialog(); dlgItem = it; d.textContent = "";
    var sv = R.sevOf(it), cv = R.splitCve(it), id = cv.id || it.id, kevSrc = it.source === "CISA KEV";
    var box = R.el("article", "d-box"); box.style.setProperty("--c", "var(--s-" + sv + ")");
    var head = R.el("header", "d-head");
    var close = R.el("button", "icon-btn d-close"); close.type = "button"; close.setAttribute("aria-label", L("إغلاق", "Close"));
    close.appendChild(R.svg("svg", { width: 18, height: 18, viewBox: "0 0 24 24", "aria-hidden": "true" })).appendChild(R.svg("path", { d: "M6 6l12 12M18 6 6 18", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round" }));
    close.onclick = closeDlg;
    var h = R.el("h2", "d-id"); h.id = "d-title"; h.appendChild(R.el("bdi", null, id)); head.appendChild(h);
    var tags = R.el("div", "d-tags");
    tags.appendChild(R.el("span", "pill", L("الخطورة: ", "Severity: ") + R.SEV[sv]));
    tags.appendChild(R.el("span", "pill " + (it.kev ? "kev" : "nokev"), it.kev ? L("ثبت استغلالها", "Known exploited") : L("لا دليل منشور على استغلالها", "No published evidence of exploitation")));
    head.appendChild(tags); head.appendChild(close);
    box.appendChild(head);

    // الدرجة: رقم كبير + مقياس من 10
    var scoreBox = R.el("section", "d-score");
    var big = R.el("div", "d-num");
    big.appendChild(R.el("b", "num", it.score != null ? Number(it.score).toFixed(1) : "?"));
    big.appendChild(R.el("span", null, it.score != null ? L("من 10 (CVSS)", "out of 10 (CVSS)") : L("لم تُقيَّم بعد في NVD", "Not yet scored by NVD")));
    scoreBox.appendChild(big);
    var meter = R.el("div", "d-meter"); meter.setAttribute("aria-hidden", "true");
    var fill = R.el("span"); fill.style.width = (it.score != null ? it.score * 10 : 0) + "%"; meter.appendChild(fill);
    ["4", "7", "9"].forEach(function (x) { var tk = R.el("i"); tk.style.insetInlineStart = (x * 10) + "%"; meter.appendChild(tk); });
    scoreBox.appendChild(meter);
    var scale = R.el("div", "d-scale"); scale.setAttribute("aria-hidden", "true");
    (R.en ? ["Low", "Medium 4+", "High 7+", "Critical 9+"] : ["منخفضة", "متوسطة 4+", "عالية 7+", "حرجة 9+"]).forEach(function (x) { scale.appendChild(R.el("span", null, x)); });
    scoreBox.appendChild(scale);
    box.appendChild(scoreBox);

    // [CTI] Risk score: number + level now (from data.json), factor breakdown when details.json arrives
    var riskSec = R.el("section", "d-sec d-risk"); riskSec.style.setProperty("--c", "var(--s-" + (it.riskLevel || "unknown") + ")");
    var rh = R.el("div", "d-risk-head");
    var rn = R.el("div", "d-risk-num");
    rn.appendChild(R.el("b", "num", it.risk != null ? String(it.risk) : "?"));
    rn.appendChild(R.el("span", null, it.risk != null ? L("من 100", "out of 100") : ""));
    rh.appendChild(rn);
    var rt = R.el("div");
    rt.appendChild(R.el("h3", null, L("درجة الخطر: ", "Risk score: ") + R.RISK[it.riskLevel || "unknown"]));
    rt.appendChild(R.el("p", "d-note", it.risk != null
      ? L("أولوية التصرف، محسوبة من درجة CVSS وثبوت الاستغلال ومعلومات الاستغلال المنشورة وعمر الثغرة وتوفر الإصلاح. تختلف عن خطورة CVSS أعلاه.",
          "Priority for action, computed from the CVSS score, confirmed exploitation, published exploit information, age and patch availability. Separate from the CVSS severity above.")
      : L("لا نحسب درجة لثغرة بلا درجة CVSS وغير مدرجة في قائمة CISA، بدل أن نعرض رقماً غير موثوق.",
          "We do not score a vulnerability with no CVSS score and no CISA listing, rather than show an unreliable number.")));
    rh.appendChild(rt); riskSec.appendChild(rh);
    var rBody = R.el("div"); riskSec.appendChild(rBody);
    if (it.risk != null) rBody.appendChild(R.el("span", "skel"));
    box.appendChild(riskSec);

    var desc = R.el("section", "d-sec");
    desc.appendChild(R.el("h3", null, L("وصف الثغرة", "Description")));
    var title = R.el("p", "d-title-text", cv.rest || it.title); title.setAttribute("dir", "auto"); desc.appendChild(title);
    var orig = R.el("div", "d-orig"); orig.appendChild(R.el("span", "skel"));
    desc.appendChild(orig);
    box.appendChild(desc);

    var sum = R.el("section", "d-sec");
    sum.appendChild(R.el("h3", null, L("الملخص بالعربية", "Arabic summary")));
    var hasSum = it.summary && (it.sumSrc === "llm" || it.sumSrc === "template");
    if (hasSum) {
      var sp = R.el("p", "d-sum", it.summary); sp.setAttribute("dir", "rtl"); sp.setAttribute("lang", "ar"); sum.appendChild(sp);
      sum.appendChild(R.el("p", "d-note", it.sumSrc === "llm"
        ? L("ملخص آلي كتبه نموذج لغوي (Qwen3) يعمل على جهاز الرادار. قد يخطئ، والوصف الأصلي أعلاه هو المرجع.",
            "Machine-written by a language model (Qwen3) running on the radar machine. It can be wrong; the original description above is the reference.")
        : L("ملخص مبني من بيانات الثغرة نفسها (الدرجة والمنتج)، بلا نموذج لغوي.", "Built from the vulnerability's own data (score and product), without a language model.")));
    } else {
      var n = R.el("div", "notice"); n.style.setProperty("--c", "var(--s-medium)");
      n.appendChild(R.el("b", null, it.sumSrc === "failed" ? L("تعذّر إنشاء ملخص عربي موثوق", "No reliable Arabic summary could be produced") : L("الملخص العربي لم يُكتب بعد", "The Arabic summary has not been written yet")));
      n.appendChild(R.el("p", null, it.sumSrc === "failed"
        ? L("رفض فحص الجودة الملخص المقترح (لغة أو أرقام لا تطابق المصدر)، فلم ننشره. اعتمد على الوصف الأصلي.",
            "The quality check rejected the proposed summary (language or numbers that do not match the source), so it was not published. Rely on the original description.")
        : L("سيُضاف في إحدى دورات التحديث القادمة. حتى ذلك الحين اعتمد على الوصف الأصلي.", "It will be added in an upcoming update cycle. Until then, rely on the original description.")));
      sum.appendChild(n);
    }
    box.appendChild(sum);

    var facts = R.el("section", "d-sec");
    facts.appendChild(R.el("h3", null, L("البيانات", "Facts")));
    var dl = R.el("dl", "facts");
    fact(dl, L("التصنيف", "Rating"), R.SEV[sv], it.score != null ? L("حسب سلّم NVD لدرجة CVSS", "NVD's CVSS severity scale") : L("تظهر الدرجة حين تقيّمها NVD", "The score appears once NVD rates it"));
    fact(dl, R.dateLabel(it), R.fmtDate(it.date) || L("غير متوفر", "Not available"));
    var pubN = kevSrc ? fact(dl, L("تاريخ النشر في NVD", "Published in NVD"), "…") : null;
    var mod = fact(dl, L("آخر تحديث في NVD", "Last modified in NVD"), "…");
    var seen = fact(dl, L("رصدها الرادار", "First seen by the radar"), "…");
    fact(dl, L("المنتج المتأثر", "Affected product"), R.el("bdi", null, R.sysName(it.system)),
      kevSrc ? L("من بيانات CISA", "From CISA data") : L("مستخرج آلياً من نص الوصف، تحقق منه في المصدر", "Extracted automatically from the description; verify it at the source"));
    var expl = fact(dl, L("حالة الاستغلال", "Exploitation"), it.kev ? L("ثبت استغلالها بحسب CISA", "Known exploited, per CISA") : L("لا دليل منشور على استغلالها", "No published evidence"),
      it.kev ? null : L("ليست في قائمة CISA للثغرات المستغلة حتى آخر تحديث، وهذا لا يعني أنها آمنة", "Not in CISA's Known Exploited Vulnerabilities list as of the last update. That does not make it safe."));
    fact(dl, L("مصدر الرصد", "Detected via"), R.srcName(it.source));
    var vec = fact(dl, L("متجه CVSS", "CVSS vector"), "…"); vec.parentNode.hidden = true;
    facts.appendChild(dl);
    box.appendChild(facts);

    var kevSec = R.el("section", "d-sec d-kev"); kevSec.hidden = true; box.appendChild(kevSec);

    if (it.advice) {
      var adv = R.el("section", "d-sec");
      adv.appendChild(R.el("h3", null, L("ماذا تفعل", "What to do")));
      adv.appendChild(R.el("p", null, R.ADVICE));
      box.appendChild(adv);
    }

    var links = R.el("footer", "d-links");
    var nvd = "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(id);
    var srcUrl = kevSrc ? R.cisaUrl(id) : R.safeUrl(it.link);
    if (srcUrl) links.appendChild(R.link(R.el("a", "btn primary", kevSrc ? L("المصدر الأصلي (CISA)", "Original source (CISA)") : L("المصدر الأصلي (NVD)", "Original source (NVD)")), srcUrl));
    if (kevSrc) links.appendChild(R.link(R.el("a", "btn", L("صفحة الثغرة في NVD", "NVD entry")), nvd));
    var shareTxt = L("نسخ رابط هذه الصفحة", "Copy link");
    var share = R.el("button", "btn", shareTxt); share.type = "button";
    share.onclick = function () {
      (navigator.clipboard ? navigator.clipboard.writeText(location.href) : Promise.reject()).then(function () { share.textContent = L("نُسخ الرابط", "Link copied"); },
        function () { share.textContent = L("انسخه من شريط العنوان", "Copy it from the address bar"); });
      setTimeout(function () { share.textContent = shareTxt; }, 2500);
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
        if (cv.raw && x.text.indexOf(cv.raw.replace(/\s+$/, "")) === 0) title.hidden = true;
        orig.appendChild(R.el("span", "d-label", kevSrc ? L("الوصف الأصلي من CISA", "Original description from CISA") : L("الوصف الأصلي من NVD", "Original description from NVD")));
        var t = R.el("p", "d-en", x.text); t.setAttribute("dir", "ltr"); t.setAttribute("lang", "en"); orig.appendChild(t);
      } else orig.appendChild(R.el("p", "d-note", L("الوصف الأصلي غير متوفر في بياناتنا. افتح المصدر للاطلاع عليه.", "The original description is not in our data. Open the source to read it.")));
      if (pubN) pubN.textContent = x.nvd_published ? R.fmtDate(x.nvd_published) : L("لم نسجّله بعد", "Not recorded yet");
      mod.textContent = x.modified ? R.fmtDate(x.modified) : L("لم نسجّله بعد", "Not recorded yet");
      if (!x.modified) mod.appendChild(R.el("small", null, L("يُجلب تدريجياً في دورات التحديث", "Fetched gradually during update cycles")));
      seen.textContent = x.seen ? R.fmtDate(x.seen) + L("، الساعة ", ", ") + R.timeF.format(Date.parse(x.seen)) : L("غير مسجّل", "Not recorded");
      renderRisk(rBody, it, x);
      if (x.vector) { vec.textContent = ""; var vb = R.el("bdi", "d-vec", (x.cvss_ver ? "v" + x.cvss_ver + " " : "") + x.vector); vb.setAttribute("dir", "ltr"); vec.appendChild(vb); vec.parentNode.hidden = false; }
      if (it.kev) {
        if (x.kev_added) expl.textContent = L("ثبت استغلالها: أضافتها CISA إلى قائمتها في ", "Known exploited: CISA added it to its list on ") + R.fmtDate(x.kev_added);
        kevSec.hidden = false; kevSec.textContent = "";
        kevSec.appendChild(R.el("h3", null, L("بيانات الاستغلال من CISA", "CISA exploitation data")));
        var kd = R.el("dl", "facts");
        if (x.kev_ransom) fact(kd, L("حملات الفدية", "Ransomware use"), x.kev_ransom === "Known" ? L("استُخدمت في حملات فدية معروفة", "Used in known ransomware campaigns") : L("غير معروف إن استُخدمت في حملات فدية", "Unknown whether used in ransomware campaigns"));
        if (x.kev_due) fact(kd, L("الموعد النهائي للإصلاح", "Remediation due date"), R.fmtDate(x.kev_due), L("حددته CISA للجهات الحكومية الأمريكية", "Set by CISA for US federal agencies"));
        if (x.kev_action) { var ka = R.el("span", "d-en", x.kev_action); ka.setAttribute("dir", "ltr"); ka.setAttribute("lang", "en"); fact(kd, L("الإجراء المطلوب", "Required action"), ka); }
        if (!kd.children.length) kd.appendChild(R.el("p", "d-note", L("تفاصيل CISA لهذه الثغرة لم تُسجَّل بعد.", "CISA details for this vulnerability are not recorded yet.")));
        kevSec.appendChild(kd);
      }
    }).catch(function () {
      if (dlgItem !== it) return;
      orig.textContent = ""; orig.appendChild(R.el("p", "d-note", L("تعذّر تحميل التفاصيل الإضافية (الوصف الأصلي وتاريخ التحديث). البيانات أعلاه من الملف الرئيسي.",
        "Could not load the extra details (original description and update date). The facts above come from the main data file.")));
      mod.textContent = L("غير متوفر", "Not available"); seen.textContent = L("غير متوفر", "Not available");
      rBody.textContent = "";
      if (pubN) pubN.textContent = L("غير متوفر", "Not available");
    });
  };
  // ---------- [CTI] Risk breakdown: each factor, its weight, and the points it adds. Points of known factors sum to the score.
  var AV = { N: L("عبر الشبكة", "over the network"), A: L("من شبكة مجاورة", "from an adjacent network"), L: L("بوصول محلي", "with local access"), P: L("بوصول مادي", "with physical access") };
  function vecText(v) {
    var m = {}; String(v || "").split("/").forEach(function (p) { var kv = p.split(":"); if (kv.length === 2) m[kv[0]] = kv[1]; });
    if (!AV[m.AV]) return "";
    var s = L("الهجوم ", "attack ") + AV[m.AV];
    if (m.AV === "N" && m.PR === "N" && (m.UI === "N" || !m.UI)) s += L(" بلا صلاحيات ولا تفاعل من المستخدم", ", no privileges or user action needed");
    return s;
  }
  function renderRisk(box, it, x) {
    box.textContent = "";
    var f = x.risk_f, ev = x.risk_ev || {};
    if (it.risk == null || !f || typeof f !== "object") {
      box.appendChild(R.el("p", "d-note", it.risk == null ? L("ستُحسب حين تقيّمها NVD أو تُدرجها CISA.", "It will be computed once NVD scores it or CISA lists it.")
        : L("تفاصيل الحساب غير متوفرة في هذه النسخة من البيانات.", "Calculation details are not in this copy of the data.")));
      return;
    }
    function val(k) { var v = f[k]; return Array.isArray(v) && typeof v[0] === "number" ? v[0] : null; }
    function w(k) { var v = f[k]; return Array.isArray(v) && typeof v[1] === "number" ? v[1] : 0; }
    var keys = ["cvss", "exploitation", "exposure", "patch"], total = 0;
    keys.forEach(function (k) { if (val(k) != null) total += w(k); });
    var age = typeof ev.age_days === "number" ? ev.age_days : null;
    var rows = {
      cvss: [L("درجة CVSS", "CVSS score"), val("cvss") != null ? Number(it.score).toFixed(1) + L(" من 10", " of 10") : L("لم تُقيَّم بعد", "Not scored yet")],
      exploitation: [L("الاستغلال", "Exploitation"),
        ev.kev ? L("مؤكد: مدرجة في قائمة CISA", "Confirmed: listed by CISA")
          : ev.exploit === "nvd" ? L("غير مؤكد، لكن يوجد استغلال منشور: رابط موسوم «Exploit» في NVD", "Not confirmed, but a public exploit exists: a reference tagged “Exploit” in NVD")
          : ev.exploit === "cna" ? L("غير مؤكد، لكن يوجد استغلال منشور بحسب وصف الجهة المبلّغة", "Not confirmed, but a public exploit exists per the reporting organisation's description")
          : L("لا استغلال مؤكد ولا استغلال منشور معروف (لا يعني أنها آمنة)", "No confirmed exploitation and no known public exploit (does not make it safe)")],
      exposure: [L("العمر ونطاق التعرض", "Age and exposure"),
        [age != null ? (R.en ? "Published " + R.countL(age, null, ["day", "days"]) + " ago" : age === 0 ? "نُشرت اليوم" : "نُشرت قبل " + R.count(age, "يوم", "يومين", "أيام", "يوماً")) : "", vecText(x.vector)]
          .filter(Boolean).join(R.comma) || L("غير معروف", "Unknown")],
      patch: [L("إصلاح رسمي", "Official fix"), val("patch") === 0 ? L("يوجد رابط إصلاح في NVD (يخفض الأولوية)", "A fix is referenced in NVD (lowers priority)") : L("غير معروف", "Unknown")]
    };
    var tb = R.el("table", "risk-t"), th = R.el("tr");
    [L("العامل", "Factor"), L("القيمة", "Value"), L("الوزن", "Weight"), L("النقاط", "Points")].forEach(function (h) { var c = R.el("th", null, h); c.scope = "col"; th.appendChild(c); });
    var thead = R.el("thead"); thead.appendChild(th); tb.appendChild(thead);
    var tbody = R.el("tbody");
    keys.forEach(function (k) {
      var v = val(k), tr = R.el("tr", v == null ? "off" : null);
      tr.appendChild(R.el("th", null, rows[k][0])).scope = "row";
      tr.appendChild(R.el("td", null, rows[k][1]));
      tr.appendChild(R.el("td", "num", w(k) + "%"));
      tr.appendChild(R.el("td", "num", v == null ? L("غير محسوب", "Not counted") : "+" + R.nf.format(Math.round(1000 * w(k) * v / total) / 10)));
      tbody.appendChild(tr);
    });
    tb.appendChild(tbody);
    var wrap = R.el("div", "risk-tw"); wrap.appendChild(tb); box.appendChild(wrap);
    box.appendChild(R.el("p", "d-note", L("العوامل غير المعروفة لا تُحسب ضدها ولا لها: تُستبعد من الوزن الكلي (", "Unknown factors count neither for nor against: they are left out of the total weight (")
      + total + L("% هنا). المعادلة كاملة في صفحة «عن المشروع».", "% here). The full formula is on the About page.")));
    // Recommended action: fixed rules tied to the facts above, not generated text
    var act = R.el("div", "notice d-act"); act.style.setProperty("--c", "var(--s-" + it.riskLevel + ")");
    act.appendChild(R.el("b", null, L("الإجراء المقترح", "Recommended action")));
    var acts = [];
    if (it.kev) acts.push(L("أولوية قصوى: ثبت أن المهاجمين يستغلونها. طبّق الإجراء الذي تطلبه CISA", "Top priority: attackers are exploiting it. Apply the action CISA requires")
      + (x.kev_due ? L(" قبل ", " by ") + R.fmtDate(x.kev_due) : "") + ".");
    else if (ev.exploit) acts.push(L("افحص بسرعة إن كان المنتج مستخدماً عندك: توجد معلومات استغلال منشورة، فقد يُستغل قريباً.", "Check soon whether you use this product: exploit information is public, so exploitation may follow."));
    if (ev.patch) acts.push(L("يوجد إصلاح رسمي مرجعه في NVD: طبّقه من رابط الشركة أدناه.", "An official fix is referenced in NVD: apply it from the vendor link below."));
    if (!it.kev && !ev.exploit) acts.push(it.riskLevel === "medium"
      ? L("تابعها ضمن دورة التحديثات المعتادة، وطبّق التحديث الرسمي حين يصدر.", "Handle it in your regular patch cycle and apply the official update when available.")
      : L("أولوية منخفضة الآن: راقبها، وأعد تقييمها إن ظهرت معلومات استغلال.", "Low priority for now: keep watching and reassess if exploit information appears."));
    var ul = R.el("ul"); acts.forEach(function (a) { ul.appendChild(R.el("li", null, a)); }); act.appendChild(ul);
    box.appendChild(act);
    // Official vendor links tagged in NVD (patch / advisory / mitigation). Exploit-code links are not linked from here.
    var refs = Array.isArray(x.refs) ? x.refs : [], shown = 0, rl = R.el("ul", "d-refs");
    refs.forEach(function (r) {
      var t = (r && Array.isArray(r.t)) ? r.t : [], u = r && R.safeUrl(r.u);
      if (!u || shown >= 6) return;
      var kind = t.indexOf("Patch") >= 0 ? L("إصلاح", "Patch") : t.indexOf("Vendor Advisory") >= 0 ? L("نشرة الشركة", "Vendor advisory") : t.indexOf("Mitigation") >= 0 ? L("تخفيف", "Mitigation") : null;
      if (!kind) return;
      var li = R.el("li"); li.appendChild(R.el("span", "pill", kind));
      var a = R.link(R.el("a", null, u.replace(/^https?:\/\//, "").slice(0, 70)), u); a.setAttribute("dir", "ltr"); li.appendChild(a);
      rl.appendChild(li); shown++;
    });
    if (shown) { box.appendChild(R.el("h4", null, L("روابط رسمية من NVD", "Official links from NVD"))); box.appendChild(rl); }
  }
  R.closeDetail = function () { if (dlg && dlg.open) closeDlg(); };
  // فتح التفاصيل من رابط مشارَك (#v=CVE-...)
  R.openFromHash = function (byId) {
    var v = R.hashParams().get("v");
    if (v && byId[v] && byId[v].type === "vul") { R.openDetail(byId[v]); return true; }
    return false;
  };

  // ---------- تقرير للطباعة أو الحفظ PDF
  // نبني نسخة مطبوعة من النتائج المعروضة ثم نفتح نافذة الطباعة: «حفظ كـ PDF» فيها يحفظ الخط العربي كما هو
  // (مكتبات PDF في JavaScript تفكك الحروف العربية، والمتصفح يرسمها صحيحة)
  R.printReport = function (list, meta) {
    meta = meta || {};
    var MAX = 500, now = Date.now(), rows = list.slice(0, MAX);
    var old = R.$("print-report"); if (old) old.remove();
    var rep = R.el("div"); rep.id = "print-report"; rep.setAttribute("aria-hidden", "true");
    var head = R.el("header", "pr-head");
    var brand = R.el("div", "pr-brand");
    var logo = R.svg("svg", { viewBox: "0 0 32 32", width: 34, height: 34 });
    logo.appendChild(R.svg("circle", { cx: 16, cy: 16, r: 15, fill: "#0A1428" }));
    logo.appendChild(R.svg("circle", { cx: 16, cy: 16, r: 9, fill: "none", stroke: "#C9A063", "stroke-width": 1.2 }));
    logo.appendChild(R.svg("path", { d: "M16 16 L16 1 A15 15 0 0 1 29 8.5 Z", fill: "#C9A063", opacity: ".6" }));
    brand.appendChild(logo);
    var bt = R.el("div"); bt.appendChild(R.el("b", null, L("رادار التقنية", "Tech Radar"))); bt.appendChild(R.el("span", null, meta.title || L("تقرير الثغرات الأمنية", "Security vulnerability report")));
    brand.appendChild(bt); head.appendChild(brand);
    var info = R.el("dl", "pr-info");
    function row(k, v) { var d = R.el("div"); d.appendChild(R.el("dt", null, k)); d.appendChild(R.el("dd", null, v)); info.appendChild(d); }
    row(L("تاريخ إنشاء التقرير", "Report generated"), R.dateF.format(now) + L("، الساعة ", ", ") + R.timeF.format(now));
    if (meta.genAt) row(L("آخر تحديث للبيانات", "Data last updated"), R.dateF.format(meta.genAt) + L("، الساعة ", ", ") + R.timeF.format(meta.genAt));
    row(L("نطاق التقرير", "Scope"), meta.scope || L("كل ما في الموقع", "Everything on the site"));
    row(L("عدد العناصر", "Items"), R.nf.format(list.length) + (list.length > MAX ? L(" (أول ", " (first ") + MAX + L(" في هذا التقرير)", " in this report)") : ""));
    head.appendChild(info); rep.appendChild(head);

    // ملخص المستويات: الخطورة والاستغلال منفصلان
    var vul = rows.filter(function (it) { return it.type === "vul"; });
    if (vul.length) {
      var sum = R.el("ul", "pr-sum");
      R.SEV_ORDER.forEach(function (s) {
        var n = vul.filter(function (it) { return R.sevOf(it) === s; }).length;
        if (!n) return;
        var li = R.el("li"); li.style.setProperty("--c", "var(--p-" + s + ")");
        li.appendChild(R.el("b", null, R.nf.format(n))); li.appendChild(R.el("span", null, R.SEV[s])); sum.appendChild(li);
      });
      var k = vul.filter(function (it) { return it.kev; }).length;
      var lk = R.el("li", "kev"); lk.appendChild(R.el("b", null, R.nf.format(k))); lk.appendChild(R.el("span", null, L("ثبت استغلالها (CISA)", "Known exploited (CISA)"))); sum.appendChild(lk);
      rep.appendChild(sum);
    }

    var tb = R.el("table", "pr-table"), th = R.el("thead"), tr = R.el("tr");
    [L("#", "#"), L("العنصر", "Item"), L("المنتج المتأثر", "Affected product"), "CVSS", L("الخطورة", "Severity"), L("درجة الخطر", "Risk"), L("الاستغلال", "Exploitation"), L("التاريخ", "Date"), L("رابط المصدر", "Source link")]
      .forEach(function (h) { tr.appendChild(R.el("th", null, h)); });
    th.appendChild(tr); tb.appendChild(th);
    var body = R.el("tbody");
    rows.forEach(function (it, i) {
      var sv = R.sevOf(it), cv = R.splitCve(it), r = R.el("tr");
      r.appendChild(R.el("td", "n", R.nf.format(i + 1)));
      var c = R.el("td", "it");
      if (cv.id) c.appendChild(R.el("b", "cve", cv.id)); else c.appendChild(R.el("b", null, R.TYPES[it.type]));
      var t = R.el("span", "t", cv.rest || it.title); t.setAttribute("dir", "auto"); c.appendChild(t);
      if (!R.en && it.summary && it.sumSrc === "llm") { var s2 = R.el("span", "s", "ملخص آلي: " + it.summary); c.appendChild(s2); }
      r.appendChild(c);
      r.appendChild(R.el("td", null, it.type === "vul" ? R.sysName(it.system) : "—"));
      r.appendChild(R.el("td", "num", it.score != null ? Number(it.score).toFixed(1) : "—"));
      var sc = R.el("td"); if (sv) { var p = R.el("span", "pill", R.SEV[sv]); p.style.setProperty("--c", "var(--p-" + sv + ")"); sc.appendChild(p); } else sc.textContent = "—";
      r.appendChild(sc);
      r.appendChild(R.el("td", "num", it.type !== "vul" ? "—" : it.risk != null ? it.risk + " · " + R.RISK[it.riskLevel] : R.RISK.unknown));
      r.appendChild(R.el("td", it.kev ? "kev" : "muted", it.type !== "vul" ? "—" : it.kev ? L("ثبت استغلالها", "Known exploited") : L("لا دليل منشور", "No evidence")));
      r.appendChild(R.el("td", "num", R.fmtDate(it.date) || "—"));
      var u = it.type === "vul" ? "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(cv.id || it.id) : R.safeUrl(it.link);
      var lc = R.el("td", "url"); if (u) { var a = R.el("a", null, u.replace(/^https?:\/\//, "")); a.href = u; lc.appendChild(a); } r.appendChild(lc);
      body.appendChild(r);
    });
    tb.appendChild(body); rep.appendChild(tb);
    rep.appendChild(R.el("p", "pr-note", L("درجات CVSS منقولة من قاعدة NVD الأمريكية، وحالة الاستغلال من قائمة وكالة CISA. الخطورة والاستغلال أمران منفصلان. درجة الخطر (من 100) أولوية تصرف يحسبها الرادار بمعادلة منشورة في صفحة «عن المشروع». الملخصات العربية يكتبها نموذج آلي وقد تخطئ، والمرجع هو رابط المصدر.",
      "CVSS scores come from the US NVD database and exploitation status from CISA's list; severity and exploitation are separate facts. The risk score (out of 100) is a priority computed by the radar with a formula published on the About page. Arabic summaries are machine-written and can be wrong; the source link is the reference.")));
    rep.appendChild(R.el("p", "pr-note", "nfalqhtan-hue.github.io/radar"));
    document.body.appendChild(rep);
    R.closeDetail();
    var t0 = document.title;
    document.title = (R.en ? "tech-radar-report-" : "تقرير-رادار-التقنية-") + new Date(now).toISOString().slice(0, 10);
    var restore = function () { document.title = t0; window.removeEventListener("afterprint", restore); };
    window.addEventListener("afterprint", restore);
    // print() ينتظر حتى تُغلق نافذة الطباعة في المتصفحات الحديثة، فنعيد العنوان بعدها (و afterprint احتياط)
    setTimeout(function () { window.print(); restore(); }, 50);
  };

  // ---------- رسالة خطأ موحدة مع زر إعادة المحاولة
  R.errorNotice = function (box, err, retry) {
    box.textContent = "";
    var n = R.el("div", "notice error"); n.setAttribute("role", "alert");
    n.appendChild(R.el("b", null, L("تعذّر تحميل البيانات", "Could not load the data")));
    var local = location.protocol === "file:";
    n.appendChild(R.el("p", null, local
      ? L("فتحت الصفحة كملف من جهازك، والمتصفح يمنع قراءة البيانات بهذه الطريقة. شغّلها عبر خادم محلي (python -m http.server داخل مجلد site).",
          "You opened the page as a local file, and the browser blocks reading data that way. Serve it locally (python -m http.server inside the site folder).")
      : (String(err && err.message) === "bad-format"
        ? L("ملف البيانات وصل بصيغة غير متوقعة. سيُصلَح مع التحديث القادم.", "The data file arrived in an unexpected format. The next update should fix it.")
        : L("تحقق من اتصالك بالإنترنت ثم أعد المحاولة.", "Check your internet connection, then try again."))));
    if (retry && !local) {
      var b = R.el("button", "btn", L("أعد المحاولة", "Try again")); b.type = "button";
      b.onclick = retry; n.appendChild(b);
    }
    box.appendChild(n);
  };

  // ---------- Visit counter (GoatCounter, account "mr7con"): one image request per page view. No cookies, no script from
  // a third party, nothing stored in the browser. It sends only the page path, its title, the referring site and the
  // screen width. Skipped outside the published site (local testing) and when the browser asks not to be tracked.
  try {
    if (location.hostname === "nfalqhtan-hue.github.io" && navigator.doNotTrack !== "1") {
      var cq = new URLSearchParams();
      cq.set("p", location.pathname); cq.set("t", document.title);
      if (document.referrer && document.referrer.indexOf(location.origin) !== 0) cq.set("r", document.referrer);
      cq.set("s", String(screen.width)); cq.set("rnd", Math.random().toString(36).slice(2));
      var px = new Image(); px.referrerPolicy = "strict-origin-when-cross-origin";
      px.src = "https://mr7con.goatcounter.com/count?" + cq.toString();
    }
  } catch (e) {}
})();
