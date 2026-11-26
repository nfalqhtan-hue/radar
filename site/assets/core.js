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
      advice: str(it.advice, 400), kev: it.kev === true
    };
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
