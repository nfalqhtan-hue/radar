/* Tech Radar assistant. It answers from the radar's own published files (data, details, trends, map, reports) and
   never from invented text: every record it shows carries its date and source link. Model-written Arabic summaries are
   labelled as such, and the short glossary explanations are labelled "general explanation". It is a search-and-summarise
   assistant over the radar's data, not a free-form chat model: GitHub Pages cannot run a model or keep a secret key. */
(function () {
  "use strict";
  var R = window.Radar; if (!R) return;
  var el = R.el, L = R.L, nf = R.nf, norm = R.norm;
  var KEY = "radar-assistant", D = null, loading = null, history = [];
  try { history = JSON.parse(sessionStorage.getItem(KEY) || "[]"); if (!Array.isArray(history)) history = []; } catch (e) { history = []; }
  function save() { try { sessionStorage.setItem(KEY, JSON.stringify(history.slice(-30))); } catch (e) {} }

  // ---------- data: loaded once, on first use
  function getJSON(u) { return fetch(u, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(u + ": HTTP " + r.status); return r.json(); }); }
  function load() {
    if (D) return Promise.resolve(D);
    if (loading) return loading;
    loading = Promise.all([
      R.load(),                                                   // same fetch + field validation as every page
      getJSON("trends.json").catch(function () { return null; }),
      getJSON("map.json").catch(function () { return null; }),
      getJSON("reports/index.json").catch(function () { return null; })
    ]).then(function (a) {
      D = { gen: a[0].genAt, items: a[0].items, trends: a[1], map: a[2], reports: a[3] };
      return D;
    }).catch(function (e) { loading = null; throw e; });
    return loading;
  }

  // ---------- helpers
  var DAY = 864e5;
  function riyadhDay(t) { return new Date(t + 3 * 36e5).toISOString().slice(0, 10); }
  function vulns() { return D.items.filter(function (i) { return i.type === "vul"; }); }
  function within(list, ms) { return list.filter(function (i) { return D.gen - i.t <= ms && i.t <= D.gen + 36e5; }); }
  function byRisk(a, b) { return R.riskRank(b) - R.riskRank(a) || (b.score || 0) - (a.score || 0) || b.t - a.t; }
  function vItem(v) {
    var cv = R.splitCve(v);
    return { title: (cv.id || v.id) + "  " + (cv.rest || ""), href: "./#v=" + encodeURIComponent(v.id), internal: true,
      meta: [R.SEV[v.severity] + (v.score != null ? " " + Number(v.score).toFixed(1) : ""), v.risk != null ? L("خطر ", "risk ") + v.risk : R.RISK.unknown,
        v.kev ? L("ثبت استغلالها (CISA)", "known exploited (CISA)") : null, R.sysName(v.system), R.fmtDate(v.date)].filter(Boolean).join(" · "),
      sub: !R.en && v.sumSrc === "llm" ? v.summary : "", subLabel: !R.en && v.sumSrc === "llm" ? "ملخص آلي (Qwen3)" : "" };
  }
  function nItem(n) {
    return { title: n.title, href: R.safeUrl(n.link), meta: [R.TYPES[n.type], R.srcName(n.source), R.fmtDate(n.date)].filter(Boolean).join(" · "),
      sub: !R.en && n.sumSrc === "llm" ? n.summary : "", subLabel: !R.en && n.sumSrc === "llm" ? "ملخص آلي (Qwen3)" : "" };
  }
  function uItem(u) {
    return { title: u.system + ": " + u.title, href: R.safeUrl(u.link),
      meta: [R.UTYPE[u.utype], u.fixed ? L("الإصدار المصحح ", "fixed in ") + u.fixed : null, u.action ? L("تحتاج تصرفاً", "act now") : null, R.fmtDate(u.date)].filter(Boolean).join(" · ") };
  }
  function src(text) { return { t: "note", text: text }; }
  function P(text) { return { t: "p", text: text }; }
  function items(list) { return { t: "items", items: list }; }
  function general(text) { return { t: "general", text: text }; }
  var FROM_DATA = L("من بيانات الرادار المنشورة، آخر تحديث ", "From the radar's published data, last updated ");
  function stamp() { return src(FROM_DATA + R.at(D.gen) + L(". افتح أي عنصر لمصدره الأصلي.", ". Open any item for its original source.")); }

  // ---------- glossary (general explanations, labelled as such)
  var GLOSS = [
    [["cve"], L("CVE رقم تعريف عالمي لكل ثغرة معلنة (مثل CVE-2026-1234). لا يقول شيئاً عن خطورتها، هو اسمها فقط.", "A CVE is a global identifier for each disclosed vulnerability (e.g. CVE-2026-1234). It names the flaw; it says nothing about how severe it is.")],
    [["cvss"], L("CVSS مقياس من 0 إلى 10 لخطورة الثغرة الفنية: 9 فأكثر حرجة، و7 إلى 8.9 عالية، و4 إلى 6.9 متوسطة. لا يقول إن كانت تُستغل فعلاً.", "CVSS scores a vulnerability's technical severity from 0 to 10: 9+ critical, 7 to 8.9 high, 4 to 6.9 medium. It does not say whether it is being exploited.")],
    [["kev", "cisa"], L("قائمة KEV من وكالة CISA الأمريكية تضم الثغرات التي ثبت أن المهاجمين استغلوها فعلاً. ثغرة فيها أولوية تحديث أولى أياً كانت درجتها.", "CISA's KEV catalog lists vulnerabilities attackers are known to have exploited. Anything in it is a first patching priority, whatever its score.")],
    [["cwe"], L("CWE تصنيف لنوع الضعف البرمجي الذي سبّب الثغرة، مثل حقن SQL (CWE-89) أو حقن السكربت XSS (CWE-79).", "CWE classifies the kind of software weakness behind a vulnerability, such as SQL injection (CWE-89) or XSS (CWE-79).")],
    [["nvd"], L("NVD قاعدة الثغرات الوطنية الأمريكية (NIST)، ومنها نأخذ وصف الثغرة ودرجة CVSS.", "NVD is the US National Vulnerability Database (NIST); the radar takes descriptions and CVSS scores from it.")],
    [["zero-day", "zero day", "0-day", "يوم الصفر", "ثغره صفريه"], L("ثغرة «يوم الصفر» تُستغل قبل أن تعلم بها الشركة أو قبل أن يتوفر إصلاح.", "A zero-day is exploited before the vendor knows about it or before a fix exists.")],
    [["درجه الخطر", "risk score"], L("درجة الخطر في الرادار (من 100) أولوية تصرف: 35% من CVSS، و50% من الاستغلال (قائمة CISA أو استغلال منشور)، و10% للعمر ونطاق التعرض، و5% للإصلاح. المعادلة كاملة في صفحة «عن المشروع».", "The radar's risk score (out of 100) is a priority for action: 35% CVSS, 50% exploitation (CISA listing or public exploit), 10% age and exposure, 5% patch. The full formula is on the About page.")],
    [["فديه", "ransomware"], L("برمجيات الفدية تشفّر ملفات الضحية أو تسرقها وتطلب مالاً مقابل إعادتها أو عدم نشرها.", "Ransomware encrypts or steals a victim's files and demands money to restore them or not publish them.")],
    [["تصيد", "phishing"], L("التصيّد خداع المستخدم برسالة أو صفحة مزيفة ليكشف كلمة مروره أو يشغّل ملفاً خبيثاً.", "Phishing tricks a user, through a fake message or page, into giving away a password or running a malicious file.")],
    [["exploit", "استغلال"], L("الاستغلال كود أو طريقة تستخدم الثغرة فعلاً للهجوم. «استغلال منشور» يعني أن تفاصيله متاحة للعامة، و«مستغلة فعلياً» يعني أن هجمات حقيقية وقعت.", "An exploit is code or a method that actually uses a vulnerability to attack. A public exploit means details are available; known exploited means real attacks happened.")],
    [["patch", "تحديث امني", "رقعه"], L("التحديث الأمني إصدار من الشركة يصلح ثغرة. تطبيقه من المصدر الرسمي هو الحل الأساسي لأغلب الثغرات.", "A security patch is a vendor release that fixes a vulnerability. Installing it from the official source is the main remedy for most flaws.")]
  ].map(function (g) { return [g[0].map(norm), g[1]]; });

  // ---------- intents (Arabic and English keywords, matched on normalised text)
  function has(q, words) { return words.some(function (w) { return q.indexOf(norm(w)) >= 0; }); }
  var W = {
    today: ["اليوم", "today", "24 ساعه", "24 hours", "اخر يوم", "last day"],
    week: ["الاسبوع", "اسبوع", "7 ايام", "week", "weekly"],
    worst: ["اخطر", "اهم", "most dangerous", "most severe", "worst", "top", "highest", "اعلي خطر"],
    exploited: ["مستغله", "مستغل", "exploited", "kev", "استغلال فعلي", "تستغل"],
    products: ["منتجات", "المنتج", "الانظمه الاكثر", "products", "most affected", "اكثر تعرض", "الاكثر تاثر"],
    summary: ["لخص", "ملخص", "summar", "اهم الاحداث", "overview", "وش صار", "ايش صار"],
    threats: ["تهديد", "threat", "احداث امنيه", "security events"],
    updates: ["تحديث", "تحديثات", "update", "patch", "نشره", "advisory"],
    news: ["اخبار", "خبر", "news"],
    map: ["دوله", "دول", "منسوب", "country", "countries", "attributed", "خريطه", "map"],
    trend: ["اتجاه", "تزيد", "تنقص", "زياده", "انخفاض", "trend", "increasing", "decreasing", "مقارنه"],
    diff: ["الفرق", "difference", "ما هو", "ما هي", "وش يعني", "ايش يعني", "what is", "what's", "اشرح", "explain", "معني"]
  };
  var TYPES_Q = [["ai", ["ذكاء اصطناعي", "الذكاء", " ai", "artificial intelligence"]], ["sec", ["امنيه", "security news", "اختراقات"]], ["os", ["انظمه التشغيل", "operating system"]], ["dev", ["اجهزه", "جوالات", "devices", "phones"]]];

  function answer(qRaw) {
    var q = " " + norm(qRaw) + " ";
    var cves = (qRaw.toUpperCase().match(/CVE-\d{4}-\d{4,}/g) || []).filter(function (x, i, a) { return a.indexOf(x) === i; });
    if (cves.length) return explainCves(cves);
    // Latin terms must stand alone among Latin letters ("cvss" inside "وcvss" still counts); Arabic terms match as substrings
    var gl = GLOSS.filter(function (g) { return g[0].some(function (k) {
      if (!/^[a-z0-9 .-]+$/.test(k)) return q.indexOf(k) >= 0;
      return new RegExp("(^|[^a-z0-9])" + k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "([^a-z0-9]|$)").test(q);
    }); });
    var asksDef = has(q, W.diff);
    if (gl.length && (asksDef || gl.length > 1 || q.trim().split(/\s+/).length <= 3)) return glossary(gl);
    if (has(q, W.map)) return mapAnswer(q);
    if (has(q, W.exploited) && !has(q, W.updates)) return exploited(q);
    if (has(q, W.products)) return products(q);
    if (has(q, W.trend)) return trendAnswer();
    if (has(q, W.summary) && has(q, W.week)) return weekSummary();
    if (has(q, W.threats) || (has(q, W.summary) && has(q, W.today))) return threats24();
    if (has(q, W.worst) && !has(q, W.updates) && !has(q, W.news)) return worst(has(q, W.week) ? 7 : 1);
    if (has(q, W.updates)) return updatesAnswer(q);
    if (has(q, W.news)) return newsAnswer(q);
    if (has(q, W.summary)) return weekSummary();
    return search(qRaw);
  }

  function explainCves(ids) {
    return R.loadDetails().catch(function () { return {}; }).then(function (det) {
      var out = [];
      ids.slice(0, 3).forEach(function (id) {
        var v = D.items.filter(function (i) { return i.id === id && i.type === "vul"; })[0];
        if (!v) {
          var inUpd = D.items.filter(function (i) { return i.type === "upd" && (i.cves || []).indexOf(id) >= 0; });
          out.push({ t: "h", text: id });
          out.push(P(L("هذه الثغرة ليست في بيانات الرادار المنشورة (نعرض آخر الثغرات وكل المستغلة فعلياً)، فلن أصف تفاصيلها من عندي.", "This vulnerability is not in the radar's published data (we show recent ones and every known-exploited one), so I will not describe it from memory.")));
          if (inUpd.length) { out.push(P(L("لكنها مذكورة في هذا التحديث الرسمي:", "It is, however, mentioned in this official update:"))); out.push(items(inUpd.slice(0, 3).map(uItem))); }
          out.push(items([{ title: L("صفحتها في NVD", "Its NVD entry"), href: "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(id), meta: L("المصدر الرسمي", "Official source") }]));
          return;
        }
        var x = det[id] || {}, cv = R.splitCve(v);
        out.push({ t: "h", text: id + (v.system ? " · " + R.sysName(v.system) : "") });
        out.push(P(L("الخطورة: ", "Severity: ") + R.SEV[v.severity] + (v.score != null ? " (CVSS " + Number(v.score).toFixed(1) + ")" : "")
          + L(". درجة الخطر: ", ". Risk score: ") + (v.risk != null ? v.risk + L(" من 100، ", "/100, ") + R.RISK[v.riskLevel] : R.RISK.unknown)
          + L(". الاستغلال: ", ". Exploitation: ") + (v.kev ? L("ثبت استغلالها حسب CISA", "known exploited per CISA") + (x.kev_added ? L(" منذ ", " since ") + R.fmtDate(x.kev_added) : "")
            : (x.risk_ev && x.risk_ev.exploit) ? L("غير مؤكد، لكن تفاصيل استغلالها منشورة", "not confirmed, but exploit details are public") : L("لا دليل منشور", "no published evidence")) + "."));
        if (!R.en && v.sumSrc === "llm" && v.summary) out.push({ t: "quote", label: "ملخص آلي (Qwen3)، قد يخطئ", text: v.summary });
        if (x.text) out.push({ t: "quote", label: L("الوصف الأصلي من ", "Original description from ") + (v.source === "CISA KEV" ? "CISA" : "NVD"), text: x.text.slice(0, 700), ltr: true });
        else if (cv.rest) out.push({ t: "quote", label: L("من عنوانها في NVD", "From its NVD title"), text: cv.rest, ltr: true });
        if (v.kev && x.kev_action) out.push(P(L("الإجراء الذي تطلبه CISA: ", "CISA's required action: ") + x.kev_action + (x.kev_due ? L(" (قبل ", " (by ") + R.fmtDate(x.kev_due) + ")" : "")));
        out.push(items([vItem(v)].map(function (i) { i.title = L("افتح صفحة الثغرة في الرادار", "Open it in the radar"); i.sub = ""; return i; })
          .concat([{ title: L("المصدر الأصلي (NVD)", "Original source (NVD)"), href: "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(id), meta: L("نُشرت ", "Published ") + (R.fmtDate(x.nvd_published || v.date) || "—") }])));
      });
      out.push(stamp());
      return out;
    });
  }
  function glossary(gl) {
    var out = gl.slice(0, 3).map(function (g) { return general(g[1]); });
    out.push(src(L("هذا شرح عام للمصطلح، وليس معلومة عن ثغرة بعينها. اسأل عن رقم CVE لترى بياناته.", "This is a general explanation, not information about a specific vulnerability. Ask about a CVE number to see its data.")));
    return out;
  }
  function worst(days) {
    var list = within(vulns(), days * DAY).filter(function (v) { return v.source === "NVD" || v.kev; }).sort(byRisk);
    if (!list.length) return [P(L("لم يُنشر في هذه الفترة شيء ضمن ما رصده الرادار.", "Nothing was published in this period in what the radar tracked.")), stamp()];
    var top = list[0];
    return [P((days === 1 ? L("أخطر ثغرة في آخر 24 ساعة حسب درجة الخطر: ", "Highest-risk vulnerability in the last 24 hours: ") : L("أخطر الثغرات في آخر 7 أيام حسب درجة الخطر: ", "Highest-risk vulnerabilities in the last 7 days: "))
      + R.splitCve(top).id + (top.risk != null ? " (" + top.risk + L(" من 100)", "/100)") : "") + L(" في ", " in ") + R.sysName(top.system) + "."),
      items(list.slice(0, 5).map(vItem)),
      src(L("درجة الخطر تجمع CVSS وثبوت الاستغلال ومعلومات الاستغلال المنشورة وعمر الثغرة. ", "The risk score combines CVSS, confirmed exploitation, public exploit information and age. ") + FROM_DATA + R.at(D.gen) + ".")];
  }
  function exploited() {
    var k = vulns().filter(function (v) { return v.kev; }).sort(function (a, b) { return b.t - a.t; });
    if (!k.length) return [P(L("لا توجد في بيانات الرادار الآن ثغرات مدرجة في قائمة CISA.", "There are no CISA-listed vulnerabilities in the radar's data right now.")), stamp()];
    var recent = within(k, 7 * DAY).length;
    return [P(L("نعم. في بيانات الرادار ", "Yes. The radar's data holds ") + R.countL(k.length, ["ثغرة واحدة", "ثغرتان", "ثغرات", "ثغرة"], ["vulnerability", "vulnerabilities"])
      + L(" أدرجتها CISA في قائمة الثغرات المستغلة فعلياً، منها ", " that CISA lists as exploited, ") + nf.format(recent) + L(" أُدرجت في آخر 7 أيام. الأحدث:", " added in the last 7 days. Most recent:")),
      items(k.slice(0, 6).map(vItem)),
      src(L("«مستغلة» هنا تعني مدرجة في قائمة CISA KEV فقط، وهو المصدر الوحيد الذي نقبله لإثبات الاستغلال. ", "“Exploited” here means listed in CISA's KEV only, the one source we accept as proof. ") + FROM_DATA + R.at(D.gen) + ".")];
  }
  function products(q) {
    var T = D.trends, rd = has(q, W.today) ? "1" : has(q, W.week) ? "7" : "30", rk = T && T.ranges && T.ranges[rd];
    if (!rk || !rk.products || !rk.products.length) return [P(L("بيانات ترتيب المنتجات غير متوفرة الآن.", "Product rankings are not available right now.")), stamp()];
    var label = rd === "1" ? L("آخر 24 ساعة", "the last 24 hours") : rd === "7" ? L("آخر 7 أيام", "the last 7 days") : L("آخر 30 يوماً", "the last 30 days");
    return [P(L("أكثر المنتجات ظهوراً في الثغرات خلال ", "Products appearing most in vulnerabilities over ") + label + L(" (من ", " (out of ") + nf.format(rk.total) + L(" ثغرة نُشرت في NVD):", " published in NVD):")),
      items(rk.products.slice(0, 8).map(function (p) { return { title: p[0], meta: R.countL(p[1], ["ثغرة واحدة", "ثغرتان", "ثغرات", "ثغرة"], ["vulnerability", "vulnerabilities"]), href: "./#type=vul&q=" + encodeURIComponent(p[0]), internal: true }; })),
      src(L("المنتج مستخرج آلياً من وصف الثغرة وقد يخطئ. التفاصيل في صفحة «الاتجاهات».", "The product is extracted automatically from the description and can be wrong. More on the Trends page."))];
  }
  function sum(arr, from, to) { var s = 0; for (var i = from; i < to; i++) { if (arr[i] == null) return null; s += arr[i]; } return s; }
  function trendAnswer() {
    var T = D.trends; if (!T || !T.series) return [P(L("بيانات الاتجاهات غير متوفرة الآن.", "Trend data is not available right now.")), stamp()];
    var n = T.days.length, end = n - 1, c = T.series.v_critical, k = T.series.kev_added;
    var c1 = sum(c, end - 7, end), c0 = sum(c, end - 14, end - 7), k1 = sum(k, end - 7, end), k0 = sum(k, end - 14, end - 7);
    function cmp(a, b) { if (a == null || b == null) return L("لا تكفي البيانات للمقارنة", "not enough data to compare"); if (!b) return a ? L("ارتفاع من صفر", "up from zero") : L("بلا تغيير", "no change"); var d = (a - b) / b; return Math.abs(d) < 0.05 ? L("مستقرة تقريباً", "about the same") : (d > 0 ? L("زيادة ", "up ") : L("انخفاض ", "down ")) + Math.round(Math.abs(d) * 100) + "%"; }
    return [P(L("آخر 7 أيام كاملة مقارنة بالسبعة قبلها: الثغرات الحرجة ", "Last 7 complete days vs. the 7 before: critical vulnerabilities ") + (c1 == null ? "—" : nf.format(c1)) + L(" مقابل ", " vs. ") + (c0 == null ? "—" : nf.format(c0)) + " (" + cmp(c1, c0) + ")"
      + L("، وإضافات قائمة CISA ", "; CISA additions ") + (k1 == null ? "—" : nf.format(k1)) + L(" مقابل ", " vs. ") + (k0 == null ? "—" : nf.format(k0)) + " (" + cmp(k1, k0) + ")."),
      items([{ title: L("صفحة الاتجاهات", "Trends page"), href: "trends.html", internal: true, meta: L("رسوم وفترات أخرى", "Charts and other periods") }]),
      src(L("هذه مقارنة تاريخية لما حدث، وليست توقعاً للمستقبل.", "This is a historical comparison, not a forecast."))];
  }
  function threats24() {
    var v = within(vulns(), DAY).sort(byRisk), kev = within(vulns().filter(function (x) { return x.kev; }), 7 * DAY);
    var news = within(D.items.filter(function (i) { return i.type === "sec"; }), DAY).sort(function (a, b) { return b.t - a.t; });
    var upd = within(D.items.filter(function (i) { return i.type === "upd" && i.action; }), 7 * DAY);
    var out = [P(L("أهم ما رصده الرادار في آخر 24 ساعة: ", "What mattered most in the last 24 hours: ") + R.countL(v.length, ["ثغرة واحدة", "ثغرتان", "ثغرات", "ثغرة"], ["new vulnerability", "new vulnerabilities"])
      + L("، منها ", ", ") + nf.format(v.filter(function (x) { return x.severity === "critical"; }).length) + L(" حرجة، و", " critical; ") + nf.format(news.length) + L(" خبراً أمنياً.", " security news items."))];
    if (v.length) { out.push({ t: "h", text: L("الأعلى خطراً", "Highest risk") }); out.push(items(v.slice(0, 3).map(vItem))); }
    if (kev.length) { out.push({ t: "h", text: L("أُدرجت في قائمة CISA (آخر 7 أيام)", "Added to CISA's list (last 7 days)") }); out.push(items(kev.slice(0, 3).map(vItem))); }
    if (upd.length) { out.push({ t: "h", text: L("تحديثات تحتاج تصرفاً (آخر 7 أيام)", "Updates needing action (last 7 days)") }); out.push(items(upd.slice(0, 3).map(uItem))); }
    if (news.length) { out.push({ t: "h", text: L("أخبار أمنية", "Security news") }); out.push(items(news.slice(0, 4).map(nItem))); }
    out.push(src(L("الأخبار منقولة عن مصادرها كما نُشرت، وليست حوادث تحقق منها الرادار. ", "News is quoted as published, not incidents the radar verified. ") + FROM_DATA + R.at(D.gen) + "."));
    return out;
  }
  function weekSummary() {
    var rep = D.reports && Array.isArray(D.reports.reports) ? D.reports.reports.filter(function (r) { return D.gen - Date.parse(r.day + "T12:00:00+03:00") <= 8 * DAY; }) : [];
    var v = within(vulns(), 7 * DAY), out = [];
    var T = D.trends, n = T && T.days ? T.days.length : 0;
    var vt = T ? sum(T.series.v_total, n - 8, n - 1) : null, vc = T ? sum(T.series.v_critical, n - 8, n - 1) : null, ka = T ? sum(T.series.kev_added, n - 8, n - 1) : null;
    out.push(P(L("ملخص آخر 7 أيام كاملة: ", "The last 7 complete days: ") + (vt == null ? "" : R.countL(vt, ["ثغرة واحدة", "ثغرتان", "ثغرات", "ثغرة"], ["vulnerability", "vulnerabilities"]) + L(" نُشرت في NVD، منها ", " published in NVD, ") + nf.format(vc || 0) + L(" حرجة، و", " critical; ") + nf.format(ka || 0) + L(" أضافتها CISA إلى قائمة الاستغلال. ", " added by CISA to its exploited list. "))
      + L("تحديثات أمنية تحتاج تصرفاً: ", "Security updates needing action: ") + nf.format(within(D.items.filter(function (i) { return i.type === "upd" && i.action; }), 7 * DAY).length) + "."));
    out.push({ t: "h", text: L("الأعلى خطراً هذا الأسبوع", "Highest risk this week") }); out.push(items(v.sort(byRisk).slice(0, 4).map(vItem)));
    var news = within(D.items.filter(function (i) { return i.type === "sec"; }), 7 * DAY).sort(function (a, b) { return b.t - a.t; });
    if (news.length) { out.push({ t: "h", text: L("أخبار أمنية بارزة", "Notable security news") }); out.push(items(news.slice(0, 4).map(nItem))); }
    if (rep.length) out.push(items(rep.slice(0, 7).map(function (r) { return { title: L("التقرير اليومي: ", "Daily report: ") + R.fmtDate(r.day), href: "report.html#day=" + r.day, internal: true, meta: R.countL((r.counts || {}).vulns || 0, ["ثغرة واحدة", "ثغرتان", "ثغرات", "ثغرة"], ["vulnerability", "vulnerabilities"]) }; })));
    out.push(stamp());
    return out;
  }
  function updatesAnswer(q) {
    var vendors = ["chrome", "ubuntu", "debian", "cisco", "fortinet", "oracle"];
    var want = vendors.filter(function (v) { return q.indexOf(v) >= 0 || q.indexOf(norm({ chrome: "كروم", ubuntu: "اوبونتو", debian: "ديبيان", cisco: "سيسكو", fortinet: "فورتينت", oracle: "اوراكل" }[v])) >= 0; });
    var list = D.items.filter(function (i) { return i.type === "upd" && (!want.length || want.some(function (w) { return norm(i.system).indexOf(w) >= 0; })); })
      .sort(function (a, b) { return (b.action - a.action) || b.t - a.t; });
    if (!list.length) return [P(L("لا توجد تحديثات مطابقة في بيانات الرادار الآن.", "No matching updates in the radar's data right now.")), stamp()];
    var act = list.filter(function (u) { return u.action; }).length;
    return [P(R.countL(list.length, ["تحديث واحد", "تحديثان", "تحديثات", "تحديثاً"], ["update", "updates"]) + L(" من المصادر الرسمية", " from official sources") + (want.length ? " (" + want.join(", ") + ")" : "")
      + L("، منها ", ", ") + nf.format(act) + L(" تحتاج تصرفاً لأنها تصلح ثغرة مستغلة. الأهم أولاً:", " needing action because they fix an exploited vulnerability. Most important first:")),
      items(list.slice(0, 6).map(uItem)),
      src(L("نعرض رقم الإصدار فقط إذا ذكرته الشركة. ", "Versions are shown only when the vendor states them. ") + FROM_DATA + R.at(D.gen) + ".")];
  }
  function newsAnswer(q) {
    var t = TYPES_Q.filter(function (x) { return has(q, x[1]); })[0];
    var list = D.items.filter(function (i) { return i.type !== "vul" && i.type !== "upd" && (!t || i.type === t[0]); }).sort(function (a, b) { return b.t - a.t; });
    var period = has(q, W.today) ? DAY : has(q, W.week) ? 7 * DAY : 0;
    if (period) list = within(list, period);
    if (!list.length) return [P(L("لا أخبار مطابقة في هذه الفترة.", "No matching news in this period.")), stamp()];
    return [P(L("آخر الأخبار", "Latest news") + (t ? L(" في «", " in “") + R.TYPES[t[0]] + L("»", "”") : "") + ":"), items(list.slice(0, 6).map(nItem)),
      src(L("منقولة عن مصادرها كما نُشرت. الملخصات العربية آلية وقد تخطئ.", "Quoted as published. Arabic summaries are machine-written and can be wrong."))];
  }
  function mapAnswer(q) {
    var M = D.map; if (!M || !M.countries) return [P(L("بيانات الخريطة غير متوفرة الآن.", "Map data is not available right now.")), stamp()];
    var code = Object.keys(M.countries).filter(function (c) { var x = M.countries[c]; return q.indexOf(norm(x.ar)) >= 0 || q.indexOf(norm(x.en)) >= 0; })[0];
    var inc = (M.incidents || []).filter(function (i) { return !code || (i.places || []).some(function (p) { return p.code === code; }); });
    if (!inc.length) return [P(code ? L("لا توجد في آخر 30 يوماً حوادث ذكرت مصادرها ", "In the last 30 days no incident's source named ") + (R.en ? M.countries[code].en : M.countries[code].ar) + L(" صراحة.", " explicitly.") : L("لا حوادث بموقع مذكور صراحة في آخر 30 يوماً.", "No incidents with an explicitly stated location in the last 30 days.")),
      src(L("لا نستنتج الموقع من عناوين IP أو مقار الشركات.", "We never infer location from IP addresses or company headquarters."))];
    return [P(L("حوادث ذكرت مصادرها ", "Incidents whose sources named ") + (code ? (R.en ? M.countries[code].en : M.countries[code].ar) : L("دولة", "a country")) + L(" صراحة (آخر 30 يوماً):", " explicitly (last 30 days):")),
      items(inc.slice(0, 6).map(function (i) {
        var p = (i.places || []).filter(function (x) { return !code || x.code === code; })[0] || {};
        return { title: i.title, href: R.safeUrl(i.link), meta: [(R.en ? (M.countries[p.code] || {}).en : (M.countries[p.code] || {}).ar), p.role === "origin" ? L("منسوب إليها حسب المصدر", "attributed, per the source") : L("مكان الجهة المستهدفة", "where the targets are"), R.srcName(i.source), R.fmtDate(i.date)].filter(Boolean).join(" · "), sub: p.evidence || "", subLabel: L("الدليل من نص الخبر", "Evidence from the article"), ltr: true };
      })),
      items([{ title: L("افتح خريطة التهديدات", "Open the threat map"), href: "map.html" + (code ? "#c=" + code : ""), internal: true }]),
      src(L("نسبة الهجوم إلى دولة ادعاء مصدر الخبر، وليست استنتاجاً من الرادار.", "Attributing an attack to a country is the source's claim, not the radar's finding."))];
  }
  function search(qRaw) {
    var stop = norm("ما هي هل في عن من على الى ثغرات ثغره اخبار عطني ابي the a of in for about is are show me any").split(" ");
    var ts = norm(qRaw).split(/[^\w؀-ۿ.-]+/).filter(function (w) { return w.length > 1 && stop.indexOf(w) < 0; });
    if (!ts.length) return help();
    var hits = D.items.map(function (i) {
      var h = norm([i.id, i.title, i.summary, i.system, i.product, R.srcName(i.source)].join(" ")), s = 0;
      ts.forEach(function (w) { if (h.indexOf(w) >= 0) s++; });
      return { i: i, s: s };
    }).filter(function (x) { return x.s === ts.length || (ts.length > 2 && x.s >= ts.length - 1); })
      .sort(function (a, b) { return b.s - a.s || R.riskRank(b.i) - R.riskRank(a.i) || b.i.t - a.i.t; });
    if (!hits.length) return [P(L("ما وجدت في بيانات الرادار ما يطابق «", "Nothing in the radar's data matches “") + qRaw.slice(0, 80)
      + L("». أجيب فقط مما جمعه الرادار، فجرّب اسم منتج أو رقم CVE أو أحد الأسئلة المقترحة.", "”. I only answer from what the radar collected; try a product name, a CVE number or a suggested question.")), help(), stamp()];
    var v = hits.filter(function (x) { return x.i.type === "vul"; }), u = hits.filter(function (x) { return x.i.type === "upd"; }), n = hits.filter(function (x) { return x.i.type !== "vul" && x.i.type !== "upd"; });
    var out = [P(L("نتائج من بيانات الرادار لـ«", "Results from the radar's data for “") + qRaw.slice(0, 80) + L("»: ", "”: ") + nf.format(v.length) + L(" ثغرة، و", " vulnerabilities, ") + nf.format(u.length) + L(" تحديثاً، و", " updates, ") + nf.format(n.length) + L(" خبراً.", " news items."))];
    if (v.length) { out.push({ t: "h", text: L("ثغرات", "Vulnerabilities") }); out.push(items(v.slice(0, 4).map(function (x) { return vItem(x.i); }))); }
    if (u.length) { out.push({ t: "h", text: L("تحديثات", "Updates") }); out.push(items(u.slice(0, 3).map(function (x) { return uItem(x.i); }))); }
    if (n.length) { out.push({ t: "h", text: L("أخبار", "News") }); out.push(items(n.slice(0, 3).map(function (x) { return nItem(x.i); }))); }
    out.push(stamp());
    return out;
  }
  function help() {
    return { t: "p", text: L("أستطيع: شرح ثغرة برقمها، وعرض أخطر الثغرات اليوم أو هذا الأسبوع، والمستغلة فعلياً، وأكثر المنتجات تأثراً، والتحديثات الأمنية، والأخبار، والاتجاهات، والحوادث حسب الدولة، وشرح مصطلحات مثل CVE وCVSS.",
      "I can explain a CVE by number, list today's or this week's highest-risk vulnerabilities, known-exploited ones, the most affected products, security updates, news, trends, incidents by country, and terms like CVE and CVSS.") };
  }

  // ---------- UI
  var SUGG = R.en
    ? ["What is the most dangerous vulnerability today?", "Top threats in the last 24 hours", "Are there exploited vulnerabilities?", "Which products are most affected?", "What is the difference between CVE and CVSS?", "Summarise this week's security events", "Latest Chrome updates"]
    : ["ما أخطر ثغرة اليوم؟", "ما أهم التهديدات خلال آخر 24 ساعة؟", "هل توجد ثغرات مستغلة فعلياً؟", "ما المنتجات الأكثر تعرضاً للثغرات؟", "ما الفرق بين CVE وCVSS؟", "لخص لي أهم الأحداث الأمنية لهذا الأسبوع", "آخر تحديثات Chrome"];
  var fab, panel, log, input, busy = false;
  function renderBlock(b) {
    if (b.t === "p") return el("p", null, b.text);
    if (b.t === "h") return el("h4", null, b.text);
    if (b.t === "note") return el("p", "as-src", b.text);
    if (b.t === "general") { var g = el("div", "as-gen"); g.appendChild(el("span", "as-tag", L("شرح عام", "General explanation"))); g.appendChild(el("p", null, b.text)); return g; }
    if (b.t === "quote") { var qd = el("div", "as-quote"); qd.appendChild(el("span", "as-tag", b.label)); var qp = el("p", null, b.text); if (b.ltr) { qp.setAttribute("dir", "ltr"); qp.setAttribute("lang", "en"); } qd.appendChild(qp); return qd; }
    if (b.t === "items") {
      var ul = el("ul", "as-items");
      (b.items || []).forEach(function (it) {
        var li = el("li"), href = it.internal ? it.href : R.safeUrl(it.href);
        var a = el(href ? "a" : "span", null, it.title); a.setAttribute("dir", "auto");
        if (href) { a.href = href; if (!it.internal) { a.target = "_blank"; a.rel = "noopener noreferrer"; } }
        li.appendChild(a);
        if (it.meta) li.appendChild(el("small", null, it.meta));
        if (it.sub) { var s = el("span", "as-sub"); if (it.subLabel) s.appendChild(el("b", null, it.subLabel + ": ")); var st = el("span", null, it.sub); if (it.ltr) st.setAttribute("dir", "ltr"); s.appendChild(st); li.appendChild(s); }
        ul.appendChild(li);
      });
      return ul;
    }
    return el("p", null, String(b.text || ""));
  }
  function addMsg(m) {
    var d = el("div", "as-msg " + m.role);
    if (m.role === "user") d.appendChild(el("p", null, m.text));
    else (m.blocks || []).forEach(function (b) { d.appendChild(renderBlock(b)); });
    log.appendChild(d); log.scrollTop = log.scrollHeight;
    return d;
  }
  function ask(text) {
    text = String(text || "").replace(/[\u0000-\u001f]/g, " ").trim().slice(0, 300);
    if (!text || busy) return;
    busy = true; input.value = "";
    var um = { role: "user", text: text }; history.push(um); addMsg(um);
    var wait = el("div", "as-msg bot as-wait"); wait.setAttribute("role", "status"); wait.appendChild(el("span", "as-dots")); wait.appendChild(el("span", "sr", L("جارٍ البحث في بيانات الرادار", "Searching the radar's data")));
    log.appendChild(wait); log.scrollTop = log.scrollHeight;
    load().then(function () { return Promise.resolve(answer(text)); }).then(function (blocks) {
      wait.remove(); var bm = { role: "bot", blocks: blocks }; history.push(bm); addMsg(bm); save();
    }).catch(function () {
      wait.remove();
      var em = { role: "bot", blocks: [P(L("تعذّر تحميل بيانات الرادار، فلا أستطيع الإجابة الآن. تحقق من الاتصال ثم أعد المحاولة.", "Could not load the radar's data, so I cannot answer right now. Check your connection and try again."))] };
      addMsg(em);
    }).then(function () { busy = false; input.focus(); });
  }
  function build() {
    fab = el("button", "as-fab"); fab.type = "button"; fab.setAttribute("aria-haspopup", "dialog"); fab.setAttribute("aria-expanded", "false");
    var ic = R.svg("svg", { width: 22, height: 22, viewBox: "0 0 24 24", "aria-hidden": "true" });
    ic.appendChild(R.svg("path", { d: "M4 5h16v10H9l-5 4V5Z", fill: "none", stroke: "currentColor", "stroke-width": 1.8, "stroke-linejoin": "round" }));
    ic.appendChild(R.svg("circle", { cx: 9, cy: 10, r: 1.2, fill: "currentColor" })); ic.appendChild(R.svg("circle", { cx: 12, cy: 10, r: 1.2, fill: "currentColor" })); ic.appendChild(R.svg("circle", { cx: 15, cy: 10, r: 1.2, fill: "currentColor" }));
    fab.appendChild(ic); fab.appendChild(el("span", null, L("اسأل الرادار", "Ask the radar")));
    panel = el("section", "as-panel"); panel.hidden = true; panel.setAttribute("role", "dialog"); panel.setAttribute("aria-label", L("مساعد الرادار", "Radar assistant"));
    var head = el("header", "as-head");
    var ht = el("div"); ht.appendChild(el("h2", null, L("مساعد الرادار", "Radar assistant")));
    ht.appendChild(el("p", null, L("يجيب من بيانات الرادار ومصادرها فقط، وليس نموذج محادثة حراً.", "Answers only from the radar's data and its sources; it is not a free-form chat model.")));
    head.appendChild(ht);
    var clear = el("button", "as-clear", L("مسح المحادثة", "Clear")); clear.type = "button";
    clear.onclick = function () { history = []; save(); log.textContent = ""; intro(); input.focus(); };
    var close = el("button", "icon-btn", "×"); close.type = "button"; close.setAttribute("aria-label", L("إغلاق", "Close")); close.onclick = toggle;
    var hb = el("div", "as-hb"); hb.appendChild(clear); hb.appendChild(close); head.appendChild(hb);
    log = el("div", "as-log"); log.setAttribute("aria-live", "polite");
    var sug = el("div", "as-sugg");
    SUGG.forEach(function (s) { var b = el("button", null, s); b.type = "button"; b.onclick = function () { ask(s); }; sug.appendChild(b); });
    var form = el("form", "as-form");
    input = el("input"); input.type = "text"; input.maxLength = 300; input.placeholder = L("اكتب سؤالك أو رقم CVE", "Type a question or a CVE number"); input.setAttribute("aria-label", L("سؤالك", "Your question")); input.autocomplete = "off";
    var send = el("button", "btn primary", L("إرسال", "Send")); send.type = "submit";
    form.appendChild(input); form.appendChild(send);
    form.onsubmit = function (e) { e.preventDefault(); ask(input.value); };
    panel.appendChild(head); panel.appendChild(log); panel.appendChild(sug); panel.appendChild(form);
    document.body.appendChild(panel); document.body.appendChild(fab);
    fab.onclick = toggle;
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !panel.hidden) toggle(); });
    if (history.length) history.forEach(addMsg); else intro();
  }
  function intro() { addMsg({ role: "bot", blocks: [P(L("أهلاً. اسألني عن الثغرات والتحديثات الأمنية والأخبار التقنية التي رصدها الرادار. كل إجابة فيها روابط مصادرها وتواريخها.", "Hello. Ask me about the vulnerabilities, security updates and tech news the radar has collected. Every answer links its sources and dates.")), help()] }); }
  function toggle() {
    var open = panel.hidden; panel.hidden = !open; fab.setAttribute("aria-expanded", String(open));
    document.documentElement.classList.toggle("as-open", open);
    if (open) { input.focus(); load().catch(function () {}); } else fab.focus();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", build); else build();
})();
