/* رادار التقنية: صفحة الإحصائيات (كل الأرقام من stats.json الذي يحسبه الوكيل من قاعدة البيانات كاملة) */
(function () {
  "use strict";
  var R = window.Radar, $ = R.$, el = R.el, nf = R.nf, L = R.L;
  // الرسم الزمني بتوقيت السعودية أياً كان توقيت جهاز الزائر (الأيام والساعات تُحسب في الوكيل بالتوقيت نفسه)
  var loc = R.en ? "en-US" : "ar-SA-u-nu-latn-ca-gregory", TZ = "Asia/Riyadh";
  var pf = new Intl.NumberFormat(R.en ? "en-US" : "ar-SA-u-nu-latn", { style: "percent", maximumFractionDigits: 0 });
  var hourF = new Intl.DateTimeFormat(loc, { hour: "numeric", timeZone: TZ });
  var dayShort = new Intl.DateTimeFormat(loc, { day: "numeric", month: "short", timeZone: TZ });
  var dayLong = new Intl.DateTimeFormat(loc, { weekday: "long", day: "numeric", month: "long", timeZone: TZ });
  var S = null, range = "hour";

  function num(v) { return typeof v === "number" && isFinite(v) && v >= 0 ? v : 0; }

  // شريط أفقي واحد: الاسم + الشريط + العدد والنسبة
  function hbar(list, label, n, total, opts) {
    opts = opts || {};
    var li = el("li"), row = el(opts.href ? "a" : "div", "hbar");
    if (opts.href) row.href = opts.href;
    if (opts.color) row.style.setProperty("--c", opts.color);
    // dir=auto: الاسم الإنجليزي يُقص من نهايته («Ruckus Smart Gate…») لا من بدايته
    var lab = el("span", "lab", label); lab.setAttribute("dir", "auto"); lab.title = label; row.appendChild(lab);
    var tr = el("span", "track"), fill = el("span", "fill");
    fill.style.width = (total ? Math.max(n / total * 100, n ? 1.5 : 0) : 0) + "%"; tr.appendChild(fill); row.appendChild(tr);
    var v = el("span", "val"); v.appendChild(el("b", null, nf.format(n)));
    if (opts.pct !== false && total) v.appendChild(document.createTextNode(" · " + pf.format(n / total)));
    row.appendChild(v);
    li.appendChild(row); list.appendChild(li);
  }
  function bars(id, pairs, opts) {
    var ul = $(id); ul.textContent = "";
    var total = pairs.reduce(function (a, p) { return a + p[1]; }, 0), max = Math.max.apply(null, pairs.map(function (p) { return p[1]; }).concat([1]));
    pairs.forEach(function (p) { hbar(ul, p[0], p[1], (opts && opts.relMax) ? max : total, Object.assign({}, opts, p[2] || {})); });
    if (!pairs.length) ul.appendChild(el("li", "s-note", L("لا توجد بيانات بعد.", "No data yet.")));
  }

  function renderKpis() {
    var v = S.vulns;
    $("k-total").textContent = nf.format(num(v.total));
    $("k-24").textContent = nf.format(num(v.last24));
    $("k-7").textContent = nf.format(num(v.last7));
    $("k-kev").textContent = nf.format(num(v.kev));
    $("k-kev-l").textContent = L("ثبت استغلالها، منها ", "known exploited, ") + nf.format(num(v.kev_critical)) + L(" حرجة", " of them critical");
    var first = Date.parse(S.first_seen);
    $("intro").textContent = R.en
      ? "Computed from everything the radar has tracked" + (first ? " since " + R.dateF.format(first) : "") + ", refreshed every cycle (last computed " + R.ago(Date.parse(S.generated_at)) + ")."
      : "أرقام محسوبة من كل ما رصده الرادار" + (first ? " منذ " + R.dateF.format(first) : "") + "، وتتحدث مع كل دورة (آخر حساب " + R.ago(Date.parse(S.generated_at)) + ").";
  }

  function renderSev() {
    var b = S.vulns.by_sev || {};
    bars("sev", R.SEV_ORDER.map(function (s) {
      return [R.SEV[s], num(b[s]), { color: "var(--s-" + s + ")", href: "./#type=vul&sev=" + s }];
    }));
    // [CTI] risk-level distribution over the whole database (older stats.json files have none)
    var rk = S.vulns.by_risk;
    $("risk").closest("section").querySelectorAll("#risk, #risk + .s-note").forEach(function (n) { n.hidden = !rk; });
    if (!rk) return;
    bars("risk", R.RISK_ORDER.map(function (k) {
      return [R.RISK[k], num(rk[k]), { color: "var(--s-" + k + ")", href: "./#type=vul&r=" + k }];
    }));
    var hi = num(rk.critical) + num(rk.high);
    $("risk-note").textContent = R.en
      ? hi + " vulnerabilities score 70 or more. " + num(S.vulns.public_exploit) + " have public exploit information (NVD tag or the reporter's description)."
      : nf.format(hi) + " ثغرة درجة خطرها 70 فأكثر، و" + nf.format(num(S.vulns.public_exploit)) + " لها معلومات استغلال منشورة (وسم في NVD أو وصف الجهة المبلّغة).";
  }

  // ---------- الرسم الزمني
  function series() {
    if (range === "hour") return (S.hourly || []).map(function (h) {
      var t = Date.parse(h.hour); return { t: t, total: num(h.total), crit: num(h.critical), kev: num(h.kev), label: dayShort.format(t) + R.comma + hourF.format(t) };
    });
    // بالأيام: نبدأ من يوم بدء الرصد، فالأيام قبله ليست صفراً بل لم تُرصد
    var first = Date.parse(S.first_seen), firstDay = first ? new Date(first + 3 * 36e5).toISOString().slice(0, 10) : "";
    return (S.daily || []).filter(function (d) { return d.day >= firstDay; }).map(function (d) {
      var t = Date.parse(d.day + "T12:00:00+03:00"); return { t: t, total: num(d.total), crit: num(d.critical), kev: num(d.kev), label: dayLong.format(t) };
    });
  }
  function renderTime() {
    var data = series(), box = $("cols"), axis = $("cols-axis"), tip = $("tip");
    box.textContent = ""; axis.textContent = "";
    document.querySelectorAll(".seg button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.range === range)); });
    var max = Math.max.apply(null, data.map(function (d) { return d.total; }).concat([1]));
    var first = Date.parse(S.first_seen), anyBefore = false;
    var sum = data.reduce(function (a, d) { return a + d.total; }, 0);
    $("time-note").textContent = range === "hour"
      ? L("عدد الثغرات التي نشرتها NVD في كل ساعة بتوقيت السعودية. الجزء الأحمر من كل عمود هو الحرجة منها.", "Vulnerabilities NVD published each hour, Saudi time. The red part of each bar is the critical ones.")
      : L("عدد الثغرات المنشورة في كل يوم منذ بدأ الرادار الرصد. السجل ما زال قصيراً ويكبر يوماً بعد يوم.", "Vulnerabilities published each day since the radar started tracking. The history is still short and grows daily.");
    var ym = el("span", "ymax", nf.format(max)); box.appendChild(ym);
    data.forEach(function (d, i) {
      // الساعات قبل أول عنصر رصده الرادار ليست صفراً حقيقياً: لم نكن نرصد بعد، فتظهر مخططة
      var before = range === "hour" && first && d.t + 36e5 <= first;
      var c = el("div", "col" + (before ? " gap" : "")), bar = el("div", "bar" + (d.total ? "" : " zero"));
      bar.style.height = (d.total / max * 100) + "%"; c.appendChild(bar);
      if (d.crit) { var cr = el("div", "crit"); cr.style.height = (d.crit / max * 100) + "%"; c.appendChild(cr); }
      function show() {
        tip.textContent = ""; tip.appendChild(el("b", null, d.label));
        if (before) tip.appendChild(document.createTextNode(L("قبل بدء الرصد", "Before tracking began")));
        else tip.appendChild(document.createTextNode(R.en
          ? d.total + " vulnerabilities" + (d.crit ? ", " + d.crit + " critical" : "") + (d.kev ? ", " + d.kev + " exploited" : "")
          : nf.format(d.total) + " ثغرة" + (d.crit ? "، منها " + nf.format(d.crit) + " حرجة" : "") + (d.kev ? "، " + nf.format(d.kev) + " مستغلة" : "")));
        var cb = c.getBoundingClientRect(), pb = box.parentNode.getBoundingClientRect();
        tip.classList.add("show"); c.classList.add("on");
        var x = cb.left - pb.left + cb.width / 2 - tip.offsetWidth / 2;
        tip.style.left = Math.min(Math.max(x, 8), pb.width - tip.offsetWidth - 8) + "px";
        tip.style.top = (cb.top - pb.top + 0) + "px";
      }
      function hide() { tip.classList.remove("show"); c.classList.remove("on"); }
      c.addEventListener("mouseenter", show); c.addEventListener("mouseleave", hide);
      c.addEventListener("click", function () { box.querySelectorAll(".col.on").forEach(function (x) { x.classList.remove("on"); }); show(); });
      if (before) anyBefore = true;
      box.appendChild(c);
      // تسمية المحور: كل 6 ساعات، أو كل يوم
      var every = range === "hour" ? 6 : Math.max(1, Math.ceil(data.length / 8));
      if (i % every === 0) {
        var s = el("span", null, range === "hour" ? hourF.format(d.t) : dayShort.format(d.t));
        s.style.insetInlineStart = ((i + 0.5) / data.length * 100) + "%"; axis.appendChild(s);
      }
    });
    box.setAttribute("aria-label", R.en
      ? (range === "hour" ? "Vulnerabilities published per hour, last 48 hours" : "Vulnerabilities published per day") + ", total " + sum + ", peak " + max + ". Details in the table below the chart."
      : (range === "hour" ? "الثغرات المنشورة بالساعة في آخر 48 ساعة" : "الثغرات المنشورة باليوم") + "، المجموع " + nf.format(sum) + "، أعلى قيمة " + nf.format(max) + ". التفاصيل في الجدول أسفل الرسم.");
    var lg = box.parentNode.querySelector(".legend");
    if (!lg) { lg = el("div", "legend"); axis.after(lg); }
    lg.textContent = "";
    var keys = [["var(--chart)", L("كل الثغرات", "All vulnerabilities")], ["var(--s-critical)", L("منها حرجة", "of which critical")]];
    if (anyBefore) keys.push(["repeating-linear-gradient(135deg, transparent 0 3px, var(--muted) 3px 4px)", L("قبل بدء الرصد", "Before tracking began")]);
    keys.forEach(function (x) { var s = el("span"); var i = el("i"); i.style.background = x[0]; s.appendChild(i); s.appendChild(document.createTextNode(x[1])); lg.appendChild(s); });
    // الجدول البديل
    var t = $("t-time"); t.textContent = "";
    var tw = el("div", "tw"), tb = el("table"), th = el("tr");
    [range === "hour" ? L("الساعة", "Hour") : L("اليوم", "Day"), L("الثغرات", "Vulnerabilities"), L("حرجة", "Critical"), L("مستغلة", "Exploited")].forEach(function (h) { th.appendChild(el("th", null, h)); });
    tb.appendChild(th);
    data.slice().reverse().forEach(function (d) {
      var tr = el("tr"); [d.label, d.total, d.crit, d.kev].forEach(function (x) { tr.appendChild(el("td", null, typeof x === "number" ? nf.format(x) : x)); }); tb.appendChild(tr);
    });
    tw.appendChild(tb); t.appendChild(tw);
  }

  function renderSystems() {
    var top = (S.top_systems || []).filter(function (x) { return x && typeof x.name === "string"; });
    $("sys-note").textContent = R.en
      ? "The product is extracted automatically from each description; we identified it for " + num(S.vulns.with_system) + " of " + num(S.vulns.total) + " vulnerabilities. Bar lengths are relative to the most frequent."
      : "المنتج مستخرج آلياً من نص وصف الثغرة، وتعرّفنا عليه في " + nf.format(num(S.vulns.with_system)) + " من " + nf.format(num(S.vulns.total)) + " ثغرة. الأطوال نسبة إلى الأكثر ظهوراً.";
    bars("sys", top.map(function (x) { return [x.name, num(x.n), { href: "./#type=vul&q=" + encodeURIComponent(x.name.slice(0, 80)) }]; }), { relMax: true, pct: false });
  }

  function renderNews() {
    var n = S.news || {};
    $("n-total").textContent = nf.format(num(n.total)); $("n-24").textContent = nf.format(num(n.last24)); $("n-7").textContent = nf.format(num(n.last7));
    var bt = n.by_type || {}, bs = n.by_source || {};
    bars("n-type", R.TYPE_ORDER.filter(function (t) { return t !== "vul" && bt[t]; }).map(function (t) { return [R.TYPES[t], num(bt[t]), { href: "./#type=" + t }]; }));
    bars("n-src", Object.keys(bs).sort(function (a, b) { return bs[b] - bs[a]; }).map(function (s) { return [R.srcName(s), num(bs[s])]; }));
  }

  // [CTI] pillar 3: security updates (stats.json "updates"; older files have none, so the card stays hidden)
  function renderUpdates() {
    var u = S.updates; if (!u) return;
    $("upd-card").hidden = false;
    $("u-total").textContent = nf.format(num(u.total)); $("u-7").textContent = nf.format(num(u.last7)); $("u-act").textContent = nf.format(num(u.action));
    var bv = u.by_vendor || {}, bt = u.by_utype || {};
    bars("u-vendor", Object.keys(bv).sort(function (a, b) { return num(bv[b]) - num(bv[a]); }).map(function (v) {
      return [v, num(bv[v]), { href: "updates.html#vendor=" + encodeURIComponent(v) }]; }));
    bars("u-type", ["patch", "advisory", "release"].filter(function (t) { return bt[t]; }).map(function (t) {
      return [R.UTYPE[t], num(bt[t]), { href: "updates.html#tab=" + t }]; }));
  }
  function renderSums() {
    var LB = R.en ? { llm: "Language model, passed the check", template: "Built from the vulnerability data", failed: "Rejected by the check, not published", pending: "Waiting to be summarized" }
      : { llm: "نموذج لغوي، اجتاز الفحص", template: "مبني من بيانات الثغرة", failed: "رفضه فحص الجودة فلم يُنشر", pending: "بانتظار التلخيص" };
    var C = { llm: "var(--chart)", template: "var(--s-unknown)", failed: "var(--s-high)", pending: "var(--muted)" };
    function one(id, o) {
      o = o || {};
      bars(id, ["llm", "template", "failed", "pending"].filter(function (k) { return num(o[k]); }).map(function (k) { return [LB[k], num(o[k]), { color: C[k] }]; }));
    }
    one("sum-v", (S.summaries || {}).vuln); one("sum-n", (S.summaries || {}).news);
  }

  document.querySelectorAll(".seg button").forEach(function (b) { b.onclick = function () { range = b.dataset.range; renderTime(); }; });
  var rz; window.addEventListener("resize", function () { clearTimeout(rz); rz = setTimeout(function () { $("tip").classList.remove("show"); }, 100); });

  R.status("loading");
  fetch("stats.json", { cache: "no-cache" })
    .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then(function (d) {
      if (!d || !d.vulns || !Array.isArray(d.hourly)) throw new Error("bad-format");
      S = d; R.status("ok", Date.parse(d.generated_at) || Date.now());
      $("dash").hidden = false;
      renderKpis(); renderSev(); renderTime(); renderSystems(); renderNews(); renderSums(); renderUpdates();
    })
    .catch(function (err) { R.status("error"); R.errorNotice($("state"), err, function () { location.reload(); }); });
})();
