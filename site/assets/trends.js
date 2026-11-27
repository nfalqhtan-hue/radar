/* Tech Radar: trends & analytics. Reads trends.json (daily series for 90 days + hourly for 48 hours, built by the
   pipeline from stored records). Everything shown is a count of what happened; nothing here forecasts.
   Days before a series' coverage start are null in the data and are drawn as gaps, never as zero. */
(function () {
  "use strict";
  var R = window.Radar, $ = R.$, el = R.el, svg = R.svg, nf = R.nf, L = R.L;
  var T = null, st = { r: "7", from: "", to: "" };
  var pf = new Intl.NumberFormat(R.en ? "en-US" : "ar-SA-u-nu-latn", { style: "percent", maximumFractionDigits: 0 });
  var dayShort = new Intl.DateTimeFormat(R.en ? "en-US" : "ar-SA-u-nu-latn-ca-gregory", { day: "numeric", month: "short" });
  var hourF = new Intl.DateTimeFormat(R.en ? "en-US" : "ar-SA-u-nu-latn-ca-gregory", { hour: "numeric" });

  // Short names for the weakness types that dominate NVD; anything else shows its CWE number
  var CWE = R.en ? {
    "CWE-79": "Cross-site scripting (XSS)", "CWE-89": "SQL injection", "CWE-787": "Out-of-bounds write", "CWE-125": "Out-of-bounds read",
    "CWE-416": "Use after free", "CWE-20": "Improper input validation", "CWE-22": "Path traversal", "CWE-78": "OS command injection",
    "CWE-77": "Command injection", "CWE-352": "Cross-site request forgery (CSRF)", "CWE-434": "Unrestricted file upload",
    "CWE-862": "Missing authorization", "CWE-863": "Incorrect authorization", "CWE-287": "Improper authentication",
    "CWE-306": "Missing authentication", "CWE-476": "NULL pointer dereference", "CWE-190": "Integer overflow",
    "CWE-502": "Unsafe deserialization", "CWE-119": "Memory buffer errors", "CWE-120": "Classic buffer overflow",
    "CWE-121": "Stack buffer overflow", "CWE-122": "Heap buffer overflow", "CWE-200": "Information exposure", "CWE-918": "Server-side request forgery (SSRF)",
    "CWE-94": "Code injection", "CWE-74": "Injection", "CWE-400": "Uncontrolled resource consumption", "CWE-639": "Insecure direct object reference",
    "CWE-284": "Improper access control", "CWE-601": "Open redirect", "CWE-798": "Hard-coded credentials", "CWE-269": "Improper privilege management",
    "CWE-80": "Basic XSS", "CWE-1321": "Prototype pollution", "CWE-362": "Race condition", "CWE-401": "Memory leak", "CWE-770": "Allocation without limits"
  } : {
    "CWE-79": "حقن سكربت في الصفحات (XSS)", "CWE-89": "حقن SQL", "CWE-787": "كتابة خارج حدود الذاكرة", "CWE-125": "قراءة خارج حدود الذاكرة",
    "CWE-416": "استخدام ذاكرة بعد تحريرها", "CWE-20": "تحقق ناقص من المدخلات", "CWE-22": "تجاوز المسار", "CWE-78": "حقن أوامر النظام",
    "CWE-77": "حقن الأوامر", "CWE-352": "تزوير الطلبات (CSRF)", "CWE-434": "رفع ملفات دون قيود",
    "CWE-862": "غياب التحقق من الصلاحية", "CWE-863": "تحقق خاطئ من الصلاحية", "CWE-287": "مصادقة غير سليمة",
    "CWE-306": "غياب المصادقة", "CWE-476": "مؤشر فارغ (NULL)", "CWE-190": "تجاوز سعة الأعداد الصحيحة",
    "CWE-502": "فك تسلسل غير آمن", "CWE-119": "أخطاء حدود الذاكرة", "CWE-120": "تجاوز سعة المخزن المؤقت",
    "CWE-121": "تجاوز سعة المكدس", "CWE-122": "تجاوز سعة الكومة", "CWE-200": "كشف معلومات", "CWE-918": "تزوير الطلبات من الخادم (SSRF)",
    "CWE-94": "حقن الشيفرة", "CWE-74": "الحقن", "CWE-400": "استهلاك الموارد دون ضبط", "CWE-639": "الوصول المباشر غير الآمن للكائنات",
    "CWE-284": "تحكم ناقص في الوصول", "CWE-601": "إعادة توجيه مفتوحة", "CWE-798": "بيانات دخول مكتوبة في الشيفرة", "CWE-269": "إدارة صلاحيات غير سليمة",
    "CWE-80": "حقن سكربت بسيط", "CWE-1321": "تلويث النموذج الأولي", "CWE-362": "حالة تسابق", "CWE-401": "تسرب الذاكرة", "CWE-770": "حجز موارد بلا حدود"
  };

  // ---------- windows: a list of point indexes for the chosen period, and the same-length period before it
  function window_() {
    var days = T.days, n = days.length;
    if (st.r === "1") return { hourly: true, cur: range(24, 48), prev: range(0, 24), len: 24 };
    var last = n - 2;                             // complete days only: yesterday is the last full day
    if (st.r === "custom") {
      var a = days.indexOf(st.from), b = days.indexOf(st.to);
      if (a < 0 || b < 0 || a > b) return null;
      var len = b - a + 1;
      return { cur: range(a, b + 1), prev: a - len >= 0 ? range(a - len, a) : null, len: len, custom: true };
    }
    var d = +st.r, s = last - d + 1;
    return { cur: range(Math.max(0, s), last + 1), prev: s - d >= 0 ? range(s - d, s) : null, len: d };
  }
  function range(a, b) { var o = []; for (var i = a; i < b; i++) o.push(i); return o; }
  function ser(key) { return window_().hourly ? (T.hourly[key] || []) : (T.series[key] || []); }
  // sum of a series over indexes; null when any day in the window was not observed
  function total(arr, idx) {
    if (!idx || !arr) return null;
    var s = 0;
    for (var i = 0; i < idx.length; i++) { var v = arr[idx[i]]; if (v == null) return null; s += v; }
    return s;
  }
  // like total(), but counts only observed points; returns {n, from} or null when nothing was observed
  function partial(keys, idx, hourly) {
    if (!idx) return null;
    var n = 0, from = null;
    for (var j = 0; j < idx.length; j++) {
      var ok = true, t = 0;
      for (var k = 0; k < keys.length; k++) { var a = hourly ? T.hourly[keys[k]] : T.series[keys[k]]; var v = a ? a[idx[j]] : null; if (v == null) { ok = false; break; } t += v; }
      if (ok) { n += t; if (from == null) from = idx[j]; }
    }
    return from == null ? null : { n: n, from: from };
  }
  function sumKeys(keys, idx, hourly) {
    var t = 0;
    for (var k = 0; k < keys.length; k++) { var a = hourly ? T.hourly[keys[k]] : T.series[keys[k]]; var v = total(a, idx); if (v == null) return null; t += v; }
    return t;
  }
  function label(i, hourly) {
    if (hourly) { var h = Date.parse(T.hours[i]); return dayShort.format(h) + R.comma + hourF.format(h); }
    return dayShort.format(Date.parse(T.days[i] + "T12:00:00+03:00"));
  }

  // ---------- SVG chart: lines or bars, one shared y axis, gaps for null, crosshair tooltip, table view
  function chart(box, idx, hourly, series, kind) {
    box.textContent = "";
    // the y axis sits on the reading-start side: right in Arabic, left in English (svg itself is laid out LTR)
    var W = Math.max(300, Math.min(640, Math.round(box.clientWidth) || 640)), Hh = W < 480 ? 170 : 190, P = R.en ? { t: 12, r: 8, b: 26, l: 36 } : { t: 12, r: 36, b: 26, l: 8 };
    var pts = idx.map(function (i) { return { i: i, label: label(i, hourly), v: series.map(function (s) { var a = s.data; return a ? a[i] : null; }) }; });
    var max = 1; pts.forEach(function (p) { p.v.forEach(function (v) { if (v != null && v > max) max = v; }); });
    var step = Math.pow(10, Math.floor(Math.log10(max))), nice = [1, 1.2, 1.6, 2, 2.4, 3, 4, 5, 6, 8, 10].map(function (m) { return m * step; })
      .filter(function (v) { return v >= max; })[0];
    if (nice < 4) nice = 4;
    var n = pts.length, iw = W - P.l - P.r, ih = Hh - P.t - P.b, bw = iw / n;
    // reading direction: oldest at the start (right in Arabic, left in English)
    function x(k) { return R.en ? P.l + bw * (k + 0.5) : W - P.r - bw * (k + 0.5); }
    function y(v) { return P.t + ih - (v / nice) * ih; }
    var s = svg("svg", { viewBox: "0 0 " + W + " " + Hh, class: "t-svg", role: "img" });
    var tot = series.map(function (sr) { return total(sr.data, idx); });
    s.setAttribute("aria-label", series.map(function (sr, j) { return sr.name + ": " + (tot[j] == null ? L("بيانات ناقصة", "incomplete data") : nf.format(tot[j])); }).join(R.comma));
    for (var g = 0; g <= 4; g++) {
      var gy = P.t + ih - ih * g / 4;
      s.appendChild(svg("line", { x1: P.l, x2: W - P.r, y1: gy, y2: gy, class: g ? "grid" : "base" }));
      var tl = svg("text", { x: R.en ? P.l - 6 : W - P.r + 6, y: gy + 4, class: "ylab", "text-anchor": R.en ? "end" : "start" });
      tl.textContent = nf.format(nice * g / 4); s.appendChild(tl);
    }
    // x labels: about 6 evenly spaced, always including the newest point
    var every = Math.max(1, Math.ceil(n / (W < 480 ? 4 : 6)));
    pts.forEach(function (p, k) {
      if ((n - 1 - k) % every) return;
      var t = svg("text", { x: x(k), y: Hh - 6, class: "xlab", "text-anchor": "middle" });
      t.textContent = hourly ? hourF.format(Date.parse(T.hours[p.i])) : p.label; s.appendChild(t);
    });
    if (kind === "bar") {
      var gap = Math.min(2, bw * 0.2), w = Math.max(1, (bw - gap) / series.length);
      pts.forEach(function (p, k) {
        p.v.forEach(function (v, j) {
          if (v == null || !v) return;
          var bx = x(k) - bw / 2 + gap / 2 + w * j, by = y(v);
          s.appendChild(svg("rect", { x: bx, y: by, width: Math.max(1, w - (series.length > 1 ? 1 : 0)), height: P.t + ih - by, rx: Math.min(3, w / 3), fill: series[j].color }));
        });
      });
    } else {
      series.forEach(function (sr, j) {
        var d = "", pen = false;
        pts.forEach(function (p, k) {
          var v = p.v[j]; if (v == null) { pen = false; return; }
          d += (pen ? "L" : "M") + x(k).toFixed(1) + " " + y(v).toFixed(1); pen = true;
        });
        if (d) s.appendChild(svg("path", { d: d, fill: "none", stroke: sr.color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }));
        // direct label at the newest observed point
        for (var k = n - 1; k >= 0; k--) if (pts[k].v[j] != null) {
          s.appendChild(svg("circle", { cx: x(k), cy: y(pts[k].v[j]), r: 3.5, fill: sr.color, class: "end" })); break;
        }
      });
    }
    // missing-data shading
    pts.forEach(function (p, k) {
      if (p.v.every(function (v) { return v == null; })) s.appendChild(svg("rect", { x: x(k) - bw / 2, y: P.t, width: bw, height: ih, class: "gap" }));
    });
    var cross = svg("line", { y1: P.t, y2: P.t + ih, class: "cross" }); cross.style.display = "none"; s.appendChild(cross);
    var wrap = el("div", "t-chart"); wrap.appendChild(s);
    var tip = el("div", "tip"); tip.setAttribute("role", "status"); wrap.appendChild(tip);
    pts.forEach(function (p, k) {
      var hit = svg("rect", { x: x(k) - bw / 2, y: 0, width: bw, height: Hh, fill: "transparent" });
      hit.addEventListener("mouseenter", function () {
        cross.setAttribute("x1", x(k)); cross.setAttribute("x2", x(k)); cross.style.display = "";
        tip.textContent = ""; tip.appendChild(el("b", null, p.label));
        series.forEach(function (sr, j) {
          var row = el("span", "tip-row"); var sw = el("i"); sw.style.background = sr.color; row.appendChild(sw);
          row.appendChild(document.createTextNode(sr.name + ": " + (p.v[j] == null ? L("لم يُرصد", "not observed") : nf.format(p.v[j]))));
          tip.appendChild(row);
        });
        var px = x(k) / W * 100; tip.style.insetInlineStart = "auto"; tip.style.left = px > 60 ? "auto" : "calc(" + px + "% + 12px)";
        tip.style.right = px > 60 ? "calc(" + (100 - px) + "% + 12px)" : "auto"; tip.style.top = "8px"; tip.classList.add("show");
      });
      hit.addEventListener("mouseleave", function () { tip.classList.remove("show"); cross.style.display = "none"; });
      s.appendChild(hit);
    });
    box.appendChild(wrap);
    if (series.length > 1) {
      var lg = el("div", "legend");
      series.forEach(function (sr, j) { var it = el("span"); var sw = el("i"); sw.style.background = sr.color; it.appendChild(sw); it.appendChild(document.createTextNode(sr.name + (tot[j] != null ? " (" + nf.format(tot[j]) + ")" : ""))); lg.appendChild(it); });
      box.appendChild(lg);
    }
    // table view: the same numbers as text
    var det = el("details", "as-table"); det.appendChild(el("summary", null, L("عرض كجدول", "Show as a table")));
    var tw = el("div", "tw"), tb = el("table"), hr = el("tr");
    hr.appendChild(el("th", null, hourly ? L("الساعة", "Hour") : L("اليوم", "Day")));
    series.forEach(function (sr) { hr.appendChild(el("th", null, sr.name)); });
    var th = el("thead"); th.appendChild(hr); tb.appendChild(th);
    var bd = el("tbody");
    pts.slice().reverse().forEach(function (p) {
      var tr = el("tr"); tr.appendChild(el("td", null, p.label));
      p.v.forEach(function (v) { tr.appendChild(el("td", null, v == null ? L("لم يُرصد", "not observed") : nf.format(v))); });
      bd.appendChild(tr);
    });
    tb.appendChild(bd); tw.appendChild(tb); det.appendChild(tw); box.appendChild(det);
  }

  // ---------- KPIs: this period vs. the one before it
  function delta(cur, prev) {
    if (cur == null || prev == null) return null;
    if (prev === 0) return cur === 0 ? 0 : null;
    return (cur - prev) / prev;
  }
  function kpi(box, title, cur, prev, note, part) {
    var k = el("div", "t-kpi");
    k.appendChild(el("span", "t-k-l", title));
    k.appendChild(el("b", "num", cur != null ? nf.format(cur) : part ? nf.format(part.n) : "—"));
    var d = delta(cur, prev), line = el("span", "t-k-d");
    if (cur == null && part) line.textContent = L("منذ بدء الجمع في ", "Only since collection began on ") + R.dateF.format(Date.parse(T.days[part.from] + "T12:00:00+03:00")) + L("، فلا مقارنة", ", so no comparison");
    else if (cur == null) line.textContent = note || L("بيانات هذه الفترة غير مكتملة", "Incomplete data for this period");
    else if (prev == null) line.textContent = L("لا تكفي البيانات للمقارنة بما قبلها", "Not enough data to compare with the period before");
    else if (d == null) line.textContent = L("مقابل 0 في الفترة السابقة", "vs. 0 in the previous period");
    else {
      var up = d > 0.0499, down = d < -0.0499;
      line.className += up ? " up" : down ? " down" : "";
      var arrow = el("span", null, up ? "▲ " : down ? "▼ " : "■ "); arrow.setAttribute("aria-hidden", "true"); line.appendChild(arrow);
      line.appendChild(document.createTextNode((up || down ? pf.format(Math.abs(d)) + (up ? L(" أكثر", " more") : L(" أقل", " fewer")) + L(" من الفترة السابقة (", " than the previous period (")
        : L("مستقر تقريباً مقارنة بالفترة السابقة (", "about the same as the previous period (")) + nf.format(prev) + ")"));
    }
    k.appendChild(line);
    box.appendChild(k);
  }

  function render() {
    var w = window_(), state = $("state"); state.textContent = "";
    if (!w) { state.appendChild(el("div", "notice", L("اختر تاريخ بداية ونهاية صحيحين ضمن آخر 90 يوماً.", "Choose a valid start and end date within the last 90 days."))); $("trends").hidden = true; return; }
    $("trends").hidden = false;
    var H = !!w.hourly, cur = w.cur, prev = w.prev;
    document.querySelectorAll("#range button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.r === st.r)); });
    $("custom").hidden = st.r !== "custom";
    var first = H ? Date.parse(T.hours[cur[0]]) : Date.parse(T.days[cur[0]] + "T12:00:00+03:00");
    var lastT = H ? Date.parse(T.hours[cur[cur.length - 1]]) : Date.parse(T.days[cur[cur.length - 1]] + "T12:00:00+03:00");
    $("scope").textContent = H
      ? L("آخر 24 ساعة، ساعة بساعة، مقارنة بالـ24 ساعة قبلها.", "The last 24 hours, hour by hour, compared with the 24 hours before.")
      : L("من ", "From ") + R.dateF.format(first) + L(" إلى ", " to ") + R.dateF.format(lastT)
        + L(" (", " (") + R.countL(cur.length, ["يوم", "يومين", "أيام", "يوماً"], ["day", "days"])
        + (w.custom ? L(")، مقارنة بالفترة نفسها قبلها.", "), compared with the same length before.")
          : L(" كاملة)، مقارنة بالفترة نفسها قبلها. اليوم الحالي لم يكتمل فلا يدخل في المقارنة.", " complete), compared with the same length before. Today is not complete, so it is left out."));

    var vT = sumKeys(["v_total"], cur, H), vTp = sumKeys(["v_total"], prev, H);
    var vC = sumKeys(["v_critical"], cur, H), vCp = sumKeys(["v_critical"], prev, H);
    var kA = H ? null : sumKeys(["kev_added"], cur, false), kAp = H ? null : sumKeys(["kev_added"], prev, false);
    var uK = H ? ["u_all"] : ["u_patch", "u_advisory", "u_release"];
    var uT = sumKeys(uK, cur, H), uTp = sumKeys(uK, prev, H);
    var nK = H ? ["n_sec", "n_other"] : ["n_sec", "n_gen", "n_ai", "n_os", "n_dev", "n_fix"];
    var nT = sumKeys(nK, cur, H), nTp = sumKeys(nK, prev, H), nS = sumKeys(["n_sec"], cur, H);
    var kb = $("kpis"); kb.textContent = "";
    kpi(kb, L("ثغرات جديدة", "New vulnerabilities"), vT, vTp);
    kpi(kb, L("منها حرجة", "Critical among them"), vC, vCp);
    kpi(kb, L("أُضيفت لقائمة CISA", "Added to CISA's list"), kA, kAp, H ? L("تواريخ القائمة بالأيام، اختر فترة بالأيام", "CISA dates are whole days; pick a period in days") : null);
    kpi(kb, L("تحديثات ونشرات أمنية", "Security updates"), uT, uTp, null, H ? null : partial(uK, cur, false));
    var nP = H ? null : partial(nK, cur, false);
    kpi(kb, L("أخبار تقنية", "Tech news"), nT, nTp, null, nP);

    // findings: fixed rules over the numbers above
    var F = $("findings"); F.textContent = "";
    function say(t) { F.appendChild(el("li", null, t)); }
    var dC = delta(vC, vCp);
    if (vC != null && vT) say(R.en
      ? nf.format(vC) + " critical vulnerabilities (" + pf.format(vC / vT) + " of " + nf.format(vT) + " new)" + (dC == null ? "." : Math.abs(dC) < 0.05 ? ", about the same as the period before." : ", " + pf.format(Math.abs(dC)) + (dC > 0 ? " more" : " fewer") + " than the period before (" + nf.format(vCp) + ").")
      : "الثغرات الحرجة " + nf.format(vC) + " (" + pf.format(vC / vT) + " من " + nf.format(vT) + " ثغرة جديدة)" + (dC == null ? "." : Math.abs(dC) < 0.05 ? "، مستقرة تقريباً مقارنة بالفترة السابقة." : "، " + (dC > 0 ? "بزيادة " : "بانخفاض ") + pf.format(Math.abs(dC)) + " عن الفترة السابقة (" + nf.format(vCp) + ")."));
    if (kA != null) say(R.en ? "CISA added " + nf.format(kA) + " vulnerabilities to its exploited list" + (kAp != null ? ", against " + nf.format(kAp) + " in the period before." : ".")
      : "أضافت CISA " + nf.format(kA) + " ثغرة إلى قائمة الثغرات المستغلة" + (kAp != null ? "، مقابل " + nf.format(kAp) + " في الفترة السابقة." : "."));
    var rk = (!H && !w.custom) ? T.ranges[String(w.len)] : H ? T.ranges["1"] : null;
    if (rk && rk.products && rk.products.length) say(R.en ? "Most affected product: " + rk.products[0][0] + " (" + nf.format(rk.products[0][1]) + " vulnerabilities)."
      : "أكثر منتج تأثراً: " + rk.products[0][0] + " (" + nf.format(rk.products[0][1]) + " ثغرة).");
    if (rk && rk.cwe && rk.cwe.length) say(R.en ? "Most common weakness: " + (CWE[rk.cwe[0][0]] || rk.cwe[0][0]) + " (" + rk.cwe[0][0] + "), in " + nf.format(rk.cwe[0][1]) + " vulnerabilities."
      : "أكثر نوع ضعف: " + (CWE[rk.cwe[0][0]] || rk.cwe[0][0]) + " (" + rk.cwe[0][0] + ") في " + nf.format(rk.cwe[0][1]) + " ثغرة.");
    var nAll = nT != null ? nT : nP ? nP.n : 0, nSec = nS != null ? nS : nP ? (partial(["n_sec"], cur, false) || { n: 0 }).n : 0;
    if (nAll) say((R.en ? "Security stories were " + pf.format(nSec / nAll) + " of the " + nf.format(nAll) + " news items" : "الأخبار الأمنية " + pf.format(nSec / nAll) + " من " + nf.format(nAll) + " خبراً")
      + (nT == null && nP ? L(" منذ بدء جمع الأخبار.", " since news collection began.") : "."));
    if (!F.children.length) say(L("لا تكفي البيانات في هذه الفترة لاستخلاص شيء.", "There is not enough data in this period to say anything."));

    // charts
    var cv = getComputedStyle(document.documentElement);
    var C1 = cv.getPropertyValue("--t1").trim(), C2 = cv.getPropertyValue("--t2").trim();
    var crit = cv.getPropertyValue("--s-critical").trim(), high = cv.getPropertyValue("--s-high").trim();
    var kind = cur.length > 1 ? "line" : "bar";
    chart($("c-v"), cur, H, [{ name: L("ثغرات جديدة", "New vulnerabilities"), color: C1, data: ser("v_total") }], cur.length <= 31 ? "bar" : "line");
    $("n-v").textContent = L("حسب تاريخ نشرها في NVD. ", "By NVD publication date. ") + (T.coverage.vulns ? L("السجل مكتمل من ", "Complete from ") + R.dateF.format(Date.parse(T.coverage.vulns + "T12:00:00+03:00")) + "." : "");
    chart($("c-ch"), cur, H, [{ name: L("حرجة", "Critical"), color: crit, data: ser("v_critical") }, { name: L("عالية", "High"), color: high, data: ser("v_high") }], kind);
    if (H) { $("c-k").textContent = ""; $("c-k").appendChild(el("p", "s-note", L("قائمة CISA تسجّل تاريخ الإضافة باليوم فقط. اختر فترة بالأيام.", "CISA records the day of addition only. Pick a period in days."))); }
    else chart($("c-k"), cur, false, [{ name: L("أُضيفت للقائمة", "Added"), color: crit, data: T.series.kev_added }], "bar");
    $("n-k").textContent = L("من تواريخ الإضافة في قائمة CISA نفسها، لكل الثغرات وليس فقط ما رصده الرادار.", "From the addition dates in CISA's own catalog, for every vulnerability, not only those the radar tracked.");
    var ub = H ? [{ name: L("تحديثات ونشرات", "Updates"), color: C1, data: T.hourly.u_all }]
      : [{ name: R.UTYPE.patch, color: C1, data: T.series.u_patch }, { name: R.UTYPE.advisory, color: C2, data: T.series.u_advisory }];
    chart($("c-u"), cur, H, ub, "bar");
    $("n-u").textContent = L("من Chrome وUbuntu وDebian وCisco وFortinet وOracle. ", "From Chrome, Ubuntu, Debian, Cisco, Fortinet and Oracle. ")
      + (H ? "" : L("التحديثات العامة بلا إصلاحات أمنية: ", "General updates with no security fixes: ") + (total(T.series.u_release, cur) == null ? "—" : nf.format(total(T.series.u_release, cur))) + ".");
    var other = H ? T.hourly.n_other : T.days.map(function (_, i) {
      var t = 0; for (var k = 0; k < nK.length; k++) { if (nK[k] === "n_sec") continue; var v = T.series[nK[k]][i]; if (v == null) return null; t += v; } return t;
    });
    chart($("c-n"), cur, H, [{ name: L("أخبار أمنية", "Security news"), color: C1, data: H ? T.hourly.n_sec : T.series.n_sec }, { name: L("أخبار تقنية أخرى", "Other tech news"), color: C2, data: other }], kind);
    $("n-n").textContent = T.coverage.news ? L("الرادار يجمع الأخبار منذ ", "The radar has collected news since ") + R.dateF.format(Date.parse(T.coverage.news + "T12:00:00+03:00")) + L("؛ الأيام قبلها لا تظهر.", "; earlier days are not shown.") : "";

    // rankings (preset ranges only: they are precomputed from the full history)
    var cw = $("cwe"), pr = $("prod"); cw.textContent = ""; pr.textContent = "";
    if (!rk) {
      $("n-cwe").textContent = $("n-prod").textContent = L("الترتيب متاح للفترات الجاهزة (24 ساعة، 7 أيام، 30 يوماً، 90 يوماً).", "Rankings are available for the preset periods (24 hours, 7, 30 and 90 days).");
    } else {
      $("n-cwe").textContent = L("من الثغرات التي حددت لها NVD أو الجهة المبلّغة نوع الضعف: ", "Among vulnerabilities whose weakness type NVD or the reporter recorded: ")
        + nf.format(rk.with_cwe) + L(" من ", " of ") + nf.format(rk.total) + ".";
      var maxC = rk.cwe.length ? rk.cwe[0][1] : 1;
      rk.cwe.concat(rk.cwe_other ? [[L("أنواع أخرى", "Other types"), rk.cwe_other, true]] : []).forEach(function (c) {
        var li = el("li"), row = el("div", "hbar");
        var lab = el("span", "lab", c[2] ? c[0] : (CWE[c[0]] || c[0])); lab.title = c[2] ? "" : c[0]; row.appendChild(lab);
        var tr = el("span", "track"), fl = el("span", "fill"); fl.style.width = Math.max(1.5, c[1] / Math.max(maxC, c[1]) * 100) + "%";
        if (c[2]) fl.style.setProperty("--c", "var(--s-unknown)"); tr.appendChild(fl); row.appendChild(tr);
        var v = el("span", "val"); v.appendChild(el("b", null, nf.format(c[1]))); if (!c[2]) v.appendChild(el("small", null, " " + c[0])); row.appendChild(v);
        li.appendChild(row); cw.appendChild(li);
      });
      if (!rk.cwe.length) cw.appendChild(el("li", "s-note", L("لا توجد بيانات بعد.", "No data yet.")));
      $("n-prod").textContent = L("المنتج مستخرج آلياً من وصف الثغرة، فقد يخطئ أحياناً.", "The product is extracted automatically from the description, so it can be wrong.");
      rk.products.forEach(function (p, i) {
        var tr = el("tr"); tr.appendChild(el("td", "num", nf.format(i + 1)));
        var td = el("td"); var a = el("a", null, null); a.appendChild(el("bdi", null, p[0])); a.href = "./#type=vul&q=" + encodeURIComponent(p[0]); td.appendChild(a); tr.appendChild(td);
        tr.appendChild(el("td", "num", nf.format(p[1]))); pr.appendChild(tr);
      });
      if (!rk.products.length) { var tr0 = el("tr"); var td0 = el("td", "s-note", L("لا توجد بيانات بعد.", "No data yet.")); td0.colSpan = 3; tr0.appendChild(td0); pr.appendChild(tr0); }
    }
    var p = new URLSearchParams(); if (st.r !== "7") p.set("r", st.r); if (st.r === "custom") { p.set("from", st.from); p.set("to", st.to); } R.setHash(p);
  }

  function readHash() {
    var p = R.hashParams();
    st.r = ({ "1": 1, "7": 1, "30": 1, "90": 1, custom: 1 })[p.get("r")] ? p.get("r") : "7";
    st.from = p.get("from") || ""; st.to = p.get("to") || "";
  }
  document.querySelectorAll("#range button").forEach(function (b) {
    b.onclick = function () {
      st.r = b.dataset.r;
      if (st.r === "custom" && (!st.from || !st.to)) { st.to = T.days[T.days.length - 2]; st.from = T.days[T.days.length - 15]; }
      $("from").value = st.from; $("to").value = st.to; render();
    };
  });
  ["from", "to"].forEach(function (id) { $(id).addEventListener("change", function () { st[id] = $(id).value; render(); }); });

  R.status("loading");
  fetch("trends.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); }).then(function (d) {
    if (!d || !Array.isArray(d.days) || !d.series || !d.hourly) throw new Error("bad-format");
    T = d; R.status("ok", Date.parse(d.generated_at) || Date.now());
    $("from").min = $("to").min = T.days[0]; $("from").max = $("to").max = T.days[T.days.length - 1];
    readHash(); $("from").value = st.from; $("to").value = st.to; render();
  }).catch(function (err) { R.status("error"); R.errorNotice($("state"), err, function () { location.reload(); }); });
})();
