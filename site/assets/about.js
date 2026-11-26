/* رادار التقنية: صفحة عن المشروع، أرقام حية من stats.json */
(function () {
  "use strict";
  var R = window.Radar, $ = R.$, nf = R.nf;
  R.status("loading");
  fetch("stats.json", { cache: "no-cache" })
    .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then(function (d) {
      if (!d || !d.vulns) throw new Error("bad-format");
      var n = function (v) { return typeof v === "number" && isFinite(v) ? nf.format(v) : "—"; };
      $("l-v").textContent = n(d.vulns.total);
      $("l-n").textContent = n(d.news && d.news.total);
      $("l-k").textContent = n(d.vulns.kev);
      var f = Date.parse(d.first_seen); $("l-s").textContent = f ? R.dateF.format(f) : "—";
      R.status("ok", Date.parse(d.generated_at) || Date.now());
    })
    .catch(function () {
      // الصفحة نصية في أساسها، فإذا تعذّرت الأرقام الحية نخفيها بدل عرض أصفار
      R.status("error"); $("live").hidden = true;
    });
})();
