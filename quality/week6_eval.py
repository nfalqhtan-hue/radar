# -*- coding: utf-8 -*-
"""
اختبار الأسبوع السادس - رادار التقنية
جولة اختبار كاملة على بيانات حقيقية:
  A) جلب حي (KEV + NVD + RSS) وتصنيف بدون نموذج
  B) سحب عينة 20 عنصراً (12 خبر + 8 ثغرات) وتلخيصها عبر Ollama المحلي مع قياس الوقت
  C) مطابقة كل ثغرة في العينة مع NVD مباشرة (رقم CVE، تاريخ النشر، CVSS، الخطورة)
  D) فحوص آلية للملخصات (رقم أو CVE غير موجود في المصدر، الطول، العربية، الرابط)
  E) اختبار التنبيه بثلاث ثغرات حرجة معروفة وقياس زمن وصول التنبيه
الناتج: quality/round<N>_results.json  (والتقييم اليدوي في quality/gold.json)

التشغيل:  python quality/week6_eval.py --round 1
"""
import os, re, sys, json, time, random, sqlite3, argparse, tempfile, urllib.parse, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__))
# --pipeline يحدد نسخة الكود المختبرة (baseline_v06.py قبل الإصلاح، أو radar_pipeline.py بعده)
_pp = next((sys.argv[i + 1] for i, x in enumerate(sys.argv) if x == "--pipeline"), os.path.join(os.path.dirname(HERE), "radar_pipeline.py"))
_spec = importlib.util.spec_from_file_location("rp", _pp); rp = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(rp)

KNOWN_CRITICAL = ["CVE-2021-44228", "CVE-2024-3400", "CVE-2023-4966"]   # Log4Shell, PAN-OS, Citrix Bleed
NVD_SEV = lambda s: None if s is None else "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "none"


def nvd_get(cve):
    """يجلب سجل CVE واحد من NVD (مع احترام حد المعدل بدون مفتاح: 5 طلبات / 30 ثانية)."""
    h = {"User-Agent": "radar-altaqniya/0.7"}
    if rp.NVD_KEY: h["apiKey"] = rp.NVD_KEY
    for attempt in range(3):
        try:
            data = json.loads(rp.http(rp.NVD_URL + "?cveId=" + urllib.parse.quote(cve), h, timeout=40))
            time.sleep(0.8 if rp.NVD_KEY else 6.5)
            return data
        except Exception as e:
            last = e; time.sleep(10)
    raise last


def numbers(s):
    return set(re.findall(r"\d+(?:\.\d+)?", s or ""))


def summary_checks(it):
    """فحوص آلية تساعد المراجعة اليدوية (لا تغني عنها)."""
    s, src = it.get("summary") or "", (it["title"] + " " + it["text"])
    arabic = len(re.findall(r"[؀-ۿ]", s)); latin = len(re.findall(r"[A-Za-z]", s))
    # أرقام عربية هندية -> لاتينية قبل المقارنة
    s_norm = s.translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789"))
    extra_nums = sorted(n for n in numbers(s_norm) - numbers(src) if len(n) > 1 or "." in n)
    extra_cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", s)) - set(re.findall(r"CVE-\d{4}-\d{4,}", src)))
    return dict(has_summary=bool(s), length=len(s), arabic_ratio=round(arabic / max(1, arabic + latin), 2),
                extra_numbers=extra_nums, extra_cves=extra_cves, has_link=it["link"].startswith("http"),
                too_long=len(s) > 700)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--round", type=int, default=1)
    p.add_argument("--hours", type=int, default=24, help="نافذة NVD")
    p.add_argument("--seed", type=int, default=6)
    p.add_argument("--reuse-sample", help="ملف نتائج جولة سابقة لإعادة اختبار نفس العينة (بعد الإصلاح)")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--pipeline", default=_pp)
    a = p.parse_args()
    out = dict(round=a.round, pipeline=os.path.basename(a.pipeline), started=time.strftime("%Y-%m-%d %H:%M:%S"), model=rp.OLLAMA_MODEL, timings={})
    db = os.path.join(HERE, f"round{a.round}.db")
    if os.path.exists(db): os.remove(db)

    # ---------------- A) جلب حي وتصنيف
    t0 = time.time()
    if a.reuse_sample:
        prev = json.load(open(a.reuse_sample, encoding="utf-8"))
        raw = [dict(kind=x["kind"], source=x["source"], uid=x["id"], title=x["title"], link=x["link"], text=x["text"],
                    date=x["date"], score=x["score_pipeline_input"], kev=x["kev"], system=x.get("system_input", ""))
               for x in prev["sample"]]
        fetchers = dict(kev=lambda: (set(i["uid"] for i in raw if i["kev"]), []), nvd=lambda: [i for i in raw if i["kind"] == "vuln"],
                        rss=lambda: [i for i in raw if i["kind"] == "news"])
        if hasattr(rp, "nvd_lookup"): fetchers["nvd_lookup"] = rp.nvd_lookup     # النسخة المصلحة: تكميل درجات KEV من NVD
    else:
        fetchers = None
    args = argparse.Namespace(db=db, out=os.path.join(HERE, f"round{a.round}_site.json"), hours=a.hours, no_llm=True, no_alert=True)
    st = rp.run(args, fetchers)
    out["timings"]["fetch_classify_s"] = round(time.time() - t0, 1)
    out["fetch_stats"] = {k: v for k, v in st.items() if k != "critical"}
    out["fetch_stats"]["critical_count"] = len(st["critical"])

    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT * FROM items")]
    out["by_type"] = {}
    for r in rows: out["by_type"][r["type"]] = out["by_type"].get(r["type"], 0) + 1
    out["by_source"] = {}
    for r in rows: out["by_source"][r["source"]] = out["by_source"].get(r["source"], 0) + 1

    # ---------------- B) العينة + التلخيص
    if a.reuse_sample:
        order = [x["id"] for x in prev["sample"]]
        sample = sorted([r for r in rows if r["uid"] in order], key=lambda r: order.index(r["uid"]))
    else:
        rnd = random.Random(a.seed)
        news = [r for r in rows if r["kind"] == "news"]; vul = [r for r in rows if r["kind"] == "vuln"]
        kev = [r for r in vul if r["kev"]]; other = [r for r in vul if not r["kev"]]
        pick_v = rnd.sample(kev, min(2, len(kev))); pick_v += rnd.sample(other, min(8 - len(pick_v), len(other)))
        sample = rnd.sample(news, min(20 - len(pick_v), len(news))) + pick_v
    t0 = time.time(); llm_times = []
    for r in sample:
        r["llm_seconds"] = None
        if hasattr(rp, "needs_llm") and not rp.needs_llm(r):
            r["summary_mode"] = "template"; continue          # النسخة المصلحة: ملخص قالبي من الحقائق للثغرات المتوسطة/المنخفضة
        r["summary"], r["summary_mode"] = "", "llm"
        if not a.no_llm:
            t = time.time()
            try: r["summary"] = rp.summarize_ollama(r)
            except Exception as e: r["summary"] = ""; r["llm_error"] = f"{type(e).__name__}: {e}"
            r["llm_seconds"] = round(time.time() - t, 1); llm_times.append(r["llm_seconds"])
            print(f"  summarized {len(llm_times)}/{len(sample)} in {r['llm_seconds']}s", flush=True)
    out["timings"]["summaries_s"] = round(time.time() - t0, 1)
    out["timings"]["avg_summary_s"] = round(sum(llm_times) / len(llm_times), 1) if llm_times else None

    # ---------------- C) مطابقة الثغرات مع NVD
    res = []
    for i, r in enumerate(sample, 1):
        e = dict(n=i, id=r["uid"], kind=r["kind"], source=r["source"], title=r["title"], link=r["link"], text=r["text"],
                 date=r["published"], type=r["type"], system=r["system"], severity=r["severity"], score=r["score"], kev=bool(r["kev"]),
                 summary=r["summary"], summary_mode=r.get("summary_mode"), llm_seconds=r["llm_seconds"], llm_error=r.get("llm_error"), verify_reason=rp.verify(dict(r, uid=r["uid"], templated=r.get("summary_mode") == "template")),
                 score_pipeline_input=r["score"], system_input=r["system"] if r["source"] == "CISA KEV" else "")
        e["checks"] = summary_checks(dict(title=r["title"], text=r["text"], link=r["link"], summary=r["summary"]))
        if r["kind"] == "vuln":
            try:
                nv = rp.parse_nvd(nvd_get(r["uid"]))
                if not nv:
                    e["nvd"] = dict(found=False)
                else:
                    n = nv[0]
                    e["nvd"] = dict(found=True, id=n["uid"], published=rp.to_iso(n["date"]), score=n["score"],
                                    nvd_severity=NVD_SEV(n["score"]))
                    e["nvd"]["id_match"] = n["uid"] == r["uid"]
                    e["nvd"]["score_match"] = n["score"] == r["score"]
                    e["nvd"]["date_match"] = (r["source"] != "NVD") or rp.to_iso(n["date"])[:10] == (r["published"] or "")[:10]
                    # الخطورة الصحيحة: من CVSS في NVD، مع رفعها إلى حرجة إذا كانت في KEV (قاعدة المشروع)
                    exp = "critical" if r["kev"] else (NVD_SEV(n["score"]) or "unknown")
                    e["nvd"]["expected_severity"] = exp
                    e["nvd"]["severity_match"] = r["severity"] == exp
            except Exception as ex:
                e["nvd"] = dict(error=str(ex))
        res.append(e)
    out["sample"] = res

    # ---------------- E) اختبار التنبيه بثغرات حرجة معروفة
    tmp = tempfile.mkdtemp(); sent = []
    known = []
    for c in KNOWN_CRITICAL:
        known += rp.parse_nvd(nvd_get(c))
    kev_ids = set()
    try: kev_ids, _ = rp.parse_kev(json.loads(rp.http(rp.KEV_URL)))
    except Exception as ex: out["kev_error"] = str(ex)
    t0 = time.time(); stamps = {}
    def notifier(msg):
        cid = re.search(r"CVE-\d{4}-\d{4,}", msg).group(0); stamps[cid] = round(time.time() - t0, 3); sent.append(msg); return True
    a2 = argparse.Namespace(db=os.path.join(tmp, "alert.db"), out=os.path.join(tmp, "alert.json"), hours=2, no_llm=True, no_alert=False)
    st2 = rp.run(a2, dict(kev=lambda: (kev_ids, []), nvd=lambda: known, rss=lambda: []), None, notifier)
    out["alert_test"] = [dict(cve=c, in_kev=c in kev_ids,
                              nvd_score=next((k["score"] for k in known if k["uid"] == c), None),
                              alert_sent=c in stamps, seconds_after_cycle_start=stamps.get(c)) for c in KNOWN_CRITICAL]
    out["alert_test_cycle_s"] = round(time.time() - t0, 2)
    out["alert_messages"] = sent
    # تكرار الدورة: يجب ألا يتكرر التنبيه
    n0 = len(sent); rp.run(a2, dict(kev=lambda: (kev_ids, []), nvd=lambda: known, rss=lambda: []), None, notifier)
    out["alert_repeat_on_second_cycle"] = len(sent) - n0

    out["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    path = os.path.join(HERE, f"round{a.round}_results.json")
    json.dump(out, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("DONE ->", path)


if __name__ == "__main__":
    main()
