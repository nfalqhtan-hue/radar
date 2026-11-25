# -*- coding: utf-8 -*-
"""يحسب مقاييس كل جولة من ملف النتائج (round<N>_results.json) والمراجعة اليدوية (gold_round<N>.json)، ويطبع جدولاً بصيغة Markdown."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))

def pct(a, b): return f"{a}/{b} ({100 * a / b:.0f}%)" if b else "—"

def score(n):
    r = json.load(open(os.path.join(HERE, f"round{n}_results.json"), encoding="utf-8"))
    g = {x["n"]: x for x in json.load(open(os.path.join(HERE, f"gold_round{n}.json"), encoding="utf-8"))["items"]}
    S = r["sample"]; V = [x for x in S if x["kind"] == "vuln"]
    gv = [g[x["n"]] for x in V]
    pub = [g[x["n"]] for x in S if g[x["n"]]["summary_ok"] is not None]
    blocked = sum(1 for x in S if g[x["n"]]["summary_ok"] is None)
    nvd = [x["nvd"] for x in V if x.get("nvd", {}).get("found")]
    at = r["alert_test"]
    return {
        "الجولة": f"{n} ({r.get('pipeline', 'radar_pipeline.py')}, {r['model']})",
        "حجم العينة": f"{len(S)} ({len(S) - len(V)} خبر + {len(V)} ثغرة)",
        "دقة التصنيف (النوع)": pct(sum(g[x["n"]]["type_ok"] for x in S), len(S)),
        "ملاءمة الأخبار للفئة": pct(sum(g[x["n"]]["relevant"] for x in S), len(S)),
        "دقة درجة الخطورة": pct(sum(x["severity_ok"] for x in gv), len(gv)),
        "مطابقة CVSS مع NVD": pct(sum(x["score_ok"] for x in gv), len(gv)),
        "دقة النظام المتأثر": pct(sum(x["system_ok"] for x in gv), len(gv)),
        "مطابقة رقم CVE": pct(sum(x["id_match"] for x in nvd), len(nvd)),
        "مطابقة تاريخ النشر": pct(sum(x["date_match"] for x in nvd), len(nvd)),
        "الملخصات المنشورة السليمة": pct(sum(x["summary_ok"] for x in pub), len(pub)),
        "ملخصات منعها حارس الجودة": str(blocked),
        "وجود رابط المصدر": pct(sum(x["checks"]["has_link"] for x in S), len(S)),
        "تنبيه الثغرات الحرجة المعروفة": pct(sum(a["alert_sent"] for a in at), len(at)),
        "تكرار التنبيه في الدورة التالية": str(r["alert_repeat_on_second_cycle"]),
        "متوسط زمن الملخص": f"{r['timings']['avg_summary_s']} ث",
    }

def main():
    rounds = [int(x) for x in sys.argv[1:]] or [1, 2, 3]
    rows = [score(n) for n in rounds if os.path.exists(os.path.join(HERE, f"gold_round{n}.json"))]
    keys = list(rows[0])
    print("| المقياس | " + " | ".join(f"الجولة {r['الجولة'].split()[0]}" for r in rows) + " |")
    print("|---|" + "---|" * len(rows))
    for k in keys[1:]:
        print(f"| {k} | " + " | ".join(r[k] for r in rows) + " |")
    json.dump(rows, open(os.path.join(HERE, "scores.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)

if __name__ == "__main__":
    main()
