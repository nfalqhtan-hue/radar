import os, json, sqlite3, argparse, tempfile
import radar_pipeline as rp

ok = 0
def check(name, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + name); ok += bool(cond)
    assert cond, name

RSS = b"""<?xml version="1.0"?><rss><channel><item><title>New AI chatbot launched</title><link>https://ex.com/a</link>
<description>&lt;p&gt;A new &lt;b&gt;LLM&lt;/b&gt; assistant.&lt;/p&gt;</description><pubDate>Tue, 10 Nov 2026 08:00:00 GMT</pubDate></item></channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Android update fixes battery bug</title>
<link href="https://ex.com/b"/><summary>Fixes drain.</summary><updated>2026-11-10T09:00:00Z</updated></entry></feed>"""
r = rp.parse_feed(RSS, "ex.com"); a = rp.parse_feed(ATOM, "ex.com")
check("RSS parsed (1 item, link)", len(r) == 1 and r[0]["link"] == "https://ex.com/a")
check("Atom parsed (link from href)", len(a) == 1 and a[0]["link"] == "https://ex.com/b")

nvd = rp.parse_nvd({"vulnerabilities": [{"cve": {"id": "CVE-2026-1111", "published": "2026-11-10T07:00:00.000",
      "descriptions": [{"lang": "en", "value": "Remote code execution in Linux service."}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}]})
check("NVD parsed with CVSS 9.8", nvd[0]["score"] == 9.8 and nvd[0]["uid"] == "CVE-2026-1111")
ids, kevi = rp.parse_kev({"vulnerabilities": [{"cveID": "CVE-2026-2222", "vendorProject": "Microsoft", "product": "Windows",
      "vulnerabilityName": "Win flaw", "shortDescription": "Exploited flaw.", "dateAdded": rp.datetime.now(rp.timezone.utc).strftime("%Y-%m-%d")}]})
check("KEV parsed (id set + recent item)", "CVE-2026-2222" in ids and len(kevi) == 1 and kevi[0]["kev"] == 1)

d = tempfile.mkdtemp()
args = argparse.Namespace(db=os.path.join(d, "t.db"), out=os.path.join(d, "site", "data.json"), hours=2, no_llm=False, no_alert=False)
sent = []
news = lambda: rp.parse_feed(RSS, "ex.com") + rp.parse_feed(RSS, "ex.com") + rp.parse_feed(ATOM, "ex.com")
bad = lambda: [dict(kind="vuln", source="NVD", uid="BAD-ID", title="x", link="https://n", text="t", date="", score=5.0),
               dict(kind="news", source="x", title="", link="", text="", date="")]
summ = lambda it: "ملخص عربي قصير."

st = rp.run(args, dict(kev=lambda: (set(), []), nvd=lambda: nvd + bad(), rss=news), summ, sent.append)
check("dedupe inside batch (2 unique news + nvd + bad)", st["duplicates"] == 1 and st["new"] == 4)
check("empty title/link counted invalid", st["invalid"] == 1)
check("bad CVE id goes to review, not published", st["review"] == 1 and st["published"] == 3)
check("critical alert sent for CVSS 9.8", len(sent) == 1 and "CVE-2026-1111" in sent[0])

st2 = rp.run(args, dict(kev=lambda: (set(), []), nvd=lambda: nvd, rss=news), summ, sent.append)
check("second run: nothing new (already in DB)", st2["new"] == 0 and st2["duplicates"] >= 3)
check("no repeated alert for the same CVE", len(sent) == 1)

con = sqlite3.connect(args.db); con.row_factory = sqlite3.Row
types = {r["title"][:12]: r["type"] for r in con.execute("select title,type from items")}
check("classification: AI news -> ai, Android fix -> os/fix", any(v == "ai" for v in types.values()) and any(v in ("os", "fix") for v in types.values()))
data = json.load(open(args.out, encoding="utf-8"))
check("data.json exports only published items", len(data["items"]) == 3 and all(i["title"] for i in data["items"]))
check("exported vuln has advice + critical severity", any(i["severity"] == "critical" and i["advice"] for i in data["items"]))

# KEV later marks a stored medium vuln as exploited -> upgraded + alert
kid = {"CVE-2026-3333"}
med = [dict(kind="vuln", source="NVD", uid="CVE-2026-3333", title="CVE-2026-3333: medium", link="https://nvd/x", text="desc", date="", score=5.0)]
rp.run(args, dict(kev=lambda: (set(), []), nvd=lambda: med, rss=lambda: []), summ, sent.append)
n_before = len(sent)
st3 = rp.run(args, dict(kev=lambda: (kid, []), nvd=lambda: med, rss=lambda: []), summ, sent.append)
check("KEV upgrade -> alert sent once", len(sent) == n_before + 1 and "CVE-2026-3333" in sent[-1])

# LLM down: title+link published, summary pending, then retried
d2 = tempfile.mkdtemp(); a2 = argparse.Namespace(db=os.path.join(d2, "t.db"), out=os.path.join(d2, "o.json"), hours=2, no_llm=False, no_alert=True)
def down(it): raise ConnectionError("ollama down")
s1 = rp.run(a2, dict(kev=lambda: (set(), []), nvd=lambda: [], rss=news), down, None)
check("LLM down: items still published, pending counted, error logged", s1["published"] == 2 and s1["pending"] == 2 and s1["errors"])
s2 = rp.run(a2, dict(kev=lambda: (set(), []), nvd=lambda: [], rss=lambda: []), summ, None)
c2 = sqlite3.connect(a2.db); left = c2.execute("select count(*) from items where pending=1").fetchone()[0]
check("pending summaries retried when LLM returns", left == 0)

# hallucination guard: summary mentions a different CVE
halluc = lambda it: "هذه الثغرة CVE-2099-9999 خطيرة."
a3 = argparse.Namespace(db=os.path.join(tempfile.mkdtemp(), "t.db"), out=os.path.join(d, "o3.json"), hours=2, no_llm=False, no_alert=True)
s3 = rp.run(a3, dict(kev=lambda: (set(), []), nvd=lambda: nvd, rss=lambda: []), halluc, None)
check("summary with foreign CVE id -> review queue", s3["review"] == 1 and s3["published"] == 0)

# a failing source does not stop the others
def boom(): raise RuntimeError("source down")
s4 = rp.run(a3 if False else argparse.Namespace(db=os.path.join(tempfile.mkdtemp(), "t.db"), out=os.path.join(d, "o4.json"), hours=2, no_llm=False, no_alert=True),
            dict(kev=boom, nvd=lambda: nvd, rss=news), summ, None)
check("one source failing does not stop the cycle", s4["published"] >= 3 and any("kev" in e for e in s4["errors"]))

# circuit breaker: when the LLM is down it is called once per run, not once per item
calls = []
def down_counted(it):
    calls.append(1); raise ConnectionError("ollama down")
a5 = argparse.Namespace(db=os.path.join(tempfile.mkdtemp(), "t.db"), out=os.path.join(d, "o5.json"), hours=2, no_llm=False, no_alert=True)
rp.run(a5, dict(kev=lambda: (set(), []), nvd=lambda: nvd, rss=news), down_counted, None)
check("LLM down: summarizer tried once per run (circuit breaker)", len(calls) == 1)

# classification uses whole words: 'ios' must not match inside 'scenarios'
w = rp.classify(dict(kind="news", title="Market scenarios for retailers", text="", score=None, kev=0))
check("whole-word matching ('scenarios' is not iOS)", w["type"] == "gen")
b = rp.classify(dict(kind="news", title="Retailer data breach exposes users", text="customers used the smartphone app", score=None, kev=0))
check("breach news is not classified as devices", b["type"] == "gen")

# ---------------- إصلاحات الأسبوع السادس
# CVSS: نفضّل تقييم NVD الرسمي (Primary) حتى لو جاء بعد تقييم الجهة المبلّغة
pv = rp.parse_nvd({"vulnerabilities": [{"cve": {"id": "CVE-2026-4444", "published": "2026-11-10T07:00:00.000", "descriptions": [],
      "metrics": {"cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 9.8}}, {"type": "Primary", "cvssData": {"baseScore": 7.5}}]}}}]})
check("CVSS: Primary (NVD) score preferred over Secondary", pv[0]["score"] == 7.5)
u = rp.classify(dict(kind="vuln", title="CVE-2026-5555: x", text="", score=None, kev=0))
check("unscored CVE -> 'unknown', not 'low'", u["severity"] == "unknown")

# KEV item without score is enriched from NVD, then summarized; medium vulns get a factual template, not the LLM
looked, llm_seen = [], []
kev_item = [dict(kind="vuln", source="CISA KEV", uid="CVE-2026-6666", title="CVE-2026-6666: KEV flaw", link="https://nvd/6666",
                 text="Exploited.", date="", score=None, kev=1, system="Cisco IOS")]
mid = [dict(kind="vuln", source="NVD", uid="CVE-2026-7777", title="CVE-2026-7777: mid", link="https://nvd/7777", text="d", date="", score=5.0)]
def lookup(cid): looked.append(cid); return dict(score=8.6)
def spy(it): llm_seen.append(it["title"]); return "ملخص."
a6 = argparse.Namespace(db=os.path.join(tempfile.mkdtemp(), "t.db"), out=os.path.join(d, "o6.json"), hours=2, no_llm=False, no_alert=False)
sent6 = []
s6 = rp.run(a6, dict(kev=lambda: ({"CVE-2026-6666"}, kev_item), nvd=lambda: mid, rss=lambda: [], nvd_lookup=lookup), spy, sent6.append)
c6 = sqlite3.connect(a6.db); c6.row_factory = sqlite3.Row
k = c6.execute("select * from items where uid='CVE-2026-6666'").fetchone(); m = c6.execute("select * from items where uid='CVE-2026-7777'").fetchone()
# [المرحلة 3] الخطورة من الدرجة وحدها: مستغلة بدرجة 8.6 تبقى «عالية» مع علامة الاستغلال (لم تعد تُرفع إلى «حرجة»)
check("KEV score enriched from NVD (8.6): severity high, exploited flag kept separately",
      looked == ["CVE-2026-6666"] and k["score"] == 8.6 and k["severity"] == "high" and k["kev"] == 1)
check("medium vuln: template summary, LLM not called", "متوسطة" in m["summary"] and "CVSS 5.0" in m["summary"] and llm_seen == ["CVE-2026-6666: KEV flaw"])
check("KEV alert labelled as exploited", len(sent6) == 1 and "CISA KEV" in sent6[0] and "8.6" in sent6[0])

# alert flood: 12 critical in one cycle -> 5 single alerts + 1 digest, KEV first
flood = [dict(kind="vuln", source="NVD", uid=f"CVE-2026-90{i:02d}", title=f"CVE-2026-90{i:02d}: c", link=f"https://nvd/{i}", text="d",
              date="", score=9.0 + (i % 10) / 10) for i in range(12)]
sent7 = []
a7 = argparse.Namespace(db=os.path.join(tempfile.mkdtemp(), "t.db"), out=os.path.join(d, "o7.json"), hours=2, no_llm=True, no_alert=False)
rp.run(a7, dict(kev=lambda: ({"CVE-2026-9011"}, []), nvd=lambda: flood, rss=lambda: []), None, sent7.append)
check("alert flood capped: 5 single + 1 digest", len(sent7) == 6 and "7 ثغرة حرجة أخرى" in sent7[-1])
check("KEV alert sent first", "CVE-2026-9011" in sent7[0])

# LLM cap per cycle: extra items stay pending for next cycle
many = [dict(kind="news", source="x", title=f"News {i}", link=f"https://ex.com/n{i}", text="t", date="") for i in range(5)]
a8 = argparse.Namespace(db=os.path.join(tempfile.mkdtemp(), "t.db"), out=os.path.join(d, "o8.json"), hours=2, no_llm=False, no_alert=True, max_llm=2)
s8 = rp.run(a8, dict(kev=lambda: (set(), []), nvd=lambda: [], rss=lambda: many), summ, None)
left8 = sqlite3.connect(a8.db).execute("select count(*) from items where pending=1").fetchone()[0]
check("max_llm caps summaries (incl. retries); rest pending for next cycle", s8["llm_calls"] == 2 and s8["published"] == 5 and left8 == 3)

# summary quality guard (real failures seen in round 1)
src = "Megaspeed would be barred from doing business with U.S. companies"
check("guard: Chinese text rejected", rp.summary_problem("ميجاسبيد 被列入美国黑名单", src))
check("guard: mostly English rejected", rp.summary_problem("Ukraine strikes have caused the sinking of a ship", src))
check("guard: glued Arabic/Latin word rejected", rp.summary_problem("في الاجتماعETING شكر الموظفين", src))
check("guard: English word not in source rejected", rp.summary_problem("أزال المزودين exposant بيانات حساسة", src))
check("guard: number not in source rejected", rp.summary_problem("ستُحظر Megaspeed خلال 30 يوماً", src))
check("guard: stray single letter before Latin name rejected", rp.summary_problem("أعلن م Megaspeed عن خطة", src))
check("guard: 'و' before Latin name allowed", rp.summary_problem("تعاونت الشركات و Megaspeed مع الحكومة", src) is None)
check("guard: clean Arabic with source name passes", rp.summary_problem("ستُمنع Megaspeed من التعامل مع الشركات الأمريكية.", src) is None)
check("rejected CVE skipped by parser", rp.parse_nvd({"vulnerabilities": [{"cve": {"id": "CVE-2026-1", "vulnStatus": "Rejected",
      "descriptions": [{"lang": "en", "value": "Rejected reason: withdrawn."}]}}]}) == [])
check("system from description (MediaWiki)", rp.extract_system("Cross-site Scripting vulnerability in Wikimedia Foundation MediaWiki. This issue affects") == "Wikimedia Foundation MediaWiki")
check("system from description (Firefox component)", rp.extract_system("Use-after-free in the DOM: Core component. This vulnerability was fixed in Firefox 150.") == "Mozilla Firefox")
check("system at start (FFmpeg)", rp.extract_system("FFmpeg before 9.1 contains an uninitialized memory vulnerability") == "FFmpeg")
check("guard: Hebrew letters rejected (round 3: «دרוזל»)", rp.summary_problem("ثغرة في دרוזל كور", "Drupal Core"))
c_a = rp.classify(dict(kind="news", title="Hackers Exploit N-able MailAssure Flaw While AI Agents Exploit MONAI Label Zero-Day", text="", score=None, kev=0))
c_b = rp.classify(dict(kind="news", title="UEFI bootkit infected fully patched Windows machines", text="", score=None, kev=0))
c_c = rp.classify(dict(kind="news", title="Meta brings its Muse AI assistant directly into Instagram DMs", text="", score=None, kev=0))
check("round 3 misclassifications fixed (security before AI, bootkit) and AI news still AI",
      c_a["type"] == "gen" and c_b["type"] == "gen" and c_c["type"] == "ai")
def bad(it): raise rp.BadSummary("الملخص يحتوي حروفاً صينية")
a9 = argparse.Namespace(db=os.path.join(tempfile.mkdtemp(), "t.db"), out=os.path.join(d, "o9.json"), hours=2, no_llm=False, no_alert=True)
s9 = rp.run(a9, dict(kev=lambda: (set(), []), nvd=lambda: [], rss=news), bad, None)
c9 = sqlite3.connect(a9.db)
check("bad summary: title+link published, not retried, other items still summarized",
      s9["published"] == 2 and s9.get("bad_summaries") == 2 and c9.execute("select count(*) from items where pending=1").fetchone()[0] == 0)
# [أسبوع 7 - جولة 4] أنماط النظام المتأثر التي فاتت في الجولة الرابعة، والتأكد أن الأنماط القديمة لم تنكسر
check("system: lowercase product + version (compose-farm)",
      rp.extract_system("compose-farm 0.19.0 before 1.22.0 contains a cross-site WebSocket hijacking") == "compose-farm")
check("system: 'Since Symfony 7.2'", rp.extract_system("Since Symfony 7.2, expressions can contain comments.") == "Symfony")
check("system: 'Version 2.1' is not a product", rp.extract_system("Version 2.1 of the plugin allows XSS") != "Version")
check("glossary has SSRF and deserialization terms", "تزوير الطلب" in rp.SUM_SYSTEM and "إلغاء التسلسل" in rp.SUM_SYSTEM)
# [أسبوع 7] أولوية التلخيص: الأخبار لا تبقى بلا ملخص حين تستهلك ثغرات NVD حد الدورة
from datetime import datetime as _dt, timezone as _tz
_now = _dt.now(_tz.utc).isoformat()
vul10 = [dict(kind="vuln", source="NVD", uid=f"CVE-2026-90{i:03d}", title=f"CVE-2026-90{i:03d}: Product{i} RCE", link=f"https://nvd.nist.gov/vuln/detail/CVE-2026-90{i:03d}",
              text=f"Product{i} before 2.0 allows remote code execution.", date=_now, score=8.1, kev=0, system="") for i in range(10)]
news3 = [dict(kind="news", source="ex.com", title=f"Tech news {i}", link=f"https://ex.com/n{i}", text="Some tech news text.", date=_now) for i in range(3)]
asked = []
def rec(it): asked.append(it["title"]); return "ملخص عربي تجريبي للخبر."
a10 = argparse.Namespace(db=os.path.join(tempfile.mkdtemp(), "t.db"), out=os.path.join(d, "o10.json"), hours=2, no_llm=False, no_alert=True, max_llm=4)
s10 = rp.run(a10, dict(kev=lambda: (set(), []), nvd=lambda: list(vul10), rss=lambda: list(news3), nvd_lookup=lambda u: None), rec, None)
check("summary budget goes to news first (3 news + 1 vuln within a cap of 4)",
      s10["llm_calls"] == 4 and all(t.startswith("Tech news") for t in asked[:3]))
c10 = sqlite3.connect(a10.db)
s10b = rp.run(a10, dict(kev=lambda: (set(), []), nvd=lambda: [], rss=lambda: [], nvd_lookup=lambda u: None), rec, None)
check("pending queue uses the whole remaining budget on the next cycle",
      s10b["llm_calls"] == 4 and c10.execute("select count(*) from items where pending=1").fetchone()[0] == 5)

# ---------------- المرحلة 3: تفاصيل الثغرة، فصل الخطورة عن الاستغلال، سجل الأحداث
# قاعدة قديمة (قبل أعمدة المرحلة 3) فيها ثغرة مستغلة درجتها 7.2 مخزنة «حرجة»: الترقية تضيف الأعمدة وتصحح الخطورة وتملأ السجل
dbo = os.path.join(tempfile.mkdtemp(), "old.db"); co = sqlite3.connect(dbo)
co.executescript("""CREATE TABLE items(uid TEXT PRIMARY KEY, kind, type, title, link, text, summary, pending INT, source, published,
  severity, score REAL, kev INT, system, status, reason, created); CREATE TABLE errors(ts, stage, msg);""")
co.execute("INSERT INTO items VALUES('CVE-2026-1200','vuln','vul','CVE-2026-1200: x','https://nvd/1200','Old desc.','ملخص.',0,'NVD',"
           "'2026-11-20T00:00:00+00:00','critical',7.2,1,'Acme','published',NULL,'2026-11-25T01:00:00+00:00')")
co.execute("INSERT INTO items VALUES('CVE-2026-1201','vuln','vul','CVE-2026-1201: y','https://nvd/1201','Other.','ثغرة أمنية خطورتها متوسطة.',0,'NVD',"
           "'2026-11-20T00:00:00+00:00','medium',5.0,0,'Acme','published',NULL,'2026-11-25T02:00:00+00:00')")
co.commit(); co.close()
cat = rp.KevIds({"CVE-2026-1201"}); cat.info["CVE-2026-1201"] = dict(kev_added="2026-11-26", kev_action="Apply updates.", kev_due="2026-12-17", kev_ransom="Unknown")
refreshed = []
def refresh(uid):
    refreshed.append(uid); return dict(score=9.1, vector="CVSS:3.1/AV:N", cvss_ver="3.1", modified="2026-11-26T10:00:00.000") if uid == "CVE-2026-1200" else None
ao = argparse.Namespace(db=dbo, out=os.path.join(tempfile.mkdtemp(), "site", "data.json"), hours=2, no_llm=True, no_alert=False)
sento = []
so = rp.run(ao, dict(kev=lambda: (cat, []), nvd=lambda: [], rss=lambda: [], refresh=refresh), None, lambda m: sento.append(m) or True)
co = sqlite3.connect(dbo); co.row_factory = sqlite3.Row
r0 = co.execute("select * from items where uid='CVE-2026-1200'").fetchone(); r1 = co.execute("select * from items where uid='CVE-2026-1201'").fetchone()
ev = [(e["kind"], e["uid"]) for e in co.execute("select * from events")]
check("old DB upgraded: new columns added, summary source inferred", r0["summary_src"] == "llm" and r1["summary_src"] == "template")
check("stored vuln found in CISA catalog -> exploited, with date and required action, severity unchanged",
      r1["kev"] == 1 and r1["kev_added"] == "2026-11-26" and r1["kev_action"] == "Apply updates." and r1["severity"] == "medium" and ("kev", "CVE-2026-1201") in ev)
check("refresh from NVD: new score 9.1 -> critical, last-modified and vector stored, change logged",
      r0["score"] == 9.1 and r0["severity"] == "critical" and r0["modified"].startswith("2026-11-26") and r0["vector"] == "CVSS:3.1/AV:N"
      and any(e["kind"] == "score" and e["detail"].startswith("7.2>9.1") for e in co.execute("select * from events")))
check("events backfilled from stored discovery time + fetch results logged",
      ("new", "CVE-2026-1200") in ev and sum(1 for k, _ in ev if k == "fetch") == 3)
check("alert sent for the newly exploited vuln and logged as an alert event", any("CVE-2026-1201" in m for m in sento) and ("alert", "CVE-2026-1201") in ev)
det = json.load(open(os.path.join(os.path.dirname(ao.out), "details.json"), encoding="utf-8"))["items"]
check("details.json carries original description, last-modified and CISA data",
      det["CVE-2026-1200"]["text"] == "Old desc." and det["CVE-2026-1200"]["modified"].startswith("2026-11-26") and det["CVE-2026-1201"]["kev_due"] == "2026-12-17")
dj = {i["id"]: i for i in json.load(open(ao.out, encoding="utf-8"))["items"]}
check("data.json says where each summary came from", dj["CVE-2026-1200"]["sum_src"] == "llm" and dj["CVE-2026-1201"]["sum_src"] == "template")
so2 = rp.run(ao, dict(kev=lambda: (cat, []), nvd=lambda: [], rss=lambda: [], refresh=refresh), None, lambda m: sento.append(m) or True)
evj = json.load(open(os.path.join(os.path.dirname(ao.out), "events.json"), encoding="utf-8"))
check("events.json: real events (no fetch noise) + last success per source",
      any(e["kind"] == "score" for e in evj["events"]) and not any(e["kind"] == "fetch" for e in evj["events"]) and evj["sources"]["nvd"]["last_ok"])
old_kev = [dict(kind="vuln", source="NVD", uid=f"CVE-2026-81{i:03d}", title=f"CVE-2026-81{i:03d}: n", link=f"https://nvd/{i}", text="d",
                date=f"2026-11-26T{i % 24:02d}:00:00+00:00", score=5.0) for i in range(260)]
ak = argparse.Namespace(db=os.path.join(tempfile.mkdtemp(), "t.db"), out=os.path.join(tempfile.mkdtemp(), "data.json"), hours=2, no_llm=True, no_alert=True)
oldk = dict(kind="vuln", source="CISA KEV", uid="CVE-2020-0001", title="CVE-2020-0001: old exploited", link="https://nvd/old", text="d",
            date="2020-01-01T00:00:00+00:00", score=None, kev=1)
rp.run(ak, dict(kev=lambda: ({"CVE-2020-0001"}, [oldk]), nvd=lambda: list(old_kev), rss=lambda: []), None, None)
ek = json.load(open(ak.out, encoding="utf-8"))["items"]
check("old exploited vuln is exported even when 250 newer vulns exist", any(i["id"] == "CVE-2020-0001" for i in ek) and len(ek) == 251)
check("refreshed items are not re-checked every cycle", so2["refreshed"] == 0 and len(refreshed) == 2)
check("severity scale: 9 critical, 7 high, 4 medium, 0.1 low, none unknown",
      [rp.severity_of(x) for x in (9.0, 7.0, 4.0, 0.1, None)] == ["critical", "high", "medium", "low", "unknown"])
print(f"\n{ok} checks passed")
