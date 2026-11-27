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
summ = lambda it: "ملخص عربي قصير يصف الخبر بدقة."

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
check("breach news is security news (sec), not devices", b["type"] == "sec")

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
def spy(it): llm_seen.append(it["title"]); return "ملخص عربي للثغرة من نص المصدر."
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
check("guard: 'و' before Latin name allowed", rp.summary_problem("تعاونت الشركات و Megaspeed مع الحكومة.", src) is None)
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
      c_a["type"] == "sec" and c_b["type"] == "sec" and c_c["type"] == "ai")
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
co.execute("INSERT INTO items VALUES('CVE-2026-1200','vuln','vul','CVE-2026-1200: x','https://nvd/1200','Old desc.','ملخص عربي سليم لهذه الثغرة.',0,'NVD',"
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
check("events backfilled from stored discovery time + fetch results logged (kev, nvd, rss, upd)",
      ("new", "CVE-2026-1200") in ev and sum(1 for k, _ in ev if k == "fetch") == 4)
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
# [المرحلة 4] الإحصائيات تُحسب من القاعدة كاملة
sj = json.load(open(os.path.join(os.path.dirname(ak.out), "stats.json"), encoding="utf-8"))
check("stats.json counts the whole DB (261 vulns), severity split and KEV",
      sj["vulns"]["total"] == 261 and sj["vulns"]["by_sev"]["medium"] == 260 and sj["vulns"]["kev"] == 1 and sum(sj["vulns"]["by_sev"].values()) == 261)
check("stats.json daily series covers 14 days and sums only dated-in-window vulns",
      len(sj["daily"]) == 14 and sj["daily"][-1]["day"] >= "2026-11-26" and sum(d["total"] for d in sj["daily"]) <= 261)
check("product names de-duplicated for stats", rp.clean_system("WP User Manager WP User Manager") == "WP User Manager" and rp.clean_system("Apache Tomcat") == "Apache Tomcat")
cw = sqlite3.connect(":memory:"); cw.executescript(rp.SCHEMA)
w0 = rp.nvd_window(cw, 2)
cw.execute("INSERT INTO events VALUES(?,?,?,?)", ((rp.datetime.now(rp.timezone.utc) - rp.timedelta(hours=9)).isoformat(timespec="seconds"), "", "fetch", "nvd:ok"))
w9 = rp.nvd_window(cw, 2)
cw.execute("INSERT INTO events VALUES(?,?,?,?)", ((rp.datetime.now(rp.timezone.utc) - rp.timedelta(minutes=50)).isoformat(timespec="seconds"), "", "fetch", "nvd:ok"))
check("NVD window covers the time the machine was off (9h gap -> 10h), never below the default 2h",
      w0 == 2 and w9 == 10 and rp.nvd_window(cw, 2) == 2)
check("refreshed items are not re-checked every cycle", so2["refreshed"] == 0 and len(refreshed) == 2)
check("severity scale: 9 critical, 7 high, 4 medium, 0.1 low, none unknown",
      [rp.severity_of(x) for x in (9.0, 7.0, 4.0, 0.1, None)] == ["critical", "high", "medium", "low", "unknown"])

# ---------------- المرحلة 6: جودة الملخصات والبيانات
src6 = "A flaw was found in the SAML identity brokering component of Keycloak. It may allow account takeover."
check("claim guard: «دون مصادقة» rejected when the source never says unauthenticated",
      "دون مصادقة" in (rp.summary_problem("ثغرة في Keycloak تسمح بالاستيلاء على الحسابات دون مصادقة.", src6) or ""))
check("claim guard: same claim accepted when the source says it",
      rp.summary_problem("ثغرة في Keycloak تسمح بالاستيلاء على الحسابات دون مصادقة.", src6 + " An unauthenticated attacker can do it.") is None)
check("claim guard: «عن بُعد» needs remote/network in the source",
      bool(rp.summary_problem("ثغرة في Keycloak يمكن استغلالها عن بُعد.", src6)) and rp.summary_problem("ثغرة في Keycloak يمكن استغلالها عن بُعد.", src6 + " remote attackers") is None)
check("broken output rejected: repeated words, truncated sentence",
      bool(rp.summary_problem("طبيق تطبيق تطبيق تطبيق تطبيق تطبيق تطبيق تطبيق.", "app")) and bool(rp.summary_problem("ثغرة في Keycloak تسمح للمهاجم بالاستيلاء على", src6)))
check("product: 'component of Keycloak' -> Keycloak (not SAML)", rp.extract_system(src6) == "Keycloak")
check("product: Joomla extension name taken from the description",
      rp.extract_system("Joomla Extension - chronoengine.com - Unauthenticated arbitrary file upload in ChronoForms extension 8.0.0-8.0.53 - When") == "Joomla ChronoForms")
check("product: repeated name merged", rp.extract_system("Missing Authorization vulnerability in WP User Manager WP User Manager wp-user-manager allows X.") == "WP User Manager")
check("product: algorithm names are not products (Crypt::JWT, not A128CBC-HS256)",
      rp.extract_system("Crypt::JWT versions before 0.037_1 for Perl compare HMAC signatures. decode_jwt compares HS256 and A128CBC-HS256 tags.") == "Crypt::JWT"
      and rp.extract_system("Issue in A128CBC-HS256 handling.") != "A128CBC-HS256")
sw = rp.classify(dict(kind="news", title="SonicWall Warns Gen 6 Firewalls Won't Get Security Patches", text="Unlike newer AI features, old devices lose support.", score=None, kev=0))
ai6 = rp.classify(dict(kind="news", title="OpenAI ships a new AI model", text="", score=None, kev=0))
check("AI type needs the term in the title or twice in the text", sw["type"] != "ai" and ai6["type"] == "ai")
# البيانات المخزنة تُفحص بالقواعد الجديدة مرة واحدة
dq = os.path.join(tempfile.mkdtemp(), "q.db"); cq = sqlite3.connect(dq); cq.executescript(rp.SCHEMA); rp.migrate(cq)
cq.execute("DELETE FROM meta")
cq.execute("INSERT INTO items(uid,kind,type,title,text,summary,pending,source,status,summary_src,system) VALUES"
           "('CVE-2026-6001','vuln','vul','CVE-2026-6001: x',?,'ثغرة في Keycloak يمكن استغلالها دون مصادقة.',0,'NVD','published','llm','SAML')", (src6,))
cq.execute("INSERT INTO items(uid,kind,type,title,text,summary,pending,source,status,summary_src) VALUES"
           "('n1','news','ai','SonicWall Warns Gen 6 Firewalls Won''t Get Patches','Old devices, unlike AI ones, lose support.','',0,'x','published','')")
rq = rp.requality(cq); rq2 = rp.requality(cq)
r6 = cq.execute("select summary, pending, summary_src, system from items where uid='CVE-2026-6001'").fetchone()
check("stored summary with an unsupported claim is pulled and queued again; product and news type corrected; runs once",
      r6 == ("", 1, "", "Keycloak") and cq.execute("select type from items where uid='n1'").fetchone()[0] == "gen"
      and rq["summaries_pulled"] == 1 and rq2 == {})
# [المرحلة 7] ما كشفه تقرير PDF: مصطلح من المسرد مُقحم، وحرف لاتيني شارد
esx = "ESX contains a heap out-of-bounds write vulnerability in the I/O filter service. Broadcom has evaluated the severity as Critical, CVSSv3 9.8."
check("glossary term not in the source is rejected («المفوضية الأوروبية» in a VMware CVE)",
      "المفوضية" in (rp.summary_problem("تحتوي ESX على ثغرة كتابة خارج الحدود. تُصنف المفوضية الأوروبية خطورتها 9.8.", esx) or "")
      and rp.summary_problem("تحتوي ESX على ثغرة كتابة خارج الحدود، وتصنف Broadcom خطورتها 9.8.", esx) is None)
check("stray Latin letter inside a name is rejected",
      bool(rp.summary_problem("ثغرة في توسعة Joomla J ChronoForms تسمح برفع ملفات.", "Joomla Extension ChronoForms extension upload")))
# ---------------------------------------------------------------- [CTI] risk engine
from datetime import datetime, timezone, timedelta
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
cv = rp.parse_nvd({"vulnerabilities": [{"cve": {"id": "CVE-2026-2001", "published": "2026-11-26T07:00:00.000", "vulnStatus": "Analyzed",
      "descriptions": [{"lang": "en", "value": "RCE in Foo."}], "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}, {"lang": "en", "value": "NVD-CWE-noinfo"}]}],
      "references": [{"url": "https://ex.com/poc", "tags": ["Exploit", "Third Party Advisory"]}, {"url": "https://ex.com/fix", "tags": ["Patch"]},
                     {"url": "https://ex.com/news", "tags": ["Press/Media Coverage"]}, {"url": "javascript:alert(1)", "tags": ["Patch"]}],
      "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]})[0]
check("NVD refs: only Exploit/Patch/Advisory tags kept, non-http links dropped; CWE and status stored",
      json.loads(cv["refs"]) == [{"u": "https://ex.com/poc", "t": ["Exploit"]}, {"u": "https://ex.com/fix", "t": ["Patch"]}]
      and cv["cwe"] == "CWE-78" and cv["nvd_status"] == "Analyzed")
base = dict(score=9.8, kev=0, refs="[]", text="RCE.", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N", published="2026-11-26T07:00:00+00:00")
r0 = rp.risk_score(base, NOW)
check("risk is reproducible: same inputs and time give the same score", r0 == rp.risk_score(dict(base), NOW))
# known: cvss .98*35 + exploitation 0*50 + exposure 1*10 = 44.3 / 95 -> 47 (patch unknown -> left out of the weight)
check("unknown patch info is excluded from the weight: 9.8, no exploitation evidence = 47 medium",
      r0["score"] == 47 and r0["level"] == "medium" and r0["factors"]["exploitation"][0] == 0.0 and r0["factors"]["patch"][0] is None)
rk = rp.risk_score(dict(base, kev=1), NOW)
check("KEV raises the score to critical (99), severity field itself is not touched", rk["score"] == 99 and rk["level"] == "critical")
rp_ = rp.risk_score(dict(base, kev=1, refs=cv["refs"]), NOW)
check("KEV + exploit tag + patch reference: exploitation stays 1 (KEV), patch lowers, evidence recorded", rp_["evidence"].get("exploit") == "nvd"
      and rp_["evidence"].get("patch") == 1 and rp_["evidence"].get("kev") == 1 and rp_["factors"]["patch"][0] == 0.0
      and rp_["score"] == round(100 * (34.3 + 50 + 10) / 100))
rc = rp.risk_score(dict(base, text="The exploit has been released to the public and may be used."), NOW)
check("public exploit (CNA description) = exploitation 0.7, not confirmed: 9.8 becomes high (83)",
      rc["evidence"]["exploit"] == "cna" and "kev" not in rc["evidence"] and rc["factors"]["exploitation"][0] == 0.7
      and rc["score"] == 83 and rc["level"] == "high")
check("'exploited in the wild' text alone does NOT count (only CISA KEV confirms exploitation)",
      rp.risk_score(dict(base, text="This flaw is exploited in the wild."), NOW)["factors"]["exploitation"][0] == 0.0)
check("no CVSS and not in KEV -> not enough data (None)", rp.risk_score(dict(base, score=None), NOW) is None)
rn = rp.risk_score(dict(base, score=None, kev=1), NOW)
check("KEV without CVSS still scored from known factors", rn is not None and rn["factors"]["cvss"][0] is None and rn["level"] == "critical")
old = rp.risk_score(dict(base, score=5.0, vector="CVSS:3.1/AV:L/PR:L/UI:R", published="2025-01-01T00:00:00+00:00"), NOW)
check("old local medium vuln is low risk (exposure = mean(recency .4, AV:L .3))", old["factors"]["exposure"][0] == 0.35 and old["level"] == "low")
check("risk levels thresholds 90/70/40", [next(l for t, l in rp.RISK_LEVELS if s_ >= t) for s_ in (90, 89, 70, 69, 40, 39)]
      == ["critical", "high", "high", "medium", "medium", "low"])
# export: risk in data.json, factors in details.json, distribution in stats.json
dr = tempfile.mkdtemp()
ar = argparse.Namespace(db=os.path.join(dr, "r.db"), out=os.path.join(dr, "data.json"), hours=2, no_llm=True, no_alert=True, max_llm=30)
cvi = dict(cv, date=(datetime.now(timezone.utc) - timedelta(hours=3)).isoformat())
rp.run(ar, dict(kev=lambda: ({"CVE-2026-2001"}, []), nvd=lambda: [dict(cvi)], rss=lambda: [], refresh=lambda u: None), None, None)
dj = json.load(open(ar.out, encoding="utf-8")); de = json.load(open(os.path.join(dr, "details.json"), encoding="utf-8"))
st = json.load(open(os.path.join(dr, "stats.json"), encoding="utf-8"))
it = next(i for i in dj["items"] if i["id"] == "CVE-2026-2001")
check("export: risk + level in data.json, factors/evidence/refs in details.json, by_risk in stats.json",
      it["risk_level"] == "critical" and isinstance(it["risk"], int) and dj["risk_model"]["weights"]["exploitation"] == 50
      and de["items"]["CVE-2026-2001"]["risk_f"]["exploitation"] == [1.0, 50] and de["items"]["CVE-2026-2001"]["refs"][0]["t"] == ["Exploit"]
      and st["vulns"]["by_risk"]["critical"] == 1 and st["vulns"]["public_exploit"] == 1)
# ---------------------------------------------------------------- [CTI] pillar 3: security updates
UNOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
chrome_raw = dict(title="Stable Channel Update for Desktop", link="https://chromereleases.googleblog.com/2026/11/stable.html", date="2026-11-25T10:00:00-08:00",
                  text="<p>The Stable channel has been updated to 159.0.8154.33/.34 for Windows, Mac.</p><p>Security Fixes and Rewards</p>"
                       "<p>[$5000][123] High CVE-2026-9001: Use after free in V8. [N/A] High CVE-2026-9002: Type confusion.</p>"
                       "<p>Google is aware that an exploit for CVE-2026-9001 exists in the wild.</p>")
cu = rp.parse_update(chrome_raw, "Google Chrome", UNOW)
check("Chrome stable: patch, fixed version, CVEs, vendor states exploitation",
      cu["utype"] == "patch" and cu["fixed_ver"] == "159.0.8154.33/.34" and cu["cves"] == "CVE-2026-9001,CVE-2026-9002"
      and cu["vendor_flag"] == "exploited" and cu["kind"] == "update" and cu["system"] == "Google Chrome")
check("Chrome Beta/Dev entries are skipped; a stable update with no security fixes is a general release",
      rp.parse_update(dict(chrome_raw, title="Chrome Beta for Desktop Update"), "Google Chrome", UNOW) is None
      and rp.parse_update(dict(chrome_raw, text="The Stable channel has been updated to 1.2.3.4 for Windows."), "Google Chrome", UNOW)["utype"] == "release")
check("entries older than 30 days are not imported", rp.parse_update(dict(chrome_raw, date="2026-09-01T00:00:00Z"), "Google Chrome", UNOW) is None)
uu = rp.parse_update(dict(title="USN-9214-1: GNU binutils vulnerabilities", link="https://ubuntu.com/security/notices/USN-9214-1",
                          date="Thu, 26 Nov 2026 22:34:55 +0000", text="It was discovered that binutils mishandled input. This issue only affected "
                          "Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2026-1111)"), "Ubuntu", UNOW)
check("Ubuntu notice: product from title, affected releases from text", uu["product"] == "GNU binutils"
      and uu["affected_ver"] == "Ubuntu 22.04 LTS, 24.04 LTS" and uu["utype"] == "patch" and uu["fixed_ver"] == "")
cs = rp.parse_update(dict(title="Vulnerabilities in nginx Affecting Cisco Products: November 2026", link="https://sec.cloudapps.cisco.com/x",
                          date="2026-11-26 01:48:13.0", text="These vulnerabilities affect nginx releases 1.9.5 through 1.31.8 and is fixed in releases "
                          "1.31.9 (mainline) and 1.30.7 (stable). CVE-2026-113425"), "Cisco", UNOW)
check("Cisco advisory: affected and fixed releases only from explicit wording",
      cs["utype"] == "advisory" and cs["affected_ver"] == "nginx 1.9.5 through 1.31.8" and cs["product"] == "nginx" and cs["fixed_ver"] == "1.31.9 (mainline) and 1.30.7 (stable)")
RDF = b"""<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<item rdf:about="https://lists.debian.org/x"><title>DSA-6060-1 chromium - security update</title><link>https://lists.debian.org/x</link>
<description>Security issues were found in chromium.</description><dc:date>2026-11-26T10:00:00Z</dc:date></item></rdf:RDF>"""
dd = rp.parse_update(rp.parse_feed(RDF, "Debian")[0], "Debian", UNOW)
check("RSS 1.0 (Debian) parsed: DSA product and link", dd["product"] == "chromium" and dd["link"] == "https://lists.debian.org/x")
ATOM2 = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>T</title><link rel="replies" href="https://ex.com/comments"/>
<link rel="alternate" href="https://ex.com/post"/><updated>2026-11-26T09:00:00Z</updated></entry></feed>"""
check("Atom: the rel=alternate article link is used, not the comments link", rp.parse_feed(ATOM2, "x")[0]["link"] == "https://ex.com/post")
s_upd = rp.update_summary(cu)
check("update summary is built from facts only (vendor, CVE count, fixed version, vendor exploitation note)",
      s_upd.startswith("تحديث أمني من Google Chrome") and "يعالج ثغرتين" in s_upd and "159.0.8154.33/.34" in s_upd and "مستغلة فعلياً" in s_upd)
# run(): updates stored, linked to KEV, exported with their fields, never trigger a Telegram vulnerability alert
du = tempfile.mkdtemp(); au = argparse.Namespace(db=os.path.join(du, "u.db"), out=os.path.join(du, "data.json"), hours=2, no_llm=True, no_alert=False, max_llm=30)
sent_u = []
uu_now = dict(uu, date=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat())
su = rp.run(au, dict(kev=lambda: ({"CVE-2026-1111"}, []), nvd=lambda: [], rss=lambda: [], upd=lambda: [dict(uu_now)], refresh=lambda u: None),
            None, lambda m: sent_u.append(m) or True)
du_j = json.load(open(au.out, encoding="utf-8")); ui = next(i for i in du_j["items"] if i["type"] == "upd")
check("update stored and exported: type upd, utype, product, affected, CVEs, template summary, action because its CVE is in CISA KEV",
      ui["utype"] == "patch" and ui["product"] == "GNU binutils" and ui["cves"] == ["CVE-2026-1111"] and ui["action"] is True
      and ui["kev"] is True and ui["sum_src"] == "template" and ui["summary"].startswith("تحديث أمني من Ubuntu"))
check("no Telegram alert for an update (alerts stay for vulnerabilities)", sent_u == [] and su["alerts_sent"] == 0)
st_u = json.load(open(os.path.join(du, "stats.json"), encoding="utf-8"))["updates"]
check("stats.json has the updates pillar", st_u["total"] == 1 and st_u["action"] == 1 and st_u["by_vendor"] == {"Ubuntu": 1})
check("security news is its own type, general tech news stays gen",
      rp.classify(dict(kind="news", title="Ransomware gang hits hospital", text="", score=None, kev=0))["type"] == "sec"
      and rp.classify(dict(kind="news", title="New laptop chips announced at trade show", text="", score=None, kev=0))["type"] in ("gen", "dev"))
# ---------------------------------------------------------------- [CTI] trends & analytics
dt_ = tempfile.mkdtemp(); ct = sqlite3.connect(os.path.join(dt_, "t.db")); ct.row_factory = sqlite3.Row; ct.executescript(rp.SCHEMA); rp.migrate(ct)
gen_t = "2026-11-27T09:00:00+00:00"          # = 12:00 Riyadh, 27 Nov
def H(uid, when, score, cwe="", text=""):
    rp.history_put(ct, dict(uid=uid, date=when, score=score, cwe=cwe, text=text))
H("CVE-2026-1", "2026-11-20T10:00:00+00:00", 9.8, "CWE-79", "Stored XSS in WordPress plugin Foo before 1.2.")
H("CVE-2026-2", "2026-11-26T10:00:00+00:00", 7.5, "CWE-79,CWE-89")
H("CVE-2026-3", "2026-11-27T05:00:00+00:00", 5.0, "CWE-89")
H("CVE-2026-3", "2026-11-27T05:00:00+00:00", 9.1, "")          # refreshed score, CWE kept
H("CVE-2026-4", "2026-11-26T22:30:00+00:00", 9.0)                # 22:30 UTC = 01:30 on 27 Nov in Riyadh
ct.execute("INSERT INTO items(uid,kind,type,title,link,status,published,created,severity,source,kev) VALUES"
           "('CVE-2026-2','vuln','vul','x','l','published','2026-11-26T10:00:00+00:00','2026-11-20T00:00:00+00:00','high','NVD',1)")
ct.execute("INSERT INTO items(uid,kind,type,title,link,status,published,created) VALUES('n1','news','sec','x','l1','published','2026-11-25T10:00:00+00:00','2026-11-24T00:00:00+00:00')")
ct.execute("INSERT INTO items(uid,kind,type,title,link,status,published,created) VALUES('n2','news','gen','x','l2','published','2026-11-20T10:00:00+00:00','2026-11-24T00:00:00+00:00')")
ct.execute("INSERT INTO items(uid,kind,type,title,link,status,published,created,utype) VALUES('u1','update','upd','x','l3','published','2026-11-26T10:00:00+00:00','2026-11-27T00:00:00+00:00','patch')")
ct.execute("INSERT INTO meta VALUES('kev_added_daily', ?)", (json.dumps({"2026-11-26": 2, "2026-08-01": 5}),))
T = rp.trends(ct, gen_t); D = T["days"]; Sx = T["series"]; at = lambda k, d: Sx[k][D.index(d)]
check("trends: 90 Riyadh days ending today", len(D) == 90 and D[-1] == "2026-11-27" and D[0] == "2026-08-30")
check("trends: vulnerabilities per day by severity, days counted in Riyadh time, refreshed score used",
      at("v_total", "2026-11-27") == 2 and at("v_critical", "2026-11-27") == 2 and at("v_high", "2026-11-26") == 1 and at("v_kev", "2026-11-26") == 1)
check("trends: days before the history starts are null (not observed), not zero",
      T["coverage"]["vulns"] == "2026-11-21" and at("v_total", "2026-11-20") is None and at("v_total", "2026-11-22") == 0)
check("trends: KEV additions from the CISA catalog dates; outside the window ignored", at("kev_added", "2026-11-26") == 2 and sum(x or 0 for x in Sx["kev_added"]) == 2)
check("trends: news by type from first collection day, older backlog not counted as complete",
      T["coverage"]["news"] == "2026-11-24" and at("n_sec", "2026-11-25") == 1 and at("n_gen", "2026-11-20") is None)
check("trends: updates by kind, covered 30 days back from first fetch", at("u_patch", "2026-11-26") == 1 and T["coverage"]["updates"] == "2026-10-29")
r7 = T["ranges"]["7"]
check("trends: 7-day ranking of weakness types and products", r7["total"] == 3 and r7["cwe"][0] == ["CWE-89", 2] and r7["with_cwe"] == 2
      and T["ranges"]["90"]["cwe"][0] == ["CWE-79", 2] and T["ranges"]["90"]["products"][0][0] == "WordPress")
check("trends: labelled as history, no forecasting", "no forecasting" in T["note"])
# ---------------------------------------------------------------- [CTI] daily intelligence report
dr_ = tempfile.mkdtemp(); cr = sqlite3.connect(os.path.join(dr_, "r.db")); cr.row_factory = sqlite3.Row; cr.executescript(rp.SCHEMA); rp.migrate(cr)
def VI(uid, pub, score, kev=0, kev_added=None, text="RCE.", sev=None):
    cr.execute("INSERT INTO items(uid,kind,type,title,link,text,status,published,nvd_published,created,severity,score,kev,kev_added,source,system,summary_src,vector)"
               " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (uid, "vuln", "vul", uid + ": x", "https://nvd.nist.gov/vuln/detail/" + uid, text, "published",
               pub, pub, pub, sev or rp.severity_of(score), score, kev, kev_added, "NVD", "Foo", "template", "CVSS:3.1/AV:N/PR:N/UI:N"))
# Riyadh day 2026-11-26 = 2026-11-25T21:00Z .. 2026-11-26T21:00Z
VI("CVE-2026-7001", "2026-11-26T10:00:00+00:00", 9.8, kev=1, kev_added="2026-11-26")
VI("CVE-2026-7002", "2026-11-26T11:00:00+00:00", 9.1, text="The exploit has been disclosed to the public.")
VI("CVE-2026-7003", "2026-11-26T12:00:00+00:00", 5.0)
VI("CVE-2026-7004", "2026-11-25T20:00:00+00:00", 9.9)              # 23:00 Riyadh on the 25th: not in the report
VI("CVE-2026-7005", "2026-11-26T22:00:00+00:00", 9.9)              # 01:00 Riyadh on the 27th: not in the report
cr.execute("INSERT INTO items(uid,kind,type,title,link,status,published,created,system,utype,fixed_ver,cves,kev,vendor_flag) VALUES"
           "('u1','update','upd','Stable Channel Update','https://chromereleases.googleblog.com/x','published','2026-11-26T09:00:00+00:00','2026-11-26T09:30:00+00:00','Google Chrome','patch','1.2.3.4','CVE-2026-9001',0,'exploited')")
cr.execute("INSERT INTO items(uid,kind,type,title,link,status,published,created,source,summary,summary_src) VALUES"
           "('n1','news','sec','Ransomware hits X','https://ex.com/n1','published','2026-11-26T08:00:00+00:00','2026-11-26T08:10:00+00:00','ex.com','ملخص','llm')")
for ts_, d_ in [("2026-11-26T05:05:00+00:00", "nvd:ok"), ("2026-11-26T05:05:00+00:00", "kev:ok"), ("2026-11-26T06:05:00+00:00", "nvd:fail:HTTP Error 503: Service Unavailable"),
                ("2026-11-26T06:05:00+00:00", "kev:ok"), ("2026-11-27T05:05:00+00:00", "nvd:ok")]:
    cr.execute("INSERT INTO events VALUES(?,?,?,?)", (ts_, "", "fetch", d_))
made = rp.make_reports(cr, "2026-11-27T09:00:00+00:00")
rep = json.loads(cr.execute("SELECT body FROM reports WHERE day='2026-11-26'").fetchone()[0])
check("daily report: built only for finished days on which the radar ran, once", made == ["2026-11-26"]
      and rp.make_reports(cr, "2026-11-27T10:00:00+00:00") == [])
check("daily report: counts use the Riyadh day boundaries", rep["counts"]["vulns"] == 3 and rep["counts"]["critical"] == 2 and rep["counts"]["kev_added"] == 1)
check("daily report: top vulnerabilities ranked by risk score (KEV first), with risk and exploit evidence",
      [v["id"] for v in rep["top_vulns"]] == ["CVE-2026-7001", "CVE-2026-7002", "CVE-2026-7003"] and rep["top_vulns"][0]["risk_level"] == "critical"
      and rep["top_vulns"][1]["exploit"] == "cna" and rep["counts"]["public_exploit"] == 1)
check("daily report: KEV list, updates needing action, security news", rep["kev"][0]["id"] == "CVE-2026-7001" and rep["kev"][0]["added"] == "2026-11-26"
      and rep["updates"][0]["action"] is True and rep["updates"][0]["fixed"] == "1.2.3.4" and rep["counts"]["updates_action"] == 1
      and rep["news_security"][0]["title"] == "Ransomware hits X" and rep["news_tech"] == [])
check("daily report: collection failures disclosed with the error", rep["collection"]["sources"]["nvd"] == {"ok": 1, "fail": 1, "errors": ["HTTP Error 503: Service Unavailable"]}
      and rep["collection"]["cycles"] == 2 and rep["collection"]["collected"]["vuln"] == 3)
export_dir = os.path.join(dr_, "site"); rp.export_reports(cr, export_dir)
check("daily report: archive exported (index + one file per day)",
      json.load(open(os.path.join(export_dir, "reports", "index.json"), encoding="utf-8"))["reports"][0]["day"] == "2026-11-26"
      and os.path.exists(os.path.join(export_dir, "reports", "2026-11-26.json")))
# ---------------------------------------------------------------- [CTI] threat map: geography only when stated
g1 = rp.geo_facts("China-Linked Hackers Exploit VMware Zero-Day", "")
check("map: attributed origin from 'X-linked hackers', with the matched words as evidence",
      g1 and g1[0][:2] == ("CN", "origin") and "China-Linked Hackers" in g1[0][2])
check("map: victim location after an attack verb ('breached a Russian organization', 'targeting Indian banks')",
      rp.geo_facts("Attackers breached a Russian organization using a public PoC.", "")[0][:2] == ("RU", "victim")
      and rp.geo_facts("Hackers targeting Indian banks stole funds.", "")[0][:2] == ("IN", "victim"))
check("map: the nationality of the accused company is NOT a victim location", rp.geo_facts("The Chinese telecom giant was accused of stealing code.", "") == [])
check("map: a country named outside any attack sentence is not placed",
      rp.geo_facts("Nvidia pauses chip shipments to Singapore", "The company cited demand in China.") == [])
check("map: 'South Korea's power giant confirms data breach' -> victim", rp.geo_facts("South Korea’s power giant KEPCO confirms data breach", "")[0][:2] == ("KR", "victim"))
check("map: threat category from keywords", rp.threat_category("New ransomware gang extorts hospitals") == "ransomware"
      and rp.threat_category("Iranian APT espionage campaign") == "espionage")
dm = tempfile.mkdtemp(); cm = sqlite3.connect(os.path.join(dm, "m.db")); cm.row_factory = sqlite3.Row; cm.executescript(rp.SCHEMA); rp.migrate(cm)
nowm = datetime.now(timezone.utc)
for uid_, ty_, ti_, days_ in [("m1", "sec", "North Korea-Linked hackers poison GitHub repositories", 2), ("m2", "sec", "New phishing kit targets banks", 3),
                              ("m3", "ai", "OpenAI ships a model", 1), ("m4", "sec", "Iranian APT hits telecoms", 45)]:
    cm.execute("INSERT INTO items(uid,kind,type,title,text,link,source,status,published) VALUES(?,?,?,?,?,?,?,?,?)",
               (uid_, "news", ty_, ti_, "", "https://ex.com/" + uid_, "ex.com", "published", (nowm - timedelta(days=days_)).isoformat()))
TM = rp.threat_map(cm, nowm.isoformat(timespec="seconds"))
check("map: located incidents, unlocated security news listed apart, non-security news and items older than 30 days left out",
      [i["id"] for i in TM["incidents"]] == ["m1"] and [u["id"] for u in TM["unlocated"]] == ["m2"]
      and TM["incidents"][0]["places"][0]["role"] == "origin" and TM["incidents"][0]["severity"] == "unknown" and TM["countries"]["KP"]["ar"] == "كوريا الشمالية")
print(f"\n{ok} checks passed")
