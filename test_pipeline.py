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
check("KEV score enriched from NVD (8.6) and kept critical", looked == ["CVE-2026-6666"] and k["score"] == 8.6 and k["severity"] == "critical")
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
print(f"\n{ok} checks passed")
