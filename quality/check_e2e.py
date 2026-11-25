# -*- coding: utf-8 -*-
"""يفحص ناتج تشغيل السكربت الحقيقي من سطر الأوامر (e2e_stdout.json و e2e_site.json و e2e.db)."""
import os, json, sqlite3
H = os.path.dirname(os.path.abspath(__file__))
s = json.loads(open(os.path.join(H, "e2e_stdout.json"), encoding="utf-8-sig").read())
print({k: v for k, v in s.items() if k not in ("critical", "alert_messages")})
print("alert messages:", len(s["alert_messages"]))
d = json.load(open(os.path.join(H, "e2e_site.json"), encoding="utf-8"))["items"]
print("exported", len(d), "| severities", sorted({str(x["severity"]) for x in d}), "| with summary", sum(bool(x["summary"]) for x in d))
c = sqlite3.connect(os.path.join(H, "e2e.db"))
for t, sm in c.execute("select title, summary from items where kind='news' and summary != ''").fetchall():
    print("-", t[:70], "=>", sm)
print("errors table:", c.execute("select stage, msg from errors").fetchall())
