# -*- coding: utf-8 -*-
"""فحص استخراج النظام المتأثر على أوصاف CVE حقيقية من قاعدة جولة سابقة."""
import os, sys, sqlite3, random
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(HERE))
import radar_pipeline as rp
db = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "round0.db")
rows = sqlite3.connect(db).execute("select uid, text from items where kind='vuln' and source='NVD'").fetchall()
random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 1).shuffle(rows)
empty = 0
for uid, t in rows[:40]:
    s = rp.extract_system(t); empty += not s
    print(f"{s!r:40} <= {t[:85]}")
print(f"empty: {empty}/40")
