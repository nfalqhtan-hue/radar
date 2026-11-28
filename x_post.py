#!/usr/bin/env python3
"""Daily X (Twitter) post for Tech Radar: the day's most important vulnerability, security update and tech story,
with a summary card image rendered from an HTML template by headless Edge (correct Arabic shaping, Dubai font).

  python x_post.py --check    verify the API keys (reads the account name only, posts nothing)
  python x_post.py --draft    build today's text and card into _work/x/ without posting
  python x_post.py --post     build and publish (used by the daily scheduled task at 13:00)

Keys come only from environment variables X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_SECRET and are never
printed or written anywhere. Content comes only from the radar's own published data; every item links back to the
site, where each record links to its official source. Standard library only, plus Microsoft Edge for the image.
"""
import os, re, sys, json, time, hmac, hashlib, base64, uuid, html, argparse, subprocess, shutil, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.join(ROOT, "site")
OUT = os.path.join(ROOT, "_work", "x")
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
SITE_URL = "https://nfalqhtan-hue.github.io/radar/"
RIYADH = timezone(timedelta(hours=3))
LOG = os.path.join(ROOT, "x_post.log")

# ---------------------------------------------------------------- OAuth 1.0a (user context), HMAC-SHA1
def _keys():
    k = {n: os.environ.get(n, "").strip() for n in ("X_API_KEY", "X_API_SECRET", "X_ACCESS_TOKEN", "X_ACCESS_SECRET")}
    missing = [n for n, v in k.items() if not v]
    if missing: raise SystemExit("missing environment variables: " + ", ".join(missing))
    return k

def _q(s): return urllib.parse.quote(str(s), safe="~-._")

def _auth(method, url, params=None):
    k = _keys()
    o = {"oauth_consumer_key": k["X_API_KEY"], "oauth_nonce": uuid.uuid4().hex, "oauth_signature_method": "HMAC-SHA1",
         "oauth_timestamp": str(int(time.time())), "oauth_token": k["X_ACCESS_TOKEN"], "oauth_version": "1.0"}
    allp = dict(o); allp.update(params or {})
    base = "&".join([method.upper(), _q(url), _q("&".join(f"{_q(a)}={_q(b)}" for a, b in sorted(allp.items())))])
    key = f"{_q(k['X_API_SECRET'])}&{_q(k['X_ACCESS_SECRET'])}".encode()
    o["oauth_signature"] = base64.b64encode(hmac.new(key, base.encode(), hashlib.sha1).digest()).decode()
    return "OAuth " + ", ".join(f'{_q(a)}="{_q(b)}"' for a, b in sorted(o.items()))

def _call(method, url, body=None, headers=None, sign_params=None):
    h = {"Authorization": _auth(method, url, sign_params), "User-Agent": "tech-radar-bot/1.0"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"HTTP {e.code} from {url.split('?')[0]}: {txt}")

def check():
    st, d = _call("GET", "https://api.x.com/2/users/me")
    u = d.get("data", {})
    print(f"keys OK: @{u.get('username')} ({u.get('name')})")

def upload_media(path):
    """Media upload (v2 endpoint, multipart). OAuth signature covers no body params for multipart."""
    boundary = uuid.uuid4().hex
    data = open(path, "rb").read()
    parts = [f"--{boundary}\r\nContent-Disposition: form-data; name=\"media_category\"\r\n\r\ntweet_image\r\n".encode(),
             f"--{boundary}\r\nContent-Disposition: form-data; name=\"media\"; filename=\"card.png\"\r\nContent-Type: image/png\r\n\r\n".encode(),
             data, f"\r\n--{boundary}--\r\n".encode()]
    st, d = _call("POST", "https://api.x.com/2/media/upload", b"".join(parts), {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    mid = (d.get("data") or {}).get("id") or d.get("media_id_string")
    if not mid: raise RuntimeError("media upload returned no id: " + json.dumps(d)[:300])
    return str(mid)

def tweet(text, media_id=None):
    body = {"text": text}
    if media_id: body["media"] = {"media_ids": [media_id]}
    st, d = _call("POST", "https://api.x.com/2/tweets", json.dumps(body).encode(), {"Content-Type": "application/json"})
    return d.get("data", {}).get("id")

# ---------------------------------------------------------------- content: only from the radar's published data
# One post a day. The kind rotates by date: tech news, security news, vulnerability (2026-11-28 = tech news).
# If today's kind has nothing new and unposted, the next kind is used. Posted items are remembered so none repeats.
KINDS = ("tech", "sec", "vul")
ROTATION_START = datetime(2026, 11, 28, tzinfo=RIYADH).date()
POSTED = os.path.join(OUT, "posted.json")
LEVEL = {"critical": "حرجة", "high": "عالية", "medium": "متوسطة", "low": "منخفضة"}
RISK = {"critical": "حرج", "high": "عالٍ", "medium": "متوسط", "low": "منخفض"}
SRC = {"feeds.feedburner.com": "The Hacker News", "feeds.arstechnica.com": "Ars Technica", "www.theverge.com": "The Verge",
       "techcrunch.com": "TechCrunch", "www.bleepingcomputer.com": "BleepingComputer"}

def _t(s):
    try: return datetime.fromisoformat((s or "").replace("Z", "+00:00"))
    except ValueError: return None

def posted_ids():
    try: return set(json.load(open(POSTED, encoding="utf-8")))
    except (OSError, ValueError): return set()

def remember(item_id):
    ids = sorted(posted_ids() | {item_id})[-500:]
    os.makedirs(OUT, exist_ok=True); json.dump(ids, open(POSTED, "w", encoding="utf-8"))

def candidates(kind, items, gen, done):
    def fresh(it, hours): return (_t(it.get("date")) or gen) >= gen - timedelta(hours=hours)
    if kind in ("tech", "sec"):
        types = ("sec",) if kind == "sec" else ("gen", "ai", "os", "dev", "fix")
        c = [i for i in items if i["type"] in types and i.get("sum_src") == "llm" and i.get("summary") and i["id"] not in done and fresh(i, 36)]
        return sorted(c, key=lambda i: -(_t(i["date"]) or gen).timestamp())
    vul = [i for i in items if i["type"] == "vul" and i.get("risk") is not None and i["id"] not in done]
    kev = sorted([i for i in vul if i.get("kev") and fresh(i, 72)], key=lambda i: -(_t(i["date"]) or gen).timestamp())
    top = sorted([i for i in vul if fresh(i, 30)], key=lambda i: (-(i.get("risk") or 0), -(i.get("score") or 0)))
    return kev + top

def load_data():
    d = json.load(open(os.path.join(SITE, "data.json"), encoding="utf-8"))
    return d["items"], _t(d["generated_at"])

def pick(today):
    items, gen = load_data(); done = posted_ids()
    first = (today - ROTATION_START).days % len(KINDS)
    for k in range(len(KINDS)):
        kind = KINDS[(first + k) % len(KINDS)]
        c = candidates(kind, items, gen, done)
        if c: return kind, c[0]
    return None, None

# ---------------------------------------------------------------- text (X counts a link as 23 characters, an emoji as 2)
LIMIT = 280
def weight(text):
    t = re.sub(r"https?://\S+", "x" * 23, text)
    return sum(2 if ord(ch) > 0xFFFF or 0x2600 <= ord(ch) <= 0x27BF else 1 for ch in t)

def fit(head, body, tail):
    """Shorten `body` at a sentence or word boundary until the whole post fits the limit."""
    full = lambda b: head + b + tail
    if weight(full(body)) <= LIMIT: return full(body)
    room = LIMIT - weight(full("")) - 1
    cut = body[:max(0, room)]
    for sep in (".", "،", " "):
        k = cut.rfind(sep)
        if k > room * 0.6: cut = cut[:k]; break
    return full(cut.rstrip(" ،.") + "…")

def cve_of(v): return v["title"].split(":")[0].strip()

def build_text(kind, it):
    if kind == "vul":
        cid = cve_of(it); prod = it.get("system") or "منتج غير محدد"
        head = (f"🔴 ثغرة اليوم: {cid} في {prod}\n"
                f"الخطورة: CVSS {it.get('score')} ({LEVEL.get(it.get('severity'), 'غير مقيّمة')})، ودرجة الخطر {it['risk']} من 100"
                + ("، وثبت استغلالها حسب CISA" if it.get("kev") else "") + "\n\n")
        body = it["summary"] if it.get("sum_src") == "llm" and it.get("summary") else ""
        tail = f"\n\nالتفاصيل والمصدر: {SITE_URL}#v={cid}"
        if not body: head, tail = head.rstrip("\n"), tail[1:]
        return fit(head, body, tail)
    # news is reported as the source published it, so the source is named up front
    src = SRC.get(it.get("source"), it.get("source") or "")
    head = f"🛡️ خبر أمني، بحسب {src}\n\n" if kind == "sec" else f"📰 خبر تقني، بحسب {src}\n\n"
    tail = f"\n\nالمصدر: {it['link']}\nرادار التقنية: {SITE_URL}"
    return fit(head, it["summary"], tail)

# ---------------------------------------------------------------- card image (HTML rendered by Edge, so Arabic shapes correctly)
CARD = """<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><style>
body{margin:0;width:1200px;height:675px;background:radial-gradient(circle at 85% 20%,#14213D 0%,#0A1428 65%);font-family:Dubai,'Segoe UI',sans-serif;color:#E6EAF2}
.w{box-sizing:border-box;height:100%;padding:48px 60px;display:flex;flex-direction:column}
.h{display:flex;justify-content:space-between;align-items:center;border-bottom:3px solid #C9A063;padding-bottom:16px}
.h b{font-size:38px;color:#fff}.h span{font-size:24px;color:#C9A063}
.k{margin-top:34px;align-self:flex-start;font-size:26px;font-weight:700;color:#0A1428;background:var(--c);border-radius:10px;padding:4px 18px}
.t{margin-top:22px;font-size:{size}px;font-weight:700;line-height:1.45;color:#fff}
.m{margin-top:18px;font-size:24px;color:#C9D2E3;line-height:1.5}
.sp{flex:1}.l{direction:ltr;unicode-bidi:isolate}
.f{display:flex;justify-content:space-between;font-size:21px;color:#9DA8BD}.f .l{color:#C9A063}
</style><div class="w" style="--c:{color}"><div class="h"><b>رادار التقنية</b><span>{day}</span></div>
<div class="k">{kind}</div><div class="t">{title}</div><div class="m">{meta}</div><div class="sp"></div>
<div class="f"><span>{foot}</span><span class="l">nfalqhtan-hue.github.io/radar</span></div></div></html>"""

def L(s): return f'<span class="l">{html.escape(str(s))}</span>'

def build_card(kind, it, day, path):
    if kind == "vul":
        title = f"{L(cve_of(it))} في {L(it.get('system') or '')}"
        meta = (f"{L('CVSS ' + str(it.get('score')))} ({LEVEL.get(it.get('severity'), '')})، ودرجة الخطر {L(it['risk'])} من 100 ({RISK.get(it.get('risk_level'), '')})"
                + ("<br>ثبت استغلالها فعلياً حسب قائمة CISA" if it.get("kev") else "<br>لا دليل منشور على استغلالها حتى الآن"))
        k, color, size, foot = "ثغرة اليوم", "#FF6B66", 46, "الدرجة من NVD، والاستغلال من CISA"
    else:
        s = it["summary"]; s = s if len(s) <= 230 else s[:230].rsplit(" ", 1)[0] + "…"
        title = html.escape(s)
        meta = "ملخص آلي بالعربية، والخبر الأصلي من " + L(SRC.get(it.get("source"), it.get("source") or ""))
        k, color = ("خبر أمني", "#FF9F4D") if kind == "sec" else ("خبر تقني", "#D7AE6E")
        size, foot = (40 if len(s) < 140 else 34), "الثغرات والتحديثات وأخبار التقنية بالعربي"
    page = (CARD.replace("{day}", html.escape(day)).replace("{kind}", k).replace("{color}", color).replace("{size}", str(size))
            .replace("{title}", title).replace("{meta}", meta).replace("{foot}", foot))
    hp = os.path.join(OUT, "card.html"); open(hp, "w", encoding="utf-8").write(page)
    prof = os.path.join(OUT, "edge_profile"); shutil.rmtree(prof, ignore_errors=True)
    subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--user-data-dir={prof}", "--window-size=1200,675",
                    f"--screenshot={path}", "file:///" + hp.replace("\\", "/")], check=True, timeout=120, capture_output=True)
    shutil.rmtree(prof, ignore_errors=True)

def log(msg):
    with open(LOG, "a", encoding="utf-8") as f: f.write(f"{datetime.now(RIYADH).isoformat(timespec='seconds')} {msg}\n")

def posted_today(today):
    if not os.path.exists(LOG): return False
    return any(l.startswith(today.isoformat()) and " posted " in l for l in open(LOG, encoding="utf-8"))

def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true"); g.add_argument("--draft", action="store_true"); g.add_argument("--post", action="store_true")
    ap.add_argument("--kind", choices=KINDS, help="draft a specific kind (for testing)")
    a = ap.parse_args()
    if a.check: check(); return
    os.makedirs(OUT, exist_ok=True)
    now = datetime.now(RIYADH); today = now.date()
    if a.post and posted_today(today):
        print("already posted today"); return
    if a.kind and a.draft:
        items, gen = load_data(); c = candidates(a.kind, items, gen, posted_ids())
        kind, it = a.kind, (c[0] if c else None)
    else:
        kind, it = pick(today)
    if not it:
        log("nothing new to post today"); print("nothing new to post today"); return
    text = build_text(kind, it)
    card = os.path.join(OUT, f"card_{kind}.png"); build_card(kind, it, now.strftime("%d/%m/%Y"), card)
    open(os.path.join(OUT, f"post_{kind}.txt"), "w", encoding="utf-8").write(text)
    if a.draft:
        print(f"[{kind}] {it['id']}  ({weight(text)}/{LIMIT})\n{text}\ncard: {card}\n"); return
    try:
        mid = upload_media(card)
        tid = tweet(text, mid)
        remember(it["id"]); log(f"posted {tid} {kind} {it['id']}"); print("posted", tid, kind)
    except Exception as e:
        log(f"FAILED {kind} {it['id']}: {e}"); print("FAILED", e); sys.exit(1)

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
