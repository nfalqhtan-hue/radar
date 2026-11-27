"""Screenshots of the live site for the v2 report and slides (headless Edge, light theme).
Output: report_assets/v2/*.png. Each shot uses a fresh browser profile so language/theme choices do not leak between shots.
Run: python -I quality/shoot_v2.py"""
import os, subprocess, shutil, sys, time
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THEME = os.environ.get("SHOT_THEME", "light")          # light for the printed report, dark for the slides
OUT = os.path.join(ROOT, "report_assets", "v2", THEME); os.makedirs(OUT, exist_ok=True)
WORK = os.path.join(ROOT, "_work", "edge"); os.makedirs(WORK, exist_ok=True)
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
BASE = "https://nfalqhtan-hue.github.io/radar/"

# name, path, width, height, crop box (left, top, right, bottom) or None, mobile
SHOTS = [
    ("home", "?lang=ar", 1280, 880, None, False),
    ("home_feed", "?lang=ar#type=vul&sort=risk", 1280, 1500, (0, 690, 1280, 1500), False),
    ("detail", "?lang=ar#v=CVE-2026-103406", 1280, 1300, None, False),
    ("alerts", "alerts.html?lang=ar#tab=risk&sort=risk", 1280, 960, None, False),
    ("updates", "updates.html?lang=ar", 1280, 1050, None, False),
    ("dashboard", "dashboard.html?lang=ar", 1280, 1450, None, False),
    ("trends_top", "trends.html?lang=ar#r=30", 1280, 980, None, False),
    ("trends_charts", "trends.html?lang=ar#r=30", 1280, 2100, (0, 880, 1280, 1820), False),
    ("report", "report.html?lang=ar", 1280, 1500, None, False),
    ("report_lower", "report.html?lang=ar", 1280, 3000, (0, 1380, 1280, 2500), False),
    ("map", "map.html?lang=ar#c=CN", 1280, 1180, None, False),
    ("about_risk", "about.html?lang=ar#risk", 1280, 1100, None, False),
    ("m_updates", "updates.html?lang=ar", 390, 844, None, True),
    ("m_map", "map.html?lang=ar", 390, 844, None, True),
    ("m_report", "report.html?lang=ar", 390, 844, None, True),
    ("trends_en", "trends.html?lang=en#r=30", 1280, 980, None, False),
]

def shoot(name, path, w, h, crop, mobile):
    prof = os.path.join(WORK, "p_" + name); shutil.rmtree(prof, ignore_errors=True)
    raw = os.path.join(WORK, name + "_raw.png")
    args = [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--user-data-dir={prof}", f"--window-size={w},{h}",
            "--virtual-time-budget=15000", "--force-color-profile=srgb", "--blink-settings=preferredColorScheme=" + ("1" if THEME == "light" else "0"), "--force-device-scale-factor=" + ("2" if mobile else "1"),
            f"--screenshot={raw}"]
    if mobile: args.append("--user-agent=Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Mobile Safari/537.36")
    args.append(BASE + path)
    subprocess.run(args, check=True, timeout=120, capture_output=True)
    im = Image.open(raw)
    if crop: im = im.crop(crop)
    im.save(os.path.join(OUT, name + ".png"), optimize=True)
    shutil.rmtree(prof, ignore_errors=True)
    print(name, im.size)

for s in SHOTS:
    if len(sys.argv) > 1 and s[0] not in sys.argv[1:]: continue
    shoot(*s)
