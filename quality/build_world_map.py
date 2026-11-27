"""Build site/assets/world.json (SVG paths of country borders) from Natural Earth 110m via world-atlas TopoJSON.
Source file (downloaded once, public domain): geo_src/countries-110m.json from world-atlas@2.0.2.
Projection: equirectangular, latitudes -58..84 (Antarctica dropped). Run: python -I quality/build_world_map.py"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "geo_src", "countries-110m.json")
OUT = os.path.join(ROOT, "site", "assets", "world.json")
W, LAT_TOP, LAT_BOT = 1000.0, 84.0, -58.0
H = W * (LAT_TOP - LAT_BOT) / 360.0

topo = json.load(open(SRC, encoding="utf-8"))
sx, sy = topo["transform"]["scale"]; tx, ty = topo["transform"]["translate"]
arcs = []
for arc in topo["arcs"]:                     # delta-decode quantized arcs into lon/lat
    x = y = 0; pts = []
    for dx, dy in arc:
        x += dx; y += dy; pts.append((x * sx + tx, y * sy + ty))
    arcs.append(pts)

def ring(idx):
    pts = []
    for i in idx:
        a = arcs[i] if i >= 0 else arcs[~i][::-1]
        pts.extend(a if not pts else a[1:])
    return pts

def proj(lon, lat):
    return ((lon + 180.0) / 360.0 * W, (LAT_TOP - max(LAT_BOT, min(LAT_TOP, lat))) / (LAT_TOP - LAT_BOT) * H)

def area_centroid(pts):
    a = cx = cy = 0.0
    for (x1, y1), (x2, y2) in zip(pts, pts[1:] + pts[:1]):
        f = x1 * y2 - x2 * y1; a += f; cx += (x1 + x2) * f; cy += (y1 + y2) * f
    if abs(a) < 1e-9: return 0.0, pts[0]
    return abs(a) / 2, (cx / (3 * a), cy / (3 * a))

out = []
for g in topo["objects"]["countries"]["geometries"]:
    name = g.get("properties", {}).get("name", "")
    if name == "Antarctica" or "arcs" not in g: continue
    polys = g["arcs"] if g["type"] == "MultiPolygon" else [g["arcs"]]
    d, best = [], (0, None)
    for poly in polys:
        for k, r in enumerate(poly):
            pts = [proj(lon, lat) for lon, lat in ring(r)]
            # drop ring segments that wrap across the antimeridian (Russia, Fiji): split at big jumps
            seg = [pts[0]]
            parts = []
            for p in pts[1:]:
                if abs(p[0] - seg[-1][0]) > W / 2: parts.append(seg); seg = [p]
                else: seg.append(p)
            parts.append(seg)
            for s in parts:
                if len(s) < 3: continue
                d.append("M" + "L".join(f"{x:.1f} {y:.1f}" for x, y in s) + "Z")
            if k == 0:
                ar, c = area_centroid(pts)
                if ar > best[0]: best = (ar, c)
    if not d: continue
    cx, cy = best[1]
    out.append(dict(id=g.get("id", ""), name=name, d="".join(d), c=[round(cx, 1), round(cy, 1)]))

json.dump(dict(w=W, h=round(H, 1), lat=[LAT_TOP, LAT_BOT], source="Natural Earth 1:110m via world-atlas 2.0.2 (public domain)",
               countries=out), open(OUT, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
print(len(out), "countries,", os.path.getsize(OUT), "bytes ->", OUT)
