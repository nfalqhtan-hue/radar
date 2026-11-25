# -*- coding: utf-8 -*-
"""يحوّل تقرير Markdown عربي إلى Word باتجاه من اليمين لليسار.
الاستخدام: python quality/md_to_docx.py TEST_REPORT_WEEK6.md TEST_REPORT_WEEK6.docx
يدعم: العناوين # و ##، الفقرات، **غامق**، `كود`، القوائم - و 1.، الجداول، والخط الفاصل ---.
"""
import re, sys
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, Cm, RGBColor

FONT = "Arial"
CODE_FONT = "Consolas"
BODY = 11
ACCENT = "1F4E79"
LATIN = re.compile(r"[A-Za-z0-9][\w.\-/:%+=≥']*(?:[ ,]+[A-Za-z0-9][\w.\-/:%+=≥']*)*")


def set_bidi(p, rtl=True):
    ppr = p._p.get_or_add_pPr()
    b = OxmlElement("w:bidi")
    if not rtl:
        b.set(qn("w:val"), "0")
    ppr.insert(0, b)


def style_run(r, size, bold=False, rtl=True, font=FONT, color=None):
    r.font.name = font
    r.font.size = Pt(size)
    r.font.bold = bold
    if color:
        r.font.color.rgb = RGBColor.from_string(color)
    rpr = r._r.get_or_add_rPr()
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts"); rpr.insert(0, fonts)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        fonts.set(qn(a), font)
    if bold:
        rpr.append(OxmlElement("w:bCs"))
    szcs = OxmlElement("w:szCs"); szcs.set(qn("w:val"), str(int(size * 2))); rpr.append(szcs)
    if rtl:
        rpr.append(OxmlElement("w:rtl"))


def add_text(p, text, size=BODY, bold=False, color=None):
    """يضيف نصاً فيه **غامق** و `كود`، ويفصل المقاطع اللاتينية عن العربية لترتيب صحيح."""
    for part in re.split(r"(\*\*.+?\*\*|`[^`]+`)", text):
        if not part:
            continue
        if part.startswith("`"):
            style_run(p.add_run(part[1:-1]), size - 1, bold, rtl=False, font=CODE_FONT, color="2E2E2E")
            continue
        b = bold
        if part.startswith("**"):
            part, b = part[2:-2], True
        pos = 0
        for m in LATIN.finditer(part):
            if m.start() > pos:
                style_run(p.add_run(part[pos:m.start()]), size, b, True, color=color)
            g, end = m.group(), m.end()
            if not re.search(r"[A-Za-z]", g):
                # رقم فقط: تبقى الأرقام غربية، وتُترك النقطة/الفاصلة الأخيرة للسياق العربي
                g2 = g.rstrip(".,:")
                end = m.start() + len(g2)
                g = g2
            style_run(p.add_run(g), size, b, False, color=color)
            pos = end
        if pos < len(part):
            style_run(p.add_run(part[pos:]), size, b, True, color=color)


def para(doc, text="", size=BODY, bold=False, align=WD_ALIGN_PARAGRAPH.RIGHT, after=6, color=None):
    p = doc.add_paragraph()
    set_bidi(p)
    p.alignment = align
    p.paragraph_format.space_after = Pt(after)
    p.paragraph_format.line_spacing = 1.15
    if text:
        add_text(p, text, size, bold, color)
    return p


def bottom_border(p, color=ACCENT, sz=8):
    ppr = p._p.get_or_add_pPr()
    bdr = OxmlElement("w:pBdr")
    b = OxmlElement("w:bottom")
    for k, v in (("w:val", "single"), ("w:sz", str(sz)), ("w:space", "4"), ("w:color", color)):
        b.set(qn(k), v)
    bdr.append(b); ppr.append(bdr)


def shade(cell, fill):
    tcpr = cell._tc.get_or_add_tcPr()
    s = OxmlElement("w:shd")
    s.set(qn("w:val"), "clear"); s.set(qn("w:color"), "auto"); s.set(qn("w:fill"), fill)
    tcpr.append(s)


def table(doc, rows, usable_cm):
    head, body = rows[0], rows[1:]
    n = len(head)
    # عرض الأعمدة حسب طول النص (مع حد أدنى)
    lens = [max(len(r[i]) if i < len(r) else 0 for r in rows) for i in range(n)]
    weights = [min(max(l, 9), 120) for l in lens]
    tot = sum(weights)
    widths = [max(usable_cm * w / tot, 1.1) for w in weights]
    extra = sum(widths) - usable_cm
    big = widths.index(max(widths)); widths[big] -= extra
    size = 9 if n >= 5 or max(lens) > 80 else 10
    t = doc.add_table(rows=len(rows), cols=n)
    t.style = "Table Grid"
    tblpr = t._tbl.tblPr
    tblpr.append(OxmlElement("w:bidiVisual"))
    t.autofit = False
    for ri, r in enumerate(rows):
        t.rows[ri]._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
        for ci in range(n):
            c = t.cell(ri, ci)
            c.width = Cm(widths[ci])
            p = c.paragraphs[0]
            set_bidi(p)
            p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            p.paragraph_format.space_after = Pt(0)
            txt = r[ci] if ci < len(r) else ""
            if ri == 0:
                shade(c, ACCENT)
                add_text(p, txt, size, True, "FFFFFF")
            else:
                if ri % 2 == 0:
                    shade(c, "EEF3F8")
                add_text(p, txt, size)
    # تكرار صف العناوين عند انتقال الجدول لصفحة جديدة
    trpr = t.rows[0]._tr.get_or_add_trPr()
    trpr.append(OxmlElement("w:tblHeader"))
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def convert(src, dst):
    lines = open(src, encoding="utf-8").read().splitlines()
    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21), Cm(29.7)
    for side in ("left_margin", "right_margin"):
        setattr(sec, side, Cm(2))
    sec.top_margin = sec.bottom_margin = Cm(2)
    usable = 21 - 4
    sec._sectPr.append(OxmlElement("w:bidi"))
    st = doc.styles["Normal"]
    st.font.name = FONT; st.font.size = Pt(BODY)

    i = 0
    while i < len(lines):
        ln = lines[i].rstrip()
        s = ln.strip()
        if not s:
            i += 1; continue
        if s.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            table(doc, rows, usable)
            continue
        if s == "---":
            p = para(doc, after=6); bottom_border(p, "BFBFBF", 4)
        elif s.startswith("# "):
            p = para(doc, s[2:], 18, True, WD_ALIGN_PARAGRAPH.CENTER, 10, ACCENT)
            bottom_border(p)
        elif s.startswith("## "):
            p = para(doc, s[3:], 14, True, after=6, color=ACCENT)
            p.paragraph_format.space_before = Pt(10)
            p.paragraph_format.keep_with_next = True
        elif re.match(r"^[-*] ", s):
            p = para(doc, after=3)
            p.paragraph_format.right_indent = Cm(0.6)
            add_text(p, "• " + s[2:])
        elif re.match(r"^\d+\. ", s):
            num, rest = s.split(". ", 1)
            p = para(doc, after=3)
            p.paragraph_format.right_indent = Cm(0.6)
            add_text(p, num + ". " + rest)
        else:
            para(doc, s.replace("\\*", "*"))
        i += 1
    doc.save(dst)
    print("saved", dst)


if __name__ == "__main__":
    convert(sys.argv[1], sys.argv[2])
