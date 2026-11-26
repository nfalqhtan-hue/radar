# -*- coding: utf-8 -*-
"""يبني التقرير النهائي لمشروع رادار التقنية بصيغة Word (عربي، من اليمين لليسار).
الاستخدام: python quality/build_final_report.py   ← يكتب FINAL_REPORT.docx في مجلد المشروع
الصور في report_assets/. الفهرس وأرقام الصفحات حقول يحدّثها Word عند الفتح (أو سكربت التصدير لـ PDF).
"""
import os, re
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, Cm, RGBColor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "report_assets")
FONT = "Dubai"
NAVY, BRASS, ACCENT, MUTED, INK, PAPER = "14213D", "C9A063", "7E5A22", "586379", "1B2233", "F3F5F9"
BODY = 11.5
USABLE = 21 - 2 * 2.2
LATIN = re.compile(r"[A-Za-z0-9][\w.\-/:%+=≥'’]*(?:(?:[ ,]|\s[+&]\s)+[A-Za-z0-9][\w.\-/:%+=≥'’]*)*")

# ------------------------------------------------------------------ أدوات RTL
def bidi(p, on=True):
    ppr = p._p.get_or_add_pPr()
    b = OxmlElement("w:bidi")
    if not on: b.set(qn("w:val"), "0")
    ppr.insert(0, b)

def style_run(r, size=BODY, bold=False, rtl=True, color=INK, italic=False, font=FONT):
    r.font.name = font; r.font.size = Pt(size); r.font.bold = bold; r.font.italic = italic
    if color: r.font.color.rgb = RGBColor.from_string(color)
    rpr = r._r.get_or_add_rPr()
    f = rpr.find(qn("w:rFonts"))
    if f is None: f = OxmlElement("w:rFonts"); rpr.insert(0, f)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"): f.set(qn(a), font)
    if bold: rpr.append(OxmlElement("w:bCs"))
    if italic: rpr.append(OxmlElement("w:iCs"))
    s = OxmlElement("w:szCs"); s.set(qn("w:val"), str(int(size * 2))); rpr.append(s)
    if rtl: rpr.append(OxmlElement("w:rtl"))

def runs(p, text, size=BODY, bold=False, color=INK, italic=False):
    """نص فيه **غامق**؛ المقاطع اللاتينية والأرقام تُكتب كمقاطع LTR مستقلة فيبقى ترتيبها صحيحاً."""
    for part in re.split(r"(\*\*.+?\*\*)", text):
        if not part: continue
        b = bold
        if part.startswith("**"): part, b = part[2:-2], True
        pos = 0
        for m in LATIN.finditer(part):
            if m.start() > pos: style_run(p.add_run(part[pos:m.start()]), size, b, True, color, italic)
            g, end = m.group(), m.end()
            if not re.search(r"[A-Za-z]", g):
                g2 = g.rstrip(".,:)("); end = m.start() + len(g2); g = g2
            style_run(p.add_run(g), size, b, False, color, italic)
            pos = end
        if pos < len(part): style_run(p.add_run(part[pos:]), size, b, True, color, italic)

def para(container, text="", size=BODY, bold=False, color=INK, align=WD_ALIGN_PARAGRAPH.JUSTIFY, after=6, before=0,
         italic=False, style=None, line=1.3):
    p = container.add_paragraph(style=style) if style else container.add_paragraph()
    bidi(p); p.alignment = align
    pf = p.paragraph_format; pf.space_after = Pt(after); pf.space_before = Pt(before); pf.line_spacing = line
    if text: runs(p, text, size, bold, color, italic)
    return p

def shade(cell, fill):
    tcpr = cell._tc.get_or_add_tcPr()
    s = OxmlElement("w:shd"); s.set(qn("w:val"), "clear"); s.set(qn("w:color"), "auto"); s.set(qn("w:fill"), fill)
    tcpr.append(s)

def cell_margins(cell, top=80, bottom=80, side=120):
    tcpr = cell._tc.get_or_add_tcPr(); m = OxmlElement("w:tcMar")
    for k, v in (("top", top), ("bottom", bottom), ("start", side), ("end", side), ("left", side), ("right", side)):
        e = OxmlElement(f"w:{k}"); e.set(qn("w:w"), str(v)); e.set(qn("w:type"), "dxa"); m.append(e)
    tcpr.append(m)

def borders(table, color="D8DEE8", sz=4, inside=True):
    tblpr = table._tbl.tblPr; b = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right") + (("insideH", "insideV") if inside else ()):
        e = OxmlElement(f"w:{edge}"); e.set(qn("w:val"), "single"); e.set(qn("w:sz"), str(sz)); e.set(qn("w:color"), color); b.append(e)
    tblpr.append(b)

def no_borders(table):
    tblpr = table._tbl.tblPr; b = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        e = OxmlElement(f"w:{edge}"); e.set(qn("w:val"), "nil"); b.append(e)
    tblpr.append(b)

def new_table(doc, nrows, widths):
    t = doc.add_table(rows=nrows, cols=len(widths))
    t._tbl.tblPr.append(OxmlElement("w:bidiVisual"))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER; t.autofit = False
    for row in t.rows:
        for i, c in enumerate(row.cells): c.width = Cm(widths[i])
    return t

def table(doc, rows, widths=None, size=10, first_bold=False):
    n = len(rows[0])
    if not widths:
        lens = [max(len(r[i]) for r in rows) for i in range(n)]
        w = [min(max(l, 8), 90) for l in lens]; widths = [USABLE * x / sum(w) for x in w]
    t = new_table(doc, len(rows), widths); borders(t)
    for ri, r in enumerate(rows):
        t.rows[ri]._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
        for ci, txt in enumerate(r):
            c = t.cell(ri, ci); cell_margins(c); c.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            p = c.paragraphs[0]
            code = ri > 0 and bool(re.match(r"(?:python |https?://)", txt))   # أمر أو رابط: فقرة من اليسار لليمين
            bidi(p, not code); p.alignment = WD_ALIGN_PARAGRAPH.LEFT if code else WD_ALIGN_PARAGRAPH.RIGHT
            p.paragraph_format.space_after = Pt(0); p.paragraph_format.line_spacing = 1.15
            if ri < len(rows) - 1: p.paragraph_format.keep_with_next = True   # الجدول يبقى متصلاً ما أمكن
            if code:
                if ri % 2 == 0: shade(c, PAPER)
                style_run(p.add_run(txt), size - .5, False, False, INK, font="Consolas"); continue
            if ri == 0:
                shade(c, NAVY); runs(p, txt, size, True, "FFFFFF")
            else:
                if ri % 2 == 0: shade(c, PAPER)
                runs(p, txt, size, first_bold and ci == 0, INK)
    t.rows[0]._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))
    gap(doc, 4)
    return t

def gap(doc, pt=6):
    p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(0); p.paragraph_format.space_before = Pt(0)
    r = p.add_run(""); r.font.size = Pt(max(1, pt / 2)); p.paragraph_format.line_spacing = Pt(pt)
    return p

def heading(doc, text, level):
    p = doc.add_paragraph(style=f"Heading {level}")
    bidi(p); p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    # العنوان مقطع واحد من اليمين لليسار: تقسيمه يجعل رقم الفصل يلتصق بالنص في الفهرس
    # بلا أرقام: الرقم في مقطع عربي يتحول لأرقام هندية، وفي مقطع منفصل يلتصق بالنص في الفهرس
    text = re.sub(r"^\d+(?:\.\d+)?\.?\s+", "", text)
    style_run(p.add_run(text), {1: 20, 2: 14.5, 3: 12.5}[level], True, True, NAVY if level < 3 else ACCENT)
    if level == 1:   # خط ذهبي تحت عنوان الفصل
        ppr = p._p.get_or_add_pPr(); bdr = OxmlElement("w:pBdr"); b = OxmlElement("w:bottom")
        for k, v in (("w:val", "single"), ("w:sz", "12"), ("w:space", "6"), ("w:color", BRASS)): b.set(qn(k), v)
        bdr.append(b); ppr.append(bdr)
    return p

def bullets(doc, items, numbered=False):
    for i, it in enumerate(items):
        p = para(doc, "", after=3, style="List Number" if numbered else "List Bullet", align=WD_ALIGN_PARAGRAPH.RIGHT)
        runs(p, it)

def figure(doc, name, width_cm, caption, num):
    p = doc.add_paragraph(); bidi(p); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(4); p.paragraph_format.space_after = Pt(2); p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(os.path.join(ASSETS, name), width=Cm(width_cm))
    c = para(doc, "", size=9.5, color=MUTED, align=WD_ALIGN_PARAGRAPH.CENTER, after=10)
    runs(c, f"شكل {num}: ", 9.5, True, ACCENT); runs(c, caption, 9.5, False, MUTED)

def box(doc, title, lines, fill="FBF7EF", edge=BRASS):
    """صندوق ملاحظة: خلية واحدة بحد جانبي ذهبي."""
    t = new_table(doc, 1, [USABLE]); no_borders(t)
    c = t.cell(0, 0); shade(c, fill); cell_margins(c, 140, 140, 220)
    tcpr = c._tc.get_or_add_tcPr(); b = OxmlElement("w:tcBorders"); e = OxmlElement("w:right")
    for k, v in (("w:val", "single"), ("w:sz", "36"), ("w:color", edge)): e.set(qn(k), v)
    b.append(e); tcpr.append(b)
    p = c.paragraphs[0]; bidi(p); p.alignment = WD_ALIGN_PARAGRAPH.RIGHT; p.paragraph_format.space_after = Pt(3)
    runs(p, title, 11.5, True, NAVY)
    for ln in lines:
        q = para(c, ln, size=10.5, after=2, align=WD_ALIGN_PARAGRAPH.RIGHT, line=1.25)
    gap(doc, 6)

def kpis(doc, items):
    """صف أرقام رئيسية: رقم كبير ووصفه."""
    w = USABLE / len(items); t = new_table(doc, 1, [w] * len(items)); no_borders(t)
    for i, (num, label) in enumerate(items):
        c = t.cell(0, i); shade(c, PAPER); cell_margins(c, 120, 120, 120)
        p = c.paragraphs[0]; bidi(p); p.alignment = WD_ALIGN_PARAGRAPH.CENTER; p.paragraph_format.space_after = Pt(0)
        runs(p, num, 20, True, NAVY)
        q = para(c, label, size=9.5, color=MUTED, align=WD_ALIGN_PARAGRAPH.CENTER, after=0, line=1.1)
    # فواصل بيضاء بين الخلايا
    tblpr = t._tbl.tblPr; sp = OxmlElement("w:tblCellSpacing"); sp.set(qn("w:w"), "60"); sp.set(qn("w:type"), "dxa"); tblpr.append(sp)
    gap(doc, 8)

def page_break(doc):
    p = doc.add_paragraph(); p.add_run().add_break(WD_BREAK.PAGE)

def field(p, instr, size=9, color=MUTED):
    r = p.add_run(); style_run(r, size, False, False, color)
    b = OxmlElement("w:fldChar"); b.set(qn("w:fldCharType"), "begin"); r._r.append(b)
    r2 = p.add_run(); style_run(r2, size, False, False, color)
    it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = instr; r2._r.append(it)
    r3 = p.add_run(); style_run(r3, size, False, False, color)
    s = OxmlElement("w:fldChar"); s.set(qn("w:fldCharType"), "separate"); r3._r.append(s)
    r4 = p.add_run("1"); style_run(r4, size, False, False, color)
    r5 = p.add_run(); e = OxmlElement("w:fldChar"); e.set(qn("w:fldCharType"), "end"); r5._r.append(e)

# ------------------------------------------------------------------ المستند
doc = Document()
st = doc.styles["Normal"]; st.font.name = FONT; st.font.size = Pt(BODY)
st.element.rPr.rFonts.set(qn("w:cs"), FONT)
for lvl, size, before, after in ((1, 20, 6, 10), (2, 14.5, 14, 6), (3, 12.5, 10, 4)):
    h = doc.styles[f"Heading {lvl}"]; h.font.name = FONT; h.font.size = Pt(size); h.font.bold = True
    h.font.color.rgb = RGBColor.from_string(NAVY)
    h.element.rPr.rFonts.set(qn("w:cs"), FONT); h.element.rPr.rFonts.set(qn("w:ascii"), FONT); h.element.rPr.rFonts.set(qn("w:hAnsi"), FONT)
    pf = h.paragraph_format; pf.space_before = Pt(before); pf.space_after = Pt(after); pf.keep_with_next = True
for name in ("List Bullet", "List Number"):
    doc.styles[name].font.name = FONT

sec = doc.sections[0]
sec.page_width, sec.page_height = Cm(21), Cm(29.7)
sec.left_margin = sec.right_margin = Cm(2.2); sec.top_margin = Cm(2.2); sec.bottom_margin = Cm(2)
sec._sectPr.append(OxmlElement("w:bidi"))
sec.different_first_page_header_footer = True

# ---------- الغلاف
t = new_table(doc, 1, [USABLE]); no_borders(t)
c = t.cell(0, 0); shade(c, NAVY); cell_margins(c, 500, 500, 500)
p = c.paragraphs[0]; bidi(p); p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
p.add_run().add_picture(os.path.join(ASSETS, "logo.png"), width=Cm(2.6))
para(c, "رادار التقنية", size=36, bold=True, color="FFFFFF", align=WD_ALIGN_PARAGRAPH.RIGHT, after=0, before=10, line=1.1)
para(c, "وكيل ذكاء اصطناعي يرصد الثغرات الأمنية وأخبار التقنية، ويصنفها ويلخصها بالعربية، وينبه بالخطير منها", size=14,
     color=BRASS, align=WD_ALIGN_PARAGRAPH.RIGHT, after=26, line=1.3)
para(c, "التقرير النهائي للمشروع", size=18, bold=True, color="FFFFFF", align=WD_ALIGN_PARAGRAPH.RIGHT, after=2)
para(c, "الأسبوع السابع: استكمال المشروع وعرضه", size=12, color="C9D2E3", align=WD_ALIGN_PARAGRAPH.RIGHT, after=0)
gap(doc, 30)
para(doc, "إعداد المتدربين", size=12, bold=True, color=ACCENT, align=WD_ALIGN_PARAGRAPH.RIGHT, after=4)
tt = new_table(doc, 3, [USABLE * .62, USABLE * .38]); borders(tt, "D8DEE8", 4)
for ri, (a, b) in enumerate((("الاسم", "الرقم التدريبي"), ("عبدالله طلال القحطاني", "445223022"), ("عبدالله يعقوب الخليفة", "445213146"))):
    for ci, txt in enumerate((a, b)):
        cc = tt.cell(ri, ci); cell_margins(cc, 100, 100, 160)
        q = cc.paragraphs[0]; bidi(q); q.alignment = WD_ALIGN_PARAGRAPH.RIGHT; q.paragraph_format.space_after = Pt(0)
        if ri == 0: shade(cc, PAPER); runs(q, txt, 10.5, True, MUTED)
        else: runs(q, txt, 13, ri > 0 and ci == 0, INK)
gap(doc, 18)
for k, v in (("رابط الموقع", "https://nfalqhtan-hue.github.io/radar/"), ("الكود المصدري", "https://github.com/nfalqhtan-hue/radar"),
             ("تاريخ التقرير", "26 نوفمبر 2026"), ("التكلفة الكلية", "0 ريال، دون أي اشتراك")):
    q = para(doc, "", after=3, align=WD_ALIGN_PARAGRAPH.RIGHT)
    runs(q, k + ": ", 11, True, MUTED); runs(q, v, 11, False, INK)

# ---------- قسم المحتوى: رأس وتذييل
doc.add_section(WD_SECTION.NEW_PAGE)
s2 = doc.sections[1]; s2.different_first_page_header_footer = False
s2.header.is_linked_to_previous = False; s2.footer.is_linked_to_previous = False
hp = s2.header.paragraphs[0]; bidi(hp); hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
runs(hp, "رادار التقنية", 9, True, NAVY); runs(hp, "  |  التقرير النهائي للمشروع", 9, False, MUTED)
ppr = hp._p.get_or_add_pPr(); bdr = OxmlElement("w:pBdr"); bb = OxmlElement("w:bottom")
for k, v in (("w:val", "single"), ("w:sz", "6"), ("w:space", "4"), ("w:color", BRASS)): bb.set(qn(k), v)
bdr.append(bb); ppr.append(bdr)
fp = s2.footer.paragraphs[0]; bidi(fp); fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
runs(fp, "صفحة ", 9, False, MUTED); field(fp, "PAGE"); runs(fp, " من ", 9, False, MUTED); field(fp, "NUMPAGES")

# ---------- الفهرس
para(doc, "المحتويات", size=20, bold=True, color=NAVY, align=WD_ALIGN_PARAGRAPH.RIGHT, after=10)
tp = doc.add_paragraph(); bidi(tp); field(tp, 'TOC \\o "1-1" \\h \\z \\u', 12, INK)
page_break(doc)

F = iter(range(1, 50))

# ================================================================== 1
heading(doc, "1. الملخص التنفيذي", 1)
para(doc, "«رادار التقنية» وكيل ذكاء اصطناعي يعمل كل ساعة دون تدخل: يجلب الثغرات الأمنية الجديدة من قاعدة NVD الأمريكية، وقائمة وكالة CISA للثغرات التي ثبت استغلالها، وخمس خلاصات أخبار تقنية. ثم يصنف كل عنصر، ويحدد المنتج المتأثر، ويأخذ درجة الخطورة الرسمية، ويكتب ملخصاً عربياً بنموذج لغوي يعمل على جهازنا، ويفحص الملخص قبل نشره. وفي النهاية ينشر كل شيء في موقع عربي وإنجليزي على GitHub Pages، ويرسل تنبيهاً على تيليجرام بالثغرات الحرجة والمستغلة.")
para(doc, "بُني المشروع كله بأدوات مجانية ومفتوحة المصدر، والتكلفة صفر. واختُبرت جودته على أربع جولات، في كل جولة 20 عنصراً حياً روجعت يدوياً مقابل مصادرها.")
kpis(doc, [("95%", "دقة التصنيف"), ("100%", "دقة الخطورة"), ("3/3", "تنبيه الثغرات الحرجة المعروفة"), ("77", "اختباراً آلياً ناجحاً"), ("0 ريال", "التكلفة")])
para(doc, "**أهم النتائج:**", after=3)
bullets(doc, [
    "التصنيف ودرجة الخطورة ومطابقة NVD تجاوزت هدف الخطة (90%) في الجولات كلها بعد الإصلاحات.",
    "الملخصات العربية أضعف جزء: بين 65% و79% من المنشور سليم حسب العينة. لذلك يمر كل ملخص بفحوص آلية، ويُعلَّم «ملخص آلي»، ويُعرض بجانبه الوصف الأصلي ورابط المصدر.",
    "الموقع يرصد حتى الآن 784 ثغرة (19 منها ثبت استغلالها) و165 خبراً تقنياً، في أربع صفحات: الرئيسية، ومركز التنبيهات، والإحصائيات، وعن المشروع.",
    "أثناء التطوير اكتشفنا وأصلحنا أخطاء بيانات جوهرية، أهمها أن الوكيل كان يفقد الثغرات المنشورة وقت إطفاء الجهاز، فاستعدنا 372 ثغرة فائتة.",
])

# ================================================================== 2
page_break(doc)
heading(doc, "2. المقدمة", 1)
heading(doc, "2.1 المشكلة", 2)
para(doc, "الأخبار والتحديثات والثغرات موزعة على عشرات المصادر الرسمية بلغات مختلفة، ومتابعتها يدوياً تستهلك وقتاً كبيراً، وقد يفوت المستخدم تحديثاً أمنياً مهماً. أغلب هذه المصادر بالإنجليزية، وتنشر قاعدة NVD وحدها مئات الثغرات يومياً دون أن تقول أيها يُصلَح أولاً.")
heading(doc, "2.2 الفكرة", 2)
para(doc, "وكيل ذكاء اصطناعي يعمل على مدار الساعة: يجمع آخر الثغرات وأخبار التقنية، ويصنفها ويلخصها بالعربية، وينشرها في موقع واحد مع تنبيه بارز للثغرات الخطيرة. والفرق عن قارئ الأخبار العادي أنه يرتب الثغرات حسب خطرها الحقيقي، ويفصل بين أمرين: خطورة الثغرة (درجة CVSS)، وثبوت استغلالها فعلاً (قائمة CISA).")
heading(doc, "2.3 الأهداف", 2)
bullets(doc, [
    "مكان عربي واحد للأخبار الأمنية المهمة، يتحدث كل ساعة دون عمل يدوي.",
    "تقييم الخطورة من المصدر الرسمي لا من تخمين النموذج، مع دقة تصنيف وخطورة لا تقل عن 90%.",
    "تنبيه فوري بالثغرات الحرجة أو المستغلة، دون إغراق المتابع بالرسائل.",
    "الدقة قبل السرعة: لا يُنشر ملخص فيه معلومة غير موجودة في المصدر.",
    "تكلفة صفر: أدوات مجانية ومفتوحة المصدر فقط.",
])
heading(doc, "2.4 الفئة المستفيدة", 2)
bullets(doc, [
    "طلاب ومتخصصو الدعم الفني وتقنية المعلومات.",
    "مستخدمو الحاسب والجوال الراغبون بمعرفة التحديثات والمشاكل المحلولة.",
    "المهتمون بالأمن السيبراني، والشركات الصغيرة التي تحتاج تنبيهات بسيطة بالثغرات الخطيرة.",
])

# ================================================================== 3
heading(doc, "3. الأدوات والتقنيات", 1)
para(doc, "اخترنا كل أداة لأنها مجانية وتعمل على جهاز شخصي عادي (ذاكرة 16 جيجابايت، دون كرت شاشة). والجدول التالي يوضح ما استخدمناه فعلاً، ويشير إلى ما تغيّر عن الخطة الأصلية وسببه.")
table(doc, [
    ["الأداة", "الاستخدام", "سبب الاختيار"],
    ["Python 3 (المكتبة القياسية فقط)", "الوكيل كاملاً: الجلب والتنظيف والتصنيف والتحقق والتصدير", "لا يحتاج تثبيت أي حزمة، فيعمل على أي جهاز"],
    ["Ollama + Qwen3 8B", "التلخيص بالعربية", "نموذج مفتوح المصدر يعمل محلياً: مجاني، بلا مفتاح API، والبيانات لا تغادر الجهاز. اختير بعد مقارنة مع qwen2.5:7b الذي كان يخلط الصينية"],
    ["SQLite", "قاعدة البيانات: العناصر وسجل الأحداث والأخطاء", "ملف واحد بلا خادم، ومدمج في بايثون"],
    ["مُجدول مهام ويندوز", "تشغيل الدورة كل ساعة في الخلفية", "بديل عن n8n (انظر الملاحظة)"],
    ["GitHub Pages + Actions", "استضافة الموقع ونشره تلقائياً عند كل رفع", "استضافة مجانية بعنوان github.io دون شراء نطاق"],
    ["Telegram Bot API", "التنبيه الفوري", "مجاني وفوري ويصل للجوال"],
    ["HTML وCSS وJavaScript", "الموقع، دون أي إطار أو مكتبة", "صفحات خفيفة وسريعة، وتُستضاف كملفات ثابتة"],
], [4.2, 5.8, USABLE - 10])
box(doc, "ما تغيّر عن الخطة ولماذا", [
    "**من n8n إلى مُجدول مهام ويندوز:** عقدة تشغيل الأوامر في n8n 2.0 معطلة افتراضياً، وn8n يحتاج Node.js غير المثبت على الجهاز. مُجدول المهام مدمج في ويندوز ويؤدي الغرض نفسه دون أي تثبيت. وأبقينا ملف n8n جاهزاً في المستودع لمن يريد استخدامه.",
    "**من Google Sheets إلى SQLite:** قاعدة محلية أسرع وأبسط، ولا تحتاج حساباً أو اتصالاً.",
    "**من draw.io إلى مخطط بلغة HTML:** رسمنا مخطط سير العمل كصفحة ويب، فصار نصه العربي سليماً ويسهل تعديله.",
])
heading(doc, "3.1 التكلفة", 2)
table(doc, [["البند", "التكلفة"], ["النموذج اللغوي (Ollama محلي)", "0 ريال"], ["الأتمتة (مُجدول مهام ويندوز)", "0 ريال"],
            ["مصادر البيانات (NVD وCISA وRSS)", "0 ريال"], ["التخزين والاستضافة والنطاق (SQLite وGitHub Pages)", "0 ريال"],
            ["التنبيهات (Telegram)", "0 ريال"], ["**المجموع**", "**0 ريال، ولا يوجد أي اشتراك**"]], [USABLE * .65, USABLE * .35])

# ================================================================== 4
heading(doc, "4. تصميم النظام", 1)
para(doc, "يعمل النظام كخط معالجة من ست خطوات، وتبدأ كل دورة كل ساعة. مخرجات كل خطوة مدخلات التي تليها، وكل خطوة تقرأ من قاعدة البيانات وتكتب فيها، فإذا تعطل مصدر واحد تكمل الدورة ببقية المصادر.")
figure(doc, "flow.png", USABLE * .88, "مخطط سير عمل الوكيل: المصادر، والخطوات الست، والمخرجات", next(F))
heading(doc, "4.1 خطوات الوكيل", 2)
table(doc, [
    ["الخطوة", "ماذا تفعل"],
    ["1. الجلب", "ثغرات NVD المنشورة منذ آخر جلب ناجح (وليس آخر ساعتين فقط)، وقائمة CISA الكاملة، وخمس خلاصات RSS. ويعيد فحص 20 ثغرة مخزنة كل دورة لرصد تغير درجتها"],
    ["2. التنظيف", "إزالة HTML، وتوحيد التواريخ، واستبعاد أرقام CVE المرفوضة والعناصر المكررة"],
    ["3. التصنيف", "نوع الخبر بقواعد كلمات، والمنتج المتأثر مستخرج من نص الوصف، والخطورة من درجة CVSS وحدها، والاستغلال من قائمة CISA كحقل منفصل"],
    ["4. التلخيص", "كل الأخبار والثغرات العالية والحرجة والمستغلة تُلخص بالنموذج (حد 30 في الدورة)، والمتوسطة والمنخفضة تأخذ ملخصاً من بياناتها"],
    ["5. التحقق", "مطابقة رقم CVE والدرجة، ورفض أي ملخص فيه لغة أجنبية، أو رقم أو ادعاء غير موجود في المصدر، أو نص مقطوع"],
    ["6. النشر والتنبيه", "تصدير أربعة ملفات بيانات ورفعها إلى GitHub، فيتحدث الموقع خلال دقيقة، ورسالة تيليجرام لكل ثغرة حرجة أو مستغلة"],
], [3.2, USABLE - 3.2], first_bold=True)
heading(doc, "4.2 البيانات", 2)
para(doc, "تحفظ القاعدة لكل عنصر: النص الأصلي، والملخص ومصدره (نموذج، أو قالب، أو مرفوض)، والخطورة والدرجة ومتجه CVSS، وحالة الاستغلال وتاريخ إدراجه في قائمة CISA، والمنتج المتأثر، وتواريخ النشر والتعديل والرصد. ويسجل جدول الأحداث كل حدث حقيقي: ثغرة جديدة، أو إدراج في قائمة الاستغلال، أو تغير درجة، أو تنبيه أُرسل، أو نجاح جلب كل مصدر وفشله.")
table(doc, [
    ["الملف", "محتواه", "متى يُحمَّل"],
    ["data.json", "آخر 120 خبراً و250 ثغرة، وكل الثغرات المستغلة", "مع كل صفحة"],
    ["details.json", "الوصف الأصلي، وتاريخ آخر تعديل، وبيانات CISA", "عند فتح التفاصيل أو البحث فقط"],
    ["stats.json", "إحصائيات محسوبة من القاعدة كاملة", "صفحتا الإحصائيات وعن المشروع"],
    ["events.json", "آخر 400 حدث، وآخر نجاح لكل مصدر", "مركز التنبيهات"],
], [3.2, 8.5, USABLE - 11.7])

# ================================================================== 5
heading(doc, "5. التنفيذ خلال الأسابيع السبعة", 1)
table(doc, [
    ["الأسبوع", "النشاط", "المخرج"],
    ["1", "تحديد المشكلة والأهداف والفئة المستفيدة", "وصف المشروع"],
    ["2", "اختيار الأدوات ومقارنة البدائل المجانية", "قائمة الأدوات، والتكلفة 0 ريال"],
    ["3", "تصميم خطوات عمل الوكيل", "مخطط سير العمل"],
    ["4", "نموذج أولي: جلب وتصنيف وتلخيص من مصدر واحد", "نموذج أولي يعمل"],
    ["5", "ربط كل المصادر، والجدولة، والنشر في الموقع", "خط معالجة متكامل (21 اختباراً آلياً)"],
    ["6", "ثلاث جولات اختبار، وإصلاح 12 خطأ، ونشر الموقع، وتفعيل تيليجرام", "تقرير الاختبار، و44 اختباراً آلياً، والموقع منشوراً"],
    ["7", "جولة اختبار رابعة، وتطوير الموقع على ثماني مراحل، والاختبار النهائي", "الموقع بصفحاته الأربع، و77 اختباراً، والتقرير والعرض"],
], [2, 9.4, USABLE - 11.4])
heading(doc, "5.1 تطوير الأسبوع السابع", 2)
para(doc, "طوّرنا الموقع والوكيل على ثماني مراحل. نشرنا كل مرحلة واختبرناها قبل بدء التالية، فبقي الموقع يعمل طوال الوقت.")
table(doc, [
    ["المرحلة", "ما أُضيف"],
    ["1. فحص المشروع", "تقرير ببنية الكود ومصادر البيانات وما ينقصها"],
    ["2. التصميم", "ملفات مشتركة، وشريط تنقل، وحالات تحميل وخطأ، ورادار أوضح، وتصميم للجوال"],
    ["3. التفاصيل والتنبيهات", "نافذة تفاصيل لكل ثغرة، ومركز التنبيهات، وسجل الأحداث، وفصل الخطورة عن الاستغلال"],
    ["4. الإحصائيات", "صفحة إحصائيات، وإصلاح ضياع الثغرات وقت إطفاء الجهاز"],
    ["5. البحث واللغتان", "بحث بكل الكلمات مع تطبيع العربية، وفلتر تاريخ، والموقع كاملاً بالإنجليزية"],
    ["6. جودة البيانات", "فحص الادعاءات غير الموجودة في المصدر، وتصحيح استخراج المنتج والتصنيف"],
    ["7. عن المشروع والتقارير", "صفحة «عن المشروع»، وتصدير النتائج إلى تقرير PDF"],
    ["8. الاختبار النهائي", "اختبار البنود العشرة، وإصلاح ما ظهر، وتقرير الاختبار"],
], [4.4, USABLE - 4.4], first_bold=True)

# ================================================================== 6
page_break(doc)
heading(doc, "6. الموقع", 1)
para(doc, "الموقع منشور على https://nfalqhtan-hue.github.io/radar/ ويعمل بالعربية (افتراضياً) والإنجليزية، وبالوضعين الفاتح والداكن، وعلى الجوال. وكل فلتر أو بحث أو ثغرة مفتوحة يُحفظ في الرابط، فيمكن مشاركة أي نتيجة.")
heading(doc, "6.1 الصفحة الرئيسية", 2)
para(doc, "تبدأ بشاشة رادار حية لعناصر آخر 24 ساعة: بُعد النقطة عن المركز عمرها، ولونها وحجمها خطورتها، والحلقة حولها تعني أنها مستغلة. وبجانبها أخطر أربع ثغرات. وتحتها كل ما رصدناه، مع بحث وفلاتر للنوع والخطورة والتاريخ، ومفتاح «الجديد فقط»، وزر تصدير PDF.")
figure(doc, "home.png", USABLE, "الصفحة الرئيسية: الرادار وقائمة «ما يحتاج انتباهك الآن»", next(F))
heading(doc, "6.2 تفاصيل الثغرة", 2)
para(doc, "الضغط على أي ثغرة يفتح نافذة فيها: رقم CVE، ودرجة CVSS على مقياس من 10، والتصنيف، وتاريخ النشر وآخر تحديث، والمنتج المتأثر مع بيان مصدره، وحالة الاستغلال وبيانات CISA إن وُجدت، والوصف الأصلي، والملخص العربي مع بيان أنه آلي، وروابط المصدر وNVD.")
figure(doc, "detail.png", USABLE, "نافذة تفاصيل ثغرة ثبت استغلالها، ودرجتها «عالية» لا «حرجة»", next(F))
heading(doc, "6.3 مركز التنبيهات", 2)
para(doc, "يعرض الثغرات التي تحتاج تصرفاً في أربعة تبويبات: الكل، وثبت استغلالها، وحرجة، وعالية. والخطورة والاستغلال في عمودين منفصلين، لأن الثغرة الحرجة قد لا تكون مستغلة، والمستغلة قد تكون درجتها متوسطة. وفي أسفلها سجل الرسائل التي أُرسلت فعلاً على تيليجرام.")
figure(doc, "alerts.png", USABLE, "مركز التنبيهات", next(F))
heading(doc, "6.4 الإحصائيات", 2)
para(doc, "كل رقم محسوب من القاعدة كاملة: إجمالي الثغرات وتوزيعها حسب الخطورة، وما نُشر في آخر 24 ساعة و7 أيام، ورسم زمني بالساعة أو باليوم، وأكثر المنتجات ظهوراً، وإحصائيات الأخبار، ومصدر الملخصات. والساعات التي سبقت بدء الرصد مخططة حتى لا تُقرأ صفراً.")
figure(doc, "dash.png", USABLE * .86, "صفحة الإحصائيات", next(F))
heading(doc, "6.5 الجوال واللغة الإنجليزية", 2)
para(doc, "على الجوال تنطوي الفلاتر خلف زر واحد، ويصير الرادار فوق القائمة. وبالإنجليزية يتغير اتجاه الصفحة، ويُعرض نص المصدر الأصلي مكان الملخص العربي بدل ترجمة آلية.")
t2 = new_table(doc, 1, [USABLE * .27, USABLE * .27, USABLE * .46]); no_borders(t2)
for i, (img, w) in enumerate((("mobile1.jpg", 4.2), ("mobile2.jpg", 4.2), ("home_en.png", 7.4))):
    q = t2.cell(0, i).paragraphs[0]; q.alignment = WD_ALIGN_PARAGRAPH.CENTER
    q.add_run().add_picture(os.path.join(ASSETS, img), width=Cm(w))
c = para(doc, "", size=9.5, align=WD_ALIGN_PARAGRAPH.CENTER, after=10)
runs(c, f"شكل {next(F)}: ", 9.5, True, ACCENT); runs(c, "الموقع على الجوال بالوضع الداكن، والصفحة الرئيسية بالإنجليزية", 9.5, False, MUTED)
heading(doc, "6.6 تقرير PDF", 2)
para(doc, "زر «تصدير PDF» يحوّل النتائج المعروضة بفلاترها إلى تقرير منسق فيه: اسم المنصة، وتاريخ إنشاء التقرير، ونطاقه، وعدد كل مستوى خطورة، وجدول الثغرات بأرقامها وروابط مصادرها. ويُحفظ من نافذة الطباعة في المتصفح، لأنها تحافظ على الحروف العربية سليمة.")
figure(doc, "report_ar_p1.png", USABLE * .62, "الصفحة الأولى من تقرير PDF للثغرات الحرجة، كما يصدّره الموقع", next(F))

# ================================================================== 7
heading(doc, "7. الاختبار والجودة", 1)
heading(doc, "7.1 طريقة الاختبار", 2)
bullets(doc, [
    "مراجعة يدوية لعينة من 20 عنصراً حياً في كل جولة (12 خبراً و8 ثغرات)، ومقارنة كل عنصر بمصدره الأصلي.",
    "قياس دقة التصنيف ودرجة الخطورة، والهدف ألا تقل عن 90%.",
    "التأكد أن الملخص لا يضيف معلومة غير موجودة في المصدر، وأن رابط المصدر موجود دائماً.",
    "مطابقة رقم CVE وتاريخ النشر ودرجة CVSS مع NVD باستعلام منفصل لكل ثغرة.",
    "اختبار التنبيه بثلاث ثغرات حرجة معروفة: Log4Shell وPAN-OS وCitrix Bleed.",
])
heading(doc, "7.2 نتائج الجولات الأربع", 2)
figure(doc, "rounds.png", USABLE, "تطور الدقة عبر جولات الاختبار الأربع", next(F))
table(doc, [
    ["المقياس", "الجولة 1", "الجولة 2", "الجولة 3", "الجولة 4", "الهدف"],
    ["دقة التصنيف", "95%", "100%", "90%", "95%", "90%"],
    ["دقة الخطورة", "88%", "100%", "100%", "100%", "90%"],
    ["مطابقة CVSS مع NVD", "75%", "100%", "100%", "100%", "—"],
    ["دقة المنتج المتأثر", "38%", "100%", "88%", "75%", "—"],
    ["مطابقة رقم CVE والتاريخ", "100%", "100%", "100%", "100%", "100%"],
    ["الملخصات المنشورة السليمة", "30%", "75%", "79%", "65%", "—"],
    ["تنبيه الثغرات الحرجة المعروفة", "3/3", "3/3", "3/3", "3/3", "فوري"],
], [5.4] + [(USABLE - 5.4) / 5] * 5, first_bold=True)
para(doc, "الجولة 1 قبل الإصلاح بالنموذج القديم، والجولة 2 على نفس العينة بعد الإصلاح، والجولتان 3 و4 على عينات جديدة كلياً، حتى نتأكد أن التحسن ليس مفصلاً على عينة واحدة.", size=10, color=MUTED)
heading(doc, "7.3 الاختبارات الآلية", 2)
para(doc, "يغطي ملف test_pipeline.py كل خطأ وجدناه بمثال حقيقي، ويعمل دون إنترنت مع كل تعديل. وارتفع عدد الفحوص من 21 في الأسبوع الخامس إلى 44 في السادس، ثم إلى 77 بعد تطوير الأسبوع السابع، وكلها ناجحة.")
heading(doc, "7.4 الاختبار النهائي للموقع", 2)
table(doc, [
    ["البند", "النتيجة"],
    ["الوظائف الحالية والجديدة", "✓ كل السيناريوهات نجحت بعد إصلاح خطأ واحد"],
    ["البحث والفلاتر", "✓ متوافقة مع بعضها، والأعداد تحترم بقية الفلاتر"],
    ["تفاصيل الثغرات", "✓ تفتح من كل مكان ومن رابط مشارَك"],
    ["الرسوم والإحصائيات", "✓ مجموع توزيع الخطورة يساوي الإجمالي (784)"],
    ["الجوال والكمبيوتر", "✓ لا تمرير أفقي في أي صفحة، بالوضعين"],
    ["العربية والإنجليزية", "✓ الإنجليزية كاملة في الصفحات الأربع"],
    ["أخطاء JavaScript", "✓ صفر"],
    ["الروابط ومصادر البيانات", "✓ 26 من 27 رابطاً، والسابع والعشرون (بحث CISA) يرفض السكربتات فقط ويعمل في المتصفح"],
    ["عدم كسر الوظائف السابقة", "✓ الرادار، والتحديث كل ساعة، وتنبيهات تيليجرام"],
    ["النشر على GitHub Pages", "✓ نجح كل نشر"],
], [5.4, USABLE - 5.4], first_bold=True)

# ================================================================== 8
page_break(doc)
heading(doc, "8. الأخطاء التي اكتشفناها وكيف أصلحناها", 1)
para(doc, "أهم ما تعلمناه أن الاختبار يكشف أخطاء لا تظهر بقراءة الكود. والجدول يلخص أبرزها من الأسبوعين السادس والسابع.")
table(doc, [
    ["الخطأ", "السبب", "الإصلاح", "النتيجة"],
    ["ملخصات تتحول للصينية والروسية وسط الجملة (14 من 20)", "ضعف النموذج القديم بالعربية", "الانتقال إلى Qwen3 8B، وحارس جودة يرفض أي لغة أجنبية", "من 30% إلى 79% سليم"],
    ["ثغرات تضيع وقت إطفاء الجهاز", "الجلب من آخر ساعتين فقط", "الجلب منذ آخر جلب ناجح", "استُعيدت 372 ثغرة"],
    ["الثغرات المستغلة لا تظهر في الموقع", "تاريخها أقدم من آخر 250 ثغرة", "تُصدَّر الثغرات المستغلة دائماً", "19 ثغرة ظهرت"],
    ["كل ثغرة مستغلة تُعرض «حرجة»", "خلط الخطورة بالاستغلال", "الخطورة من CVSS وحدها، والاستغلال حقل منفصل", "9 فقط من 19 حرجة فعلاً"],
    ["ملخصات تقول «دون مصادقة» و«عن بُعد» بلا دليل", "النموذج يضيف تفاصيل", "فحص يطلب دليلاً صريحاً في المصدر لكل ادعاء", "سُحب 31 ملخصاً"],
    ["«المفوضية الأوروبية» في ثغرة VMware", "النموذج يُقحم مصطلحات المسرد", "مصطلح المسرد يحتاج مقابله في المصدر", "سُحبت 5 ملخصات"],
    ["منتج خاطئ: «SAML» و«A128CBC-HS256» و«Joomla Extension»", "أنماط استخراج ناقصة", "قواعد جديدة، ورفض أسماء الخوارزميات", "صُحح 38 منتجاً"],
    ["106 تنبيهات في دورة واحدة", "رسالة لكل ثغرة حرجة", "5 رسائل للأهم ورسالة جامعة", "6 رسائل بدل 106"],
    ["إغلاق نافذة التفاصيل لا يحذفها من الرابط", "حدث الإغلاق لا يصل دائماً", "تنظيف الرابط في كل طرق الإغلاق", "اختبار آلي في المتصفح"],
], [4.2, 3.6, 4.6, USABLE - 12.4], size=9.5)

# ================================================================== 9
heading(doc, "9. الأمان والخصوصية", 1)
bullets(doc, [
    "لا توجد أي مفاتيح أو كلمات مرور في الكود المنشور. توكن تيليجرام محفوظ في متغيرات بيئة الجهاز فقط، وفحصنا المستودع كاملاً.",
    "النموذج اللغوي يعمل على الجهاز نفسه، فلا تُرسل البيانات لأي خدمة ذكاء اصطناعي خارجية.",
    "الموقع يعرض كل نص قادم من البيانات كنص عادي لا كـ HTML، ويفحص كل رابط ليقبل http وhttps فقط، فلا يمكن لمحتوى خبيث في مصدر خارجي أن ينفذ كوداً في المتصفح.",
    "سياسة أمان المحتوى (CSP) في كل صفحة تمنع تحميل أي سكربت غير سكربتات الموقع نفسه.",
    "تعليمات النموذج تطلب تجاهل أي أوامر داخل نص المصدر، لأن الأخبار نص خارجي غير موثوق.",
    "نحترم حقوق النشر: ننشر ملخصاً قصيراً مع رابط المصدر، ولا ننسخ المقالات.",
])

# ================================================================== 10
heading(doc, "10. القيود والتطوير المستقبلي", 1)
heading(doc, "10.1 قيود معروفة", 2)
bullets(doc, [
    "**الملخصات:** من نموذج صغير (8B) قد يخطئ في المعنى بطرق لا يكشفها فحص آلي، مثل «مئات» بدل «عشرات». لذلك يُعلَّم كل ملخص ويرتبط بمصدره.",
    "**لا يوجد خادم:** الوكيل يعمل على جهازنا، فلا يتحدث الموقع وهو مطفأ، وما فات يُجلب في الدورة التالية.",
    "**المنتج المتأثر:** يُستخرج بقواعد من النص، ولا يُعرف لكل الثغرات (عُرف لـ 641 من 784).",
    "**السرعة:** 15 إلى 30 ثانية للملخص على المعالج، فحد 30 ملخصاً في الدورة يترك طابوراً عند وصول دفعات كبيرة.",
])
heading(doc, "10.2 تطوير مقترح", 2)
bullets(doc, [
    "نموذج أكبر (qwen3:14b) أو جهاز بكرت شاشة لرفع دقة الملخصات وسرعتها.",
    "مراجعة بشرية سريعة للثغرات الحرجة فقط قبل نشر ملخصها.",
    "قناة تيليجرام عامة يشترك فيها أي أحد، وملخص أسبوعي تلقائي.",
    "تشغيل الوكيل على خادم مجاني دائم بدل الجهاز الشخصي.",
    "مراجعة شهرية للموقع يقترح فيها الفريق تحسينات، وتُسجل في ملف IMPROVEMENTS.md.",
])

# ================================================================== 11
heading(doc, "11. الاستفادة التجارية", 1)
bullets(doc, [
    "بيع تقارير أمنية مخصصة لمرة واحدة للشركات الصغيرة وأقسام تقنية المعلومات (الموقع يصدّرها الآن بصيغة PDF).",
    "تقارير شهرية بالثغرات المهمة للمؤسسات مقابل رسوم.",
    "واجهة API لبيانات الثغرات المصنفة والملخصة بالعربية.",
    "إعلانات ورعايات من شركات تقنية في الموقع والنشرة البريدية.",
])

# ================================================================== 12
heading(doc, "12. الخاتمة", 1)
para(doc, "بنينا وكيلاً يعمل وحده كل ساعة، من الجلب إلى النشر والتنبيه، بتكلفة صفر وأدوات مفتوحة المصدر. وحقق أهداف الخطة في التصنيف والخطورة والتنبيه. أما الملخصات العربية فهي الجزء الذي ما زال يحتاج تحسيناً، وتعاملنا معها بصراحة: نفحصها قبل النشر، ونسحب ما فيه شك، ونعرض المصدر بجانب كل ملخص.")
para(doc, "وأهم درس خرجنا به أن دقة المعلومة أهم من كثرتها: كل جولة اختبار كشفت خطأً لم نتوقعه، وكل خطأ صار اختباراً آلياً يمنع عودته.")

# ---------- ملحق
heading(doc, "ملحق: الروابط والتشغيل", 1)
table(doc, [
    ["البند", "القيمة"],
    ["الموقع", "https://nfalqhtan-hue.github.io/radar/"],
    ["الكود المصدري", "https://github.com/nfalqhtan-hue/radar"],
    ["تشغيل الاختبارات", "python test_pipeline.py"],
    ["تشغيل دورة يدوياً", "python radar_pipeline.py"],
    ["تجربة الموقع محلياً", "python -m http.server 8765 --directory site"],
    ["تقرير الاختبار التفصيلي", "TEST_REPORT_WEEK6.md وTEST_REPORT_ROUND4.md وTEST_REPORT_FINAL.md"],
], [4.6, USABLE - 4.6], first_bold=True)

out = os.path.join(ROOT, "FINAL_REPORT.docx")
doc.save(out)
print("saved", out)
