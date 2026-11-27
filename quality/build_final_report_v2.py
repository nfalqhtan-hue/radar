# -*- coding: utf-8 -*-
"""Final project report, v2 (after the CTI upgrade). Arabic RTL Word document.
Run: python quality/build_final_report_v2.py  -> FINAL_REPORT_v2.docx in the project folder
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
V2 = os.path.join(ASSETS, "v2", "light")   # screenshots of the live site, light theme
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
L2 = "v2/light/"
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
para(c, "منصة عربية لاستخبارات التهديدات التقنية: تتابع الثغرات الأمنية والتحديثات الرسمية وأخبار التقنية، وترتبها حسب خطرها الحقيقي، وتلخصها وتحللها وتنبه بالخطير منها",
     size=14, color=BRASS, align=WD_ALIGN_PARAGRAPH.RIGHT, after=26, line=1.3)
para(c, "التقرير النهائي للمشروع", size=18, bold=True, color="FFFFFF", align=WD_ALIGN_PARAGRAPH.RIGHT, after=2)
para(c, "النسخة المطورة بعد ترقية المنصة، الأسبوع السابع", size=12, color="C9D2E3", align=WD_ALIGN_PARAGRAPH.RIGHT, after=0)
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
             ("تاريخ التقرير", "27 نوفمبر 2026"), ("التكلفة الكلية", "0 ريال، دون أي اشتراك")):
    q = para(doc, "", after=3, align=WD_ALIGN_PARAGRAPH.RIGHT)
    runs(q, k + ": ", 11, True, MUTED); runs(q, v, 11, False, INK)

# ---------- قسم المحتوى: رأس وتذييل
doc.add_section(WD_SECTION.NEW_PAGE)
s2 = doc.sections[1]; s2.different_first_page_header_footer = False
s2.header.is_linked_to_previous = False; s2.footer.is_linked_to_previous = False
hp = s2.header.paragraphs[0]; bidi(hp); hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
runs(hp, "رادار التقنية", 9, True, NAVY); runs(hp, "  |  التقرير النهائي، النسخة المطورة", 9, False, MUTED)
ppr = hp._p.get_or_add_pPr(); bdr = OxmlElement("w:pBdr"); bb = OxmlElement("w:bottom")
for k, v in (("w:val", "single"), ("w:sz", "6"), ("w:space", "4"), ("w:color", BRASS)): bb.set(qn(k), v)
bdr.append(bb); ppr.append(bdr)
fp = s2.footer.paragraphs[0]; bidi(fp); fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
runs(fp, "صفحة ", 9, False, MUTED); field(fp, "PAGE"); runs(fp, " من ", 9, False, MUTED); field(fp, "NUMPAGES")

# ---------- الفهرس
para(doc, "المحتويات", size=20, bold=True, color=NAVY, align=WD_ALIGN_PARAGRAPH.RIGHT, after=10)
tp = doc.add_paragraph(); bidi(tp); field(tp, 'TOC \\o "1-1" \\h \\z \\u', 12, INK)
page_break(doc)

F = iter(range(1, 60))

# ================================================================== الملخص التنفيذي
heading(doc, "الملخص التنفيذي", 1)
para(doc, "«رادار التقنية» منصة عربية تعمل كل ساعة دون تدخل، وتغطي ثلاث ركائز: **الثغرات الأمنية** من قاعدة NVD وقائمة CISA للثغرات المستغلة، و**التحديثات الأمنية الرسمية** من ست جهات هي Chrome وUbuntu وDebian وCisco وFortinet وOracle، و**أخبار التقنية** من خمس خلاصات. يجمعها وكيل يعمل على جهازنا، فيصنفها، ويأخذ درجة الخطورة الرسمية، ويكتب ملخصاً عربياً بنموذج لغوي محلي يفحصه قبل النشر، ثم ينشر كل شيء في موقع عربي وإنجليزي على GitHub Pages، وينبه على تيليجرام بالثغرات الحرجة والمستغلة.")
para(doc, "وفي الأسبوع السابع رقّينا المشروع من موقع أخبار إلى منصة استخبارات تهديدات: **درجة خطر** من 100 ترتب الثغرات حسب أولوية التصرف، و**صفحة للتحديثات الأمنية**، و**اتجاهات** مبنية على تاريخ 90 يوماً، و**تقرير أمني يومي** يُبنى تلقائياً، و**خريطة تهديدات** لا تضع دولة إلا إذا ذكرها الخبر صراحة. والتكلفة ما زالت صفراً.")
kpis(doc, [("1,204", "ثغرة يتابعها الموقع"), ("47,658", "سجلاً تاريخياً لـ90 يوماً"), ("126", "تحديثاً ونشرة رسمية"), ("122", "اختباراً آلياً ناجحاً"), ("0 ريال", "التكلفة")])
para(doc, "**أهم النتائج:**", after=3)
bullets(doc, [
    "التصنيف ودرجة الخطورة ومطابقة NVD تجاوزت هدف الخطة (90%) في جولات الاختبار الأربع.",
    "درجة الخطر فرّقت ما يحتاج تصرفاً من غيره: 15 ثغرة خطرها حرج و27 عالٍ من أصل 1,204، بدل 73 «حرجة» حسب CVSS وحده.",
    "كل رقم وجملة في التقرير اليومي والاتجاهات والخريطة محسوب من البيانات بقواعد ثابتة، لا يكتبه نموذج لغوي، ولا يتنبأ بالمستقبل.",
    "الملخصات العربية أضعف جزء: بين 65% و79% من المنشور سليم. لذلك يمر كل ملخص بفحوص آلية، ويُعلَّم «ملخص آلي»، ويُعرض بجانبه الوصف الأصلي.",
    "الاختبار النهائي: الصفحات الثماني تعمل بلا أي خطأ، والموقع المنشور يطابق الكود، ولا أسرار في الكود، وكل الوظائف القديمة سليمة.",
])

# ================================================================== المقدمة
page_break(doc)
heading(doc, "المقدمة", 1)
heading(doc, "المشكلة", 2)
para(doc, "الأخبار والتحديثات والثغرات موزعة على عشرات المصادر الرسمية، وأغلبها بالإنجليزية. تنشر قاعدة NVD وحدها بين 300 و2,000 ثغرة يومياً، دون أن تقول أيها يُصلَح أولاً، ونشرات الشركات الأمنية متفرقة على مواقعها. ومتابعة ذلك يدوياً تستهلك وقتاً كبيراً، وقد يفوت المستخدم تحديثاً أمنياً مهماً.")
heading(doc, "الفكرة", 2)
para(doc, "منصة واحدة بالعربية تجمع الركائز الثلاث وتجيب عن سؤال عملي: **ما الذي يحتاج تصرفاً الآن؟** والفرق عن قارئ الأخبار العادي أنها تفصل بين أمرين: خطورة الثغرة الفنية (درجة CVSS)، وثبوت استغلالها فعلاً (قائمة CISA). ثم تجمعهما في درجة خطر واحدة شفافة المعادلة، وتعرض لكل رقم مصدره.")
heading(doc, "الأهداف", 2)
bullets(doc, [
    "مكان عربي واحد للثغرات والتحديثات الأمنية وأخبار التقنية، يتحدث كل ساعة دون عمل يدوي.",
    "تقييم الخطورة من المصدر الرسمي لا من تخمين النموذج، بدقة لا تقل عن 90%.",
    "ترتيب الثغرات حسب أولوية التصرف بمعادلة منشورة يمكن التحقق منها يدوياً.",
    "تنبيه فوري بالثغرات الحرجة أو المستغلة، دون إغراق المتابع بالرسائل.",
    "الدقة قبل الكثرة: لا رقم ولا موقع ولا ملخص بلا دليل في المصدر.",
    "تكلفة صفر: أدوات مجانية ومفتوحة المصدر فقط.",
])
heading(doc, "الفئة المستفيدة", 2)
bullets(doc, [
    "طلاب ومتخصصو الدعم الفني وتقنية المعلومات.",
    "مسؤولو الأنظمة في الشركات الصغيرة، ويحتاجون معرفة ما يُحدَّث أولاً.",
    "المهتمون بالأمن السيبراني، ومستخدمو الحاسب والجوال الراغبون بمعرفة التحديثات المهمة.",
])

# ================================================================== الأدوات
heading(doc, "الأدوات والتقنيات", 1)
para(doc, "اخترنا كل أداة لأنها مجانية وتعمل على جهاز شخصي عادي (ذاكرة 16 جيجابايت، دون كرت شاشة). ولم تُضف الترقية أي حزمة برمجية جديدة: الوكيل ما زال بالمكتبة القياسية لبايثون، والرسوم والخريطة في الموقع مرسومة بـ SVG دون مكتبات.")
table(doc, [
    ["الأداة", "الاستخدام", "سبب الاختيار"],
    ["Python 3 (المكتبة القياسية فقط)", "الوكيل كاملاً: الجلب والتصنيف والتحقق ودرجة الخطر والاتجاهات والتقارير", "لا يحتاج تثبيت أي حزمة، فيعمل على أي جهاز"],
    ["Ollama + Qwen3 8B", "التلخيص بالعربية", "نموذج مفتوح المصدر يعمل محلياً: مجاني، بلا مفتاح API، والبيانات لا تغادر الجهاز"],
    ["SQLite", "قاعدة البيانات: العناصر، والأحداث، وتاريخ 90 يوماً، والتقارير اليومية", "ملف واحد بلا خادم، ومدمج في بايثون"],
    ["مُجدول مهام ويندوز", "تشغيل الدورة كل ساعة في الخلفية", "مدمج في ويندوز، بديلاً عن n8n"],
    ["GitHub Pages + Actions", "استضافة الموقع ونشره تلقائياً عند كل رفع", "استضافة مجانية دون شراء نطاق"],
    ["Telegram Bot API", "التنبيه الفوري", "مجاني وفوري ويصل للجوال"],
    ["HTML وCSS وJavaScript وSVG", "الموقع بصفحاته الثماني، ورسومه البيانية، وخريطته", "دون أي إطار أو مكتبة: صفحات خفيفة، ولا سكربت خارجي"],
    ["Natural Earth", "حدود دول العالم في الخريطة", "بيانات جغرافية مجانية للاستخدام العام، حُوّلت مرة واحدة إلى ملف داخل الموقع"],
], [4.2, 5.8, USABLE - 10])
box(doc, "ما تغيّر عن الخطة ولماذا", [
    "**من n8n إلى مُجدول مهام ويندوز:** عقدة تشغيل الأوامر في n8n 2.0 معطلة افتراضياً، وn8n يحتاج Node.js. والمجدول مدمج ويؤدي الغرض نفسه.",
    "**من Google Sheets إلى SQLite:** قاعدة محلية أسرع وأبسط، ولا تحتاج حساباً أو اتصالاً.",
    "**مساعد ذكي بُني ثم أُزيل:** موقع GitHub Pages لا يستطيع تشغيل نموذج لغوي ولا إخفاء مفتاح API. بنينا مساعداً يجيب من بيانات الموقع فقط، ثم قررنا إزالته لأنه لا يضيف على البحث والصفحات الموجودة ما يبرر وجوده.",
])
heading(doc, "التكلفة", 2)
table(doc, [["البند", "التكلفة"], ["النموذج اللغوي (Ollama محلي)", "0 ريال"], ["الأتمتة (مُجدول مهام ويندوز)", "0 ريال"],
            ["مصادر البيانات (NVD وCISA وست نشرات رسمية وخمس خلاصات أخبار)", "0 ريال"], ["التخزين والاستضافة (SQLite وGitHub Pages)", "0 ريال"],
            ["الخريطة (Natural Earth)", "0 ريال"], ["التنبيهات (Telegram)", "0 ريال"], ["**المجموع**", "**0 ريال، ولا يوجد أي اشتراك**"]], [USABLE * .65, USABLE * .35])

# ================================================================== تصميم النظام
heading(doc, "تصميم النظام", 1)
para(doc, "يعمل النظام كخط معالجة تبدأ دورته كل ساعة. كل خطوة تقرأ من قاعدة البيانات وتكتب فيها، فإذا تعطل مصدر واحد تكمل الدورة ببقية المصادر، ويُسجَّل الفشل ويظهر في الموقع والتقرير اليومي.")
figure(doc, "v2/flow_v2.png", USABLE, "مخطط سير العمل بعد الترقية: المصادر، وخطوات الوكيل، والمخرجات (الجديد بإطار ذهبي)", next(F))
heading(doc, "خطوات الوكيل", 2)
table(doc, [
    ["الخطوة", "ماذا تفعل"],
    ["1. الجلب", "ثغرات NVD المنشورة منذ آخر جلب ناجح، وقائمة CISA الكاملة، والنشرات الرسمية لآخر 30 يوماً، وخمس خلاصات أخبار. وتعيد فحص الثغرات المخزنة لرصد تغير درجتها أو إضافة وسوم Exploit وPatch"],
    ["2. التنظيف والتصنيف", "إزالة HTML وتوحيد التواريخ واستبعاد المكرر. ونوع الخبر بقواعد (أمني، تقني، ذكاء اصطناعي...)، ونوع التحديث (أمني، نشرة، عام)، والمنتج المتأثر من نص الوصف، والخطورة من CVSS، والاستغلال من CISA"],
    ["3. التلخيص", "الأخبار والثغرات المهمة بالنموذج المحلي، والتحديثات والثغرات الأقل أهمية بملخص مبني من بياناتها مباشرة"],
    ["4. التحقق", "رفض أي ملخص فيه لغة أجنبية، أو رقم أو ادعاء غير موجود في المصدر، أو نص مقطوع"],
    ["5. درجة الخطر", "معادلة من 100 تجمع CVSS والاستغلال والعمر ونطاق التعرض والإصلاح، مع سبب كل نقطة"],
    ["6. التحليل والنشر", "سلاسل الاتجاهات، والتقرير اليومي، والمواقع الجغرافية المذكورة صراحة، ثم تصدير ملفات البيانات ورفعها، ورسائل تيليجرام"],
], [3.6, USABLE - 3.6], first_bold=True)
heading(doc, "البيانات", 2)
para(doc, "كل تغيير في قاعدة البيانات يُضاف تلقائياً دون حذف أي سجل: أعمدة جديدة للعناصر الموجودة، وجداول جديدة إن لم تكن موجودة.")
table(doc, [
    ["الجدول", "محتواه"],
    ["items", "كل ثغرة وخبر وتحديث: النص الأصلي، والملخص ومصدره، والخطورة والدرجة، والاستغلال، والمنتج، وروابط NVD الموسومة، ونوع الضعف، وحقول التحديث (النوع والإصدارات والثغرات)"],
    ["events", "كل حدث حقيقي: ثغرة جديدة، أو إدراج في قائمة الاستغلال، أو تغير درجة، أو تنبيه أُرسل، أو نجاح جلب كل مصدر وفشله"],
    ["vuln_history (جديد)", "التاريخ والدرجة ونوع الضعف والمنتج لكل ثغرة نشرتها NVD في آخر 90 يوماً (47,658 سجلاً)، للاتجاهات فقط"],
    ["reports (جديد)", "تقرير لكل يوم مكتمل، يُحفظ 90 يوماً"],
], [3.8, USABLE - 3.8], first_bold=True)
table(doc, [
    ["الملف المنشور", "محتواه", "تستخدمه"],
    ["data.json", "آخر 120 خبراً و150 تحديثاً و250 ثغرة، وكل الثغرات المستغلة، ودرجة خطر كل ثغرة", "كل الصفحات"],
    ["details.json", "الوصف الأصلي، وبيانات CISA، وعوامل درجة الخطر، والروابط الرسمية", "نافذة التفاصيل"],
    ["stats.json وevents.json", "إحصائيات القاعدة كاملة، وسجل الأحداث وصحة المصادر", "الإحصائيات والتنبيهات والتحديثات"],
    ["trends.json (جديد)", "سلاسل يومية لـ90 يوماً وساعية لـ48 ساعة، وترتيب المنتجات وأنواع الضعف", "الاتجاهات"],
    ["map.json (جديد)", "الحوادث بمواقعها المذكورة صراحة ونص الدليل، والحوادث بلا موقع", "الخريطة"],
    ["reports/ (جديد)", "التقارير اليومية وفهرسها", "التقرير اليومي"],
], [3.6, 8.6, USABLE - 12.2])

# ================================================================== مبادئ سلامة البيانات
heading(doc, "مبادئ سلامة البيانات", 1)
para(doc, "منصة تتحدث عن الأمن السيبراني تفقد قيمتها إذا اخترعت رقماً أو موقعاً أو ثغرة. لذلك بنينا كل ميزة جديدة على ستة مبادئ، وكل مبدأ منها له اختبار آلي يمنع كسره:")
table(doc, [
    ["المبدأ", "كيف طبقناه"],
    ["لا بيانات مخترعة", "كل رقم في الموقع محسوب من سجلات حقيقية، وكل عنصر يرتبط بمصدره الأصلي وتاريخه"],
    ["الخطورة غير الاستغلال", "درجة CVSS وإدراج CISA حقلان منفصلان في كل صفحة. ولا نعتبر ثغرة «مستغلة» إلا إذا أدرجتها CISA، حتى لو قال وصفها «exploited in the wild»"],
    ["نقص المعلومة ليس حكماً", "غياب وسم Exploit لا يعني عدم وجود استغلال، فالعامل غير المعروف يُستبعد من المعادلة بدل أن يُحسب صفراً. وثغرة بلا درجة ولا إدراج تظهر «بيانات غير كافية» لا رقماً"],
    ["لا موقع إلا بنص صريح", "الخريطة لا تستنتج الدولة من عنوان IP، ولا من مقر الشركة، ولا من جنسيتها. تضعها فقط إذا قال الخبر ذلك، وتقتبس الدليل"],
    ["الحقائق قبل النموذج", "التقرير اليومي والاتجاهات وملخصات التحديثات مبنية بقواعد ثابتة. والنموذج اللغوي يكتب ملخصات الأخبار والثغرات فقط، ويُعلَّم كل ملخص منها"],
    ["الإفصاح عن النقص", "الأيام قبل بدء الرصد تظهر «لم يُرصد» لا صفراً، والتقرير يذكر ساعات عمل الرادار، وفشل أي مصدر يظهر مع رسالة الخطأ"],
], [4.2, USABLE - 4.2], first_bold=True)

# ================================================================== التنفيذ
heading(doc, "التنفيذ خلال الأسابيع السبعة", 1)
table(doc, [
    ["الأسبوع", "النشاط", "المخرج"],
    ["1", "تحديد المشكلة والأهداف والفئة المستفيدة", "وصف المشروع"],
    ["2", "اختيار الأدوات ومقارنة البدائل المجانية", "قائمة الأدوات، والتكلفة 0 ريال"],
    ["3", "تصميم خطوات عمل الوكيل", "مخطط سير العمل"],
    ["4", "نموذج أولي: جلب وتصنيف وتلخيص من مصدر واحد", "نموذج أولي يعمل"],
    ["5", "ربط كل المصادر، والجدولة، والنشر في الموقع", "خط معالجة متكامل (21 اختباراً)"],
    ["6", "ثلاث جولات اختبار، وإصلاح 12 خطأ، ونشر الموقع، وتفعيل تيليجرام", "تقرير الاختبار، و44 اختباراً"],
    ["7", "جولة اختبار رابعة، وتطوير الموقع على ثماني مراحل، ثم الترقية إلى منصة استخبارات تهديدات", "ثماني صفحات، و122 اختباراً، والتقرير والعرض"],
], [2, 9.4, USABLE - 11.4])
heading(doc, "الترقية إلى منصة استخبارات تهديدات", 2)
para(doc, "نفذنا الترقية على مراحل. فحصنا المشروع وكتبنا خطة قبل أي تعديل، ثم نشرنا كل مرحلة واختبرناها قبل التالية، فبقي الموقع يعمل طوال الوقت، ولم يُحذف أي سجل تاريخي. وقبل كل مرحلة أخذنا نسخة احتياطية من القاعدة والكود.")
table(doc, [
    ["المرحلة", "ما أُضيف", "الاختبارات"],
    ["0. الفحص والخطة", "تقرير ببنية المشروع ومصادره، وما يمكن بناؤه بصدق وما يحتاج بنية إضافية", "77"],
    ["1. درجة الخطر", "روابط NVD الموسومة ونوع الضعف، ومعادلة من 100، وشارات وترتيب وتصفية، وتفصيل في كل ثغرة", "89"],
    ["2. التحديثات الأمنية", "ست نشرات رسمية، وصفحة التحديثات، وفصل الأخبار الأمنية عن التقنية", "101"],
    ["3. الاتجاهات", "تاريخ 90 يوماً من NVD، وإضافات CISA اليومية، وصفحة الاتجاهات", "109"],
    ["4. التقرير اليومي", "تقرير لكل يوم مكتمل، وأرشيف، وتصدير PDF", "115"],
    ["5. الخريطة", "استخراج الدولة ودورها من نص الخبر مع الدليل، وخريطة العالم", "122"],
    ["6. الاختبار النهائي", "فحص الأمان والموقع المنشور والوظائف القديمة والروابط والوكيل، والتقرير الفني", "122"],
], [3.6, USABLE - 5.6, 2], first_bold=True)

# ================================================================== الموقع
page_break(doc)
heading(doc, "الموقع: ثماني صفحات", 1)
para(doc, "الموقع منشور على https://nfalqhtan-hue.github.io/radar/ ويعمل بالعربية (افتراضياً) والإنجليزية، وبالوضعين الفاتح والداكن، وعلى الجوال. وكل فلتر أو بحث أو ثغرة مفتوحة يُحفظ في الرابط، فيمكن مشاركة أي نتيجة.")
heading(doc, "الصفحة الرئيسية", 2)
para(doc, "تبدأ بشاشة رادار حية لعناصر آخر 24 ساعة: بُعد النقطة عن المركز عمرها، ولونها وحجمها خطورتها. وبجانبها أخطر أربع ثغرات. وتحتها كل ما رصدناه من ثغرات وتحديثات وأخبار، مع بحث، وفلاتر للنوع والتاريخ والخطورة ودرجة الخطر، ومفتاح «الجديد فقط»، وترتيب «الأعلى خطراً»، وزر تصدير PDF.")
figure(doc, L2 + "home.png", USABLE, "الصفحة الرئيسية: الرادار وقائمة «ما يحتاج انتباهك الآن»", next(F))
figure(doc, L2 + "home_feed.png", USABLE, "الخلاصة مرتبة حسب درجة الخطر: شارة الخطورة (CVSS) وشارة الخطر (من 100) منفصلتان", next(F))
heading(doc, "تفاصيل الثغرة ودرجة الخطر", 2)
para(doc, "الضغط على أي ثغرة يفتح نافذة فيها: درجة CVSS، ثم **درجة الخطر** وجدول عواملها (القيمة والوزن والنقاط التي أضافها كل عامل)، والإجراء المقترح بقواعد ثابتة، والروابط الرسمية من NVD، ثم الوصف الأصلي والملخص العربي وبيانات CISA.")
figure(doc, L2 + "detail.png", USABLE * .8, "ثغرة مستغلة: درجة خطرها 99، وجدول العوامل يبيّن مصدر كل نقطة", next(F))
heading(doc, "مركز التنبيهات", 2)
para(doc, "يعرض الثغرات التي تحتاج تصرفاً في خمسة تبويبات: الكل، و«خطر حرج أو عالٍ (70+)»، وثبت استغلالها، وحرجة، وعالية. والخطورة ودرجة الخطر والاستغلال في أعمدة منفصلة. وفي أسفلها سجل الرسائل التي أُرسلت فعلاً على تيليجرام.")
figure(doc, L2 + "alerts.png", USABLE, "مركز التنبيهات مرتباً حسب درجة الخطر", next(F))
heading(doc, "التحديثات الأمنية", 2)
para(doc, "صفحة جديدة للركيزة الثالثة: 126 تحديثاً ونشرة من المصادر الرسمية في آخر 30 يوماً. تفصل بين التحديث الأمني (49) والنشرة الأمنية (69) والتحديث العام بلا إصلاحات (8)، وتعرض الإصدار المصحح والمتأثر **فقط إذا ذكرته الشركة**. وتبويب «تحتاج تصرفاً الآن» يجمع التحديثات التي تصلح ثغرة في قائمة CISA أو ذكرت الشركة أنها مستغلة (9 تحديثات).")
figure(doc, L2 + "updates.png", USABLE, "صفحة التحديثات الأمنية", next(F))
heading(doc, "الإحصائيات", 2)
para(doc, "كل رقم محسوب من القاعدة كاملة: الثغرات حسب الخطورة وحسب درجة الخطر جنباً إلى جنب، ورسم زمني، وأكثر المنتجات ظهوراً، والأخبار حسب التصنيف، ومصدر الملخصات، والتحديثات حسب الشركة والنوع.")
figure(doc, L2 + "dashboard.png", USABLE * .66, "صفحة الإحصائيات", next(F))
heading(doc, "الاتجاهات", 2)
para(doc, "تحليل تاريخي لا توقع: فترات 24 ساعة و7 و30 و90 يوماً أو فترة مخصصة، وكل مؤشر يُقارن بالفترة المساوية قبلها. وتحتها جمل «ماذا تقول الأرقام» محسوبة بقواعد، ورسوم للثغرات الجديدة، والحرجة والعالية، وإضافات CISA، وأكثر أنواع الضعف والمنتجات، والتحديثات، والأخبار.")
figure(doc, L2 + "trends_top.png", USABLE, "الاتجاهات لآخر 30 يوماً: الثغرات الحرجة 1,408، بانخفاض 11% عن الفترة السابقة", next(F))
figure(doc, L2 + "trends_charts.png", USABLE, "رسوم الاتجاهات: الثغرات الجديدة يومياً، والحرجة والعالية، وإضافات قائمة CISA", next(F))
heading(doc, "التقرير اليومي", 2)
para(doc, "يُبنى تلقائياً بعد منتصف الليل لليوم السابق، ويحتوي: ملخصاً تنفيذياً، وأخطر 5 ثغرات، وإضافات CISA، وأهم التحديثات، والأخبار الأمنية والتقنية، وتوصيات مبنية على سجلات التقرير، وملخص جمع البيانات بنجاح كل مصدر وفشله. ويُحفظ 90 يوماً في أرشيف، ويُصدَّر PDF.")
figure(doc, L2 + "report.png", USABLE * .66, "التقرير الأمني اليومي، ويذكر ساعات عمل الرادار في ذلك اليوم", next(F))
heading(doc, "خريطة التهديدات", 2)
para(doc, "تضع الحادثة على دولة فقط إذا قال الخبر ذلك في جملة عن هجوم: إما **منسوبة إليها** حسب المصدر («China-linked hackers»)، أو **مكان الجهة المستهدفة** («breached a Russian organization»). وتحت كل حادثة نص الدليل من الخبر. وفي آخر 30 يوماً وُضعت 9 حوادث على 7 دول، وبقيت 83 «بلا موقع»، وهذا هو الصادق.")
figure(doc, L2 + "map.png", USABLE * .9, "خريطة التهديدات: لوحة الصين تعرض الحوادث المنسوبة إليها مع الدليل من نص الخبر", next(F))
heading(doc, "الجوال واللغة الإنجليزية", 2)
para(doc, "على الجوال تنطوي الفلاتر، وتتحول الجداول إلى بطاقات، ولا يوجد تمرير أفقي في أي صفحة. وبالإنجليزية يتغير اتجاه الصفحة كاملة.")
t2 = new_table(doc, 1, [USABLE / 3] * 3); no_borders(t2)
for i, img in enumerate(("m_updates.png", "m_map.png", "m_report.png")):
    q = t2.cell(0, i).paragraphs[0]; q.alignment = WD_ALIGN_PARAGRAPH.CENTER
    q.add_run().add_picture(os.path.join(ASSETS, L2 + img), width=Cm(4.6))
c = para(doc, "", size=9.5, align=WD_ALIGN_PARAGRAPH.CENTER, after=10)
runs(c, f"شكل {next(F)}: ", 9.5, True, ACCENT); runs(c, "التحديثات والخريطة والتقرير اليومي على الجوال", 9.5, False, MUTED)
figure(doc, L2 + "trends_en.png", USABLE * .85, "صفحة الاتجاهات بالإنجليزية", next(F))

# ================================================================== درجة الخطر
heading(doc, "محرك تقييم الخطورة", 1)
para(doc, "درجة CVSS تقول كم قد تكون الثغرة سيئة، لكنها لا تقول هل تُستغل الآن. لذلك أضفنا **درجة خطر** من 0 إلى 100 تقيس أولوية التصرف. كل درجة محسوبة من بيانات تظهر في صفحة الثغرة، ويمكن إعادة حسابها يدوياً، وتعطي النتيجة نفسها لنفس المدخلات.")
table(doc, [
    ["العامل", "الوزن", "القيمة (من 0 إلى 1)"],
    ["درجة CVSS", "35%", "درجة NVD مقسومة على 10"],
    ["الاستغلال", "50%", "1 إن كانت في قائمة CISA، و0.7 إن لم تكن لكن الاستغلال منشور (وسم Exploit في NVD أو وصف الجهة المبلّغة)، و0 غير ذلك"],
    ["العمر ونطاق التعرض", "10%", "متوسط الحداثة (من 1 إلى 0.4) ونطاق الهجوم من متجه CVSS (عبر الشبكة بلا صلاحيات 1، ومحلي 0.3، ومادي 0.1)"],
    ["الإصلاح الرسمي", "5%", "0 إن وُجد رابط إصلاح في NVD فتنخفض الأولوية، وإلا غير معروف"],
], [4, 1.8, USABLE - 5.8], first_bold=True)
box(doc, "المعادلة", [
    "الدرجة = 100 × مجموع (الوزن × القيمة) للعوامل المعروفة ÷ مجموع أوزان العوامل المعروفة.",
    "العامل غير المعروف يُستبعد من الطرفين، فلا يُحسب نقص البيانات ضد الثغرة ولا لها. والمستويات: من 90 حرج، ومن 70 عالٍ، ومن 40 متوسط، وأقل من 40 منخفض.",
])
heading(doc, "التحقق من الأوزان على بياناتنا", 2)
para(doc, "جربنا أولاً أوزان الخطة كما هي على 1,190 ثغرة حقيقية: 35% لدرجة CVSS، و35% للإدراج في CISA، و15% للاستغلال المنشور، و10% للعمر، و5% للإصلاح. فاكتشفنا أن الثغرة غير المدرجة في CISA لا يمكن أن تتجاوز «متوسط» مهما كانت، فبقيت ثغرة درجتها 9.8 واستغلالها منشور «متوسطة». فدمجنا الاستغلال المؤكد والمنشور في عامل واحد وزنه 50%، يُحسب فيه المنشور 0.7، فصارت مثل هذه الثغرة «عالية» (83)، وبقيت المدرجة في CISA «حرجة».")
table(doc, [
    ["المستوى", "بالأوزان الأولى", "بالأوزان المعتمدة", "اليوم"],
    ["خطر حرج", "15", "15", "15"],
    ["خطر عالٍ", "4", "26", "27"],
    ["خطر متوسط", "538", "190", "190"],
    ["خطر منخفض", "539", "865", "875"],
    ["بيانات غير كافية", "97", "97", "97"],
], [4.6] + [(USABLE - 4.6) / 3] * 3, first_bold=True)
para(doc, "والنتيجة أن 42 ثغرة فقط من 1,204 تحتاج تصرفاً عاجلاً (حرج أو عالٍ)، بدل 73 ثغرة «حرجة» حسب CVSS وحده، أغلبها غير مستغل.", size=10.5, color=MUTED)

# ================================================================== الاختبار
heading(doc, "الاختبار والجودة", 1)
heading(doc, "طريقة الاختبار", 2)
bullets(doc, [
    "أربع جولات مراجعة يدوية، في كل جولة عينة من 20 عنصراً حياً (12 خبراً و8 ثغرات)، وكل عنصر قورن بمصدره الأصلي.",
    "مطابقة رقم CVE وتاريخ النشر ودرجة CVSS مع NVD باستعلام منفصل لكل ثغرة.",
    "اختبار التنبيه بثلاث ثغرات حرجة معروفة: Log4Shell وPAN-OS وCitrix Bleed.",
    "اختبارات آلية لكل خطأ وجدناه بمثال حقيقي، تعمل دون إنترنت مع كل تعديل.",
    "اختبار نهائي للموقع المنشور: الأمان، والروابط، والوظائف القديمة، والجوال، واللغتين، وصحة الوكيل.",
])
heading(doc, "نتائج الجولات الأربع", 2)
figure(doc, "rounds.png", USABLE, "تطور الدقة عبر جولات الاختبار الأربع", next(F))
table(doc, [
    ["المقياس", "الجولة 1", "الجولة 2", "الجولة 3", "الجولة 4", "الهدف"],
    ["دقة التصنيف", "95%", "100%", "90%", "95%", "90%"],
    ["دقة الخطورة", "88%", "100%", "100%", "100%", "90%"],
    ["مطابقة CVSS مع NVD", "75%", "100%", "100%", "100%", "—"],
    ["مطابقة رقم CVE والتاريخ", "100%", "100%", "100%", "100%", "100%"],
    ["الملخصات المنشورة السليمة", "30%", "75%", "79%", "65%", "—"],
    ["تنبيه الثغرات الحرجة المعروفة", "3/3", "3/3", "3/3", "3/3", "فوري"],
], [5.4] + [(USABLE - 5.4) / 5] * 5, first_bold=True)
heading(doc, "الاختبارات الآلية", 2)
para(doc, "ارتفع عدد الفحوص الآلية من 21 في الأسبوع الخامس إلى 44 في السادس، ثم 77 بعد تطوير الأسبوع السابع، ثم **122** بعد الترقية، وكلها ناجحة. ومن الفحوص الجديدة:")
bullets(doc, [
    "درجة الخطر تعطي النتيجة نفسها لنفس المدخلات، والعامل غير المعروف لا يُحسب ضد الثغرة، وعبارة «exploited in the wild» وحدها لا تجعل الثغرة مستغلة.",
    "استخراج الإصدارات والثغرات من نشرات Chrome وUbuntu وCisco، وتجاهل إصدارات Beta، وعدم إرسال تنبيه تيليجرام لتحديث.",
    "حساب الأيام بتوقيت الرياض، والأيام قبل بدء الرصد «لم تُرصد» لا صفر.",
    "التقرير اليومي يُبنى مرة واحدة لكل يوم مكتمل، ويكشف فشل المصادر مع رسالة الخطأ.",
    "الخريطة: جنسية الشركة المتهمة لا تجعل دولتها «ضحية»، والدولة المذكورة خارج جملة عن هجوم لا توضع.",
])
heading(doc, "الاختبار النهائي للمنصة", 2)
table(doc, [
    ["البند", "النتيجة"],
    ["الاختبارات الآلية", "✓ 122 من 122"],
    ["الأسرار في الكود", "✓ لا توكن ولا مفتاح ولا بريد شخصي في أي ملف"],
    ["سياسة أمان المحتوى", "✓ في الصفحات الثماني، وبصمة السكربت المضمّن مطابقة، ولا سكربت خارجي"],
    ["ملفات البيانات", "✓ لا كود مدسوس، والتطابق الوحيد نص وصف ثغرة يُعرض كنص"],
    ["الموقع المنشور", "✓ كل الصفحات والملفات تعمل (200)، والمنشور يطابق الكود حرفياً"],
    ["أخطاء المتصفح", "✓ صفر في الصفحات الثماني"],
    ["الوظائف القديمة", "✓ البحث والفلاتر والتفاصيل والإنجليزية والوضع الداكن وتصدير PDF"],
    ["الجوال", "✓ لا تمرير أفقي في أي صفحة"],
    ["الروابط", "✓ الداخلية كلها، وعينة من المصادر (موقعان يرفضان البرامج فقط ويعملان في المتصفح)"],
    ["الوكيل", "✓ آخر الدورات رُفعت بلا خطأ، وقاعدة البيانات سليمة، ولا مهام مكررة"],
], [5, USABLE - 5], first_bold=True)

# ================================================================== الأخطاء
page_break(doc)
heading(doc, "الأخطاء التي اكتشفناها وكيف أصلحناها", 1)
para(doc, "أهم ما تعلمناه أن الاختبار يكشف أخطاء لا تظهر بقراءة الكود. وكل خطأ هنا صار اختباراً آلياً يمنع عودته.")
table(doc, [
    ["الخطأ", "السبب", "الإصلاح", "النتيجة"],
    ["ملخصات تتحول للصينية والروسية وسط الجملة", "ضعف النموذج القديم بالعربية", "Qwen3 8B، وحارس جودة يرفض أي لغة أجنبية", "من 30% إلى 79% سليم"],
    ["ثغرات تضيع وقت إطفاء الجهاز", "الجلب من آخر ساعتين فقط", "الجلب منذ آخر جلب ناجح", "استُعيدت 372 ثغرة"],
    ["كل ثغرة مستغلة تُعرض «حرجة»", "خلط الخطورة بالاستغلال", "حقلان منفصلان", "9 فقط من 19 حرجة فعلاً"],
    ["ملخصات تقول «دون مصادقة» بلا دليل", "النموذج يضيف تفاصيل", "دليل صريح في المصدر لكل ادعاء", "سُحب 31 ملخصاً"],
    ["ثغرة 9.8 واستغلالها منشور تبقى «متوسطة»", "أوزان الخطة تحصر «عالٍ» في قائمة CISA", "عامل استغلال واحد بوزن 50%", "27 ثغرة عالية بدل 4"],
    ["الأخبار الأمنية تغطي على الأخبار التقنية", "تصنيف واحد للنوعين (71% أمني)", "تصنيف «أخبار أمنية» مستقل", "75 أمنية و55 تقنية عامة"],
    ["رابط منشورات Chrome يفتح التعليقات", "الخلاصة تضع رابط التعليقات أولاً", "اختيار الرابط rel=alternate", "الرابط يفتح المنشور"],
    ["«الصين» ضحية في خبر عن شركة صينية متهمة", "نمط الجنسية قبل كلمة «شركة»", "الجنسية تُحسب ضحية فقط بعد فعل هجوم", "اختبار سلبي يمنع عودته"],
    ["مقارنة الأخبار لـ30 يوماً تقول «انخفاض»", "الأيام قبل بدء الجمع تُحسب صفراً", "قيمة فارغة لما قبل بدء الرصد", "«منذ بدء الجمع، فلا مقارنة»"],
], [4.2, 3.6, 4.4, USABLE - 12.2], size=9.5)

# ================================================================== الأمان
heading(doc, "الأمان والخصوصية", 1)
bullets(doc, [
    "لا توجد أي مفاتيح أو كلمات مرور في الكود المنشور. توكن تيليجرام محفوظ في متغيرات بيئة الجهاز فقط.",
    "النموذج اللغوي يعمل على الجهاز نفسه، فلا تُرسل البيانات لأي خدمة ذكاء اصطناعي خارجية. والموقع لا يتصل بأي جهة خارجية: حتى الخريطة ملف داخله.",
    "الموقع يعرض كل نص قادم من المصادر كنص عادي لا كـ HTML، ويقبل الروابط بصيغة http وhttps فقط، فلا يمكن لمحتوى خبيث في مصدر خارجي أن ينفذ كوداً.",
    "سياسة أمان المحتوى (CSP) في كل صفحة تمنع تحميل أي سكربت غير سكربتات الموقع.",
    "مراجعة أمنية آلية كل يوم الساعة 9 صباحاً، للقراءة فقط: تقارن الموقع المنشور بالكود، وتفحص الأسرار وبصمات الملفات الحساسة وسجل النشر.",
    "نحترم حقوق النشر: ننشر ملخصاً قصيراً مع رابط المصدر، ولا ننسخ المقالات.",
])

# ================================================================== القيود
heading(doc, "القيود والتطوير المستقبلي", 1)
heading(doc, "قيود معروفة", 2)
bullets(doc, [
    "**الملخصات:** من نموذج صغير قد يخطئ في المعنى بطرق لا يكشفها فحص آلي، لذلك يُعلَّم كل ملخص ويرتبط بمصدره.",
    "**لا يوجد خادم:** الوكيل يعمل على جهازنا، فلا يتحدث الموقع وهو مطفأ، ولا يُبنى تقرير ليوم لم يعمل فيه.",
    "**عمق التاريخ:** اتجاهات الثغرات تغطي 90 يوماً، أما الأخبار والتحديثات فتبدأ من بدء جمعها، وتطول مقارناتها مع الوقت.",
    "**الخريطة:** تعتمد على ذكر صريح، فأغلب الأخبار تبقى بلا موقع.",
    "**مصادر غير مغطاة:** نشرات Microsoft وApple وMozilla لا توفر خلاصة يقرؤها برنامج، وثغراتها تصل عبر NVD.",
    "**المساعد الذكي:** يحتاج خادماً لتشغيل نموذج أو حماية مفتاح، وهذا غير متاح في استضافة ثابتة مجانية.",
])
heading(doc, "تطوير مقترح", 2)
bullets(doc, [
    "تشغيل الوكيل على خادم مجاني دائم بدل الجهاز الشخصي، فتكتمل التقارير اليومية كل يوم.",
    "نموذج أكبر أو جهاز بكرت شاشة لرفع دقة الملخصات.",
    "إرسال التقرير اليومي على تيليجرام أو البريد تلقائياً.",
    "قياس دقة درجة الخطر بمقارنة ما صنفته «عالياً» بما أُدرج لاحقاً في قائمة CISA.",
    "مراجعة شهرية للموقع يقترح فيها الفريق تحسينات، وتُسجل في ملف IMPROVEMENTS.md.",
])

# ================================================================== الاستفادة التجارية
heading(doc, "الاستفادة التجارية", 1)
bullets(doc, [
    "اشتراك في التقرير الأمني اليومي بالعربية للشركات الصغيرة وأقسام تقنية المعلومات.",
    "تقارير مخصصة بالمنتجات التي تستخدمها المنشأة، مرتبة حسب درجة الخطر.",
    "واجهة API لبيانات الثغرات المصنفة ودرجات خطرها.",
    "إعلانات ورعايات من شركات تقنية في الموقع والنشرة.",
])

# ================================================================== الخاتمة
heading(doc, "الخاتمة", 1)
para(doc, "بدأنا بوكيل يجمع الأخبار ويلخصها، وانتهينا بمنصة تجيب عن سؤال عملي: ما الذي يحتاج تصرفاً الآن؟ تعمل وحدها كل ساعة، وتغطي الثغرات والتحديثات الرسمية والأخبار، وترتبها بدرجة خطر شفافة، وتحللها عبر الزمن، وتكتب تقريراً يومياً، بتكلفة صفر وأدوات مفتوحة المصدر.")
para(doc, "وأهم درس خرجنا به أن دقة المعلومة أهم من كثرتها. لذلك فضّلنا خريطة قليلة النقاط على خريطة مليئة بمواقع مستنتجة، و«بيانات غير كافية» على رقم غير موثوق، وصرّحنا بكل قيد بدل أن نخفيه.")

# ---------- ملحق
heading(doc, "ملحق: الروابط والتشغيل", 1)
table(doc, [
    ["البند", "القيمة"],
    ["الموقع", "https://nfalqhtan-hue.github.io/radar/"],
    ["الكود المصدري", "https://github.com/nfalqhtan-hue/radar"],
    ["تشغيل الاختبارات", "python test_pipeline.py"],
    ["تشغيل دورة يدوياً", "python radar_pipeline.py"],
    ["تحميل تاريخ 90 يوماً (مرة واحدة)", "python radar_pipeline.py --backfill-history"],
    ["تجربة الموقع محلياً", "python -m http.server 8765 --directory site"],
    ["التقارير التفصيلية", "CTI_TECHNICAL_REPORT.md وCTI_PLAN.md وTEST_REPORT_FINAL.md"],
], [5.2, USABLE - 5.2], first_bold=True)

out = os.path.join(ROOT, "FINAL_REPORT_v2.docx")
doc.save(out)
print("saved", out)
