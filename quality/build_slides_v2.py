# -*- coding: utf-8 -*-
"""Presentation v2 (after the CTI upgrade): a guided tour of the site, Arabic RTL, with speaker notes.
Run: python quality/build_slides_v2.py  -> FINAL_PRESENTATION_v2.pptx
"""
import os, re
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION, XL_LABEL_POSITION
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.oxml.ns import qn
from pptx.util import Inches, Pt, Emu

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = lambda n: os.path.join(ROOT, "report_assets", n)
FONT = "Dubai"
NAVY, INK, BRASS, GOLD_D, RED, MUTED, PAPER, LINE, WHITE, TEAL = ("14213D", "0A1428", "C9A063", "7E5A22", "B3261E", "586379",
                                                                 "F3F5F9", "D8DEE8", "FFFFFF", "2C7A6B")
W, H = 13.333, 7.5
M = 0.6                      # الهامش
rgb = RGBColor.from_string
# مقطع لاتيني: كلمات وأرقام متصلة، وما بينها من مسافات وعلامات + و& و/ و.
LATIN = re.compile(r"[A-Za-z0-9][\w.\-/:%+=≥'’@]*(?:(?: |\s[+&]\s)[A-Za-z0-9][\w.\-/:%+=≥'’@]*)*")

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(W), Inches(H)
BLANK = prs.slide_layouts[6]

# ------------------------------------------------------------------ أدوات
def text(slide, x, y, w, h, paras, size=16, color=INK, bold=False, align="r", anchor="t", name=None, spacing=1.15):
    """paras: نص، أو قائمة فقرات؛ الفقرة نص أو قائمة مقاطع (نص، {size,bold,color})."""
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    if name: tb.name = name
    tf = tb.text_frame; tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05); tf.margin_top = tf.margin_bottom = Inches(0.02)
    tf.vertical_anchor = {"t": MSO_ANCHOR.TOP, "m": MSO_ANCHOR.MIDDLE, "b": MSO_ANCHOR.BOTTOM}[anchor]
    if isinstance(paras, str): paras = [paras]
    for i, para in enumerate(paras):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = {"r": PP_ALIGN.RIGHT, "c": PP_ALIGN.CENTER, "l": PP_ALIGN.LEFT}[align]
        p.line_spacing = spacing
        p._p.get_or_add_pPr().set("rtl", "0" if align == "l" else "1")
        segs = [(para, {})] if isinstance(para, str) else para
        for seg, o in segs:
            # الأرقام والكلمات اللاتينية في مقاطع لغتها en-US فتبقى الأرقام غربية (مثل الموقع)،
            # وبقية النص بما فيه علامات الترقيم بالعربية فلا تنقلب النقطتان والأقواس
            # the comma of "47,658" falls in an Arabic run between two Latin runs and PowerPoint shows "658,47":
            # slides use numbers without a thousands separator
            seg = re.sub(r"(?<=\d),(?=\d{3}(?!\d))", "", seg)
            pos = 0
            pieces = []
            for m in LATIN.finditer(seg):
                if m.start() > pos: pieces.append((seg[pos:m.start()], "ar-SA"))
                pieces.append((m.group(), "en-US")); pos = m.end()
            if pos < len(seg): pieces.append((seg[pos:], "ar-SA"))
            for piece, lang in pieces:
                # PowerPoint reverses "47,658" inside an RTL paragraph (shows 658,47): no thousands separator in slides
                if lang == "en-US": piece = re.sub(r"(?<=\d),(?=\d{3})", "", piece)
                r = p.add_run(); r.text = piece
                f = r.font; f.name = FONT; f.size = Pt(o.get("size", size)); f.bold = o.get("bold", bold)
                f.color.rgb = rgb(o.get("color", color))
                rpr = r._r.get_or_add_rPr(); rpr.set("lang", lang)
                for tag in ("a:latin", "a:cs"):
                    e = rpr.find(qn(tag))
                    if e is None: e = rpr.makeelement(qn(tag), {}); rpr.append(e)
                    e.set("typeface", FONT)
    return tb

def box(slide, x, y, w, h, fill, radius=0.08, line=None, name=None):
    s = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    s.adjustments[0] = radius
    s.fill.solid(); s.fill.fore_color.rgb = rgb(fill)
    if line: s.line.color.rgb = rgb(line); s.line.width = Pt(1)
    else: s.line.fill.background()
    s.shadow.inherit = False
    if name: s.name = name
    return s

def circle(slide, x, y, d, fill, label, size=16, color=NAVY):
    s = slide.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
    s.fill.solid(); s.fill.fore_color.rgb = rgb(fill); s.line.fill.background(); s.shadow.inherit = False
    tf = s.text_frame; tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
    r = p.add_run(); r.text = label; r.font.size = Pt(size); r.font.bold = True; r.font.name = FONT; r.font.color.rgb = rgb(color)
    r._r.get_or_add_rPr().set("lang", "en-US")
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    return s

def bg(slide, color):
    f = slide.background.fill; f.solid(); f.fore_color.rgb = rgb(color)

def pic(slide, name, x, y, w=None, h=None, frame=False):
    if frame: box(slide, x - 0.06, y - 0.06, (w or 0) + 0.12, (h or 0) + 0.12, LINE, 0.03)
    return slide.shapes.add_picture(A(name), Inches(x), Inches(y), Inches(w) if w else None, Inches(h) if h else None)

def title(slide, t, sub=None, dark=False):
    text(slide, M, 0.42, W - 2 * M, 0.8, t, 34, WHITE if dark else NAVY, True, name="Title")
    if sub: text(slide, M, 1.18, W - 2 * M, 0.5, sub, 16, "C9D2E3" if dark else MUTED, name="Subtitle")

def footer(slide, n, dark=False):
    c = "6F7FA0" if dark else MUTED
    text(slide, M, H - 0.45, 6, 0.3, "رادار التقنية  |  العرض النهائي للمشروع", 10, c)
    text(slide, W - M - 1, H - 0.45, 1, 0.3, str(n), 10, c, align="l")

def notes(slide, s):
    slide.notes_slide.notes_text_frame.text = s

def new(dark=False):
    s = prs.slides.add_slide(BLANK); bg(s, INK if dark else WHITE); return s

N = iter(range(1, 99))

S = "v2/slides/"
from PIL import Image as _Img
def size_of(name):
    with _Img.open(A(name)) as im: return im.size

def shot(slide, name, x, y, w=None, h=None):
    """Screenshot with a thin navy frame; give w or h, the other follows the image ratio."""
    iw, ih = size_of(name)
    if w is None: w = h * iw / ih
    if h is None: h = w * ih / iw
    box(slide, x - 0.05, y - 0.05, w + 0.1, h + 0.1, "2A4170", 0.02)
    slide.shapes.add_picture(A(name), Inches(x), Inches(y), Inches(w), Inches(h))
    return w, h

def points(slide, x, y, w, items, gap_=1.45, tsize=19, dsize=14):
    for i, (t, d) in enumerate(items):
        yy = y + i * gap_
        box(slide, x + w - 0.08, yy + 0.08, 0.08, 0.42, BRASS, 0.5)
        text(slide, x, yy, w - 0.25, 0.5, t, tsize, NAVY, True)
        text(slide, x, yy + 0.5, w - 0.25, gap_ - 0.55, d, dsize, MUTED)

def page_slide(t, sub, img, items, note, gap_=1.45):
    s = new(); title(s, t, sub)
    top = 1.75 if sub else 1.5
    iw, ih = size_of(img); h = min(H - top - 0.75, 7.9 * ih / iw); w = h * iw / ih
    shot(s, img, M + 0.05, top, w, h)
    cx = M + w + 0.45; points(s, cx, top, W - M - cx, items, gap_)
    footer(s, next(N)); notes(s, note)
    return s

# ================================================================== 1 الغلاف
s = new(True)
pic(s, "logo.png", W - M - 1.5, 0.8, 1.5, 1.5)
text(s, M, 2.4, W - 2 * M, 1.2, "رادار التقنية", 60, WHITE, True)
text(s, M, 3.6, W - 2 * M, 1.2, "منصة عربية لاستخبارات التهديدات التقنية: الثغرات، والتحديثات الأمنية، وأخبار التقنية، مرتبة حسب خطرها الحقيقي", 22, BRASS)
text(s, M, 5.2, W - 2 * M, 1.2, [
    [("عبدالله طلال القحطاني", {"bold": True, "color": WHITE}), ("   445223022", {"color": "A3AFC6", "size": 16})],
    [("عبدالله يعقوب الخليفة", {"bold": True, "color": WHITE}), ("   445213146", {"color": "A3AFC6", "size": 16})]], 20, WHITE)
text(s, M, 6.65, 6, 0.4, "nfalqhtan-hue.github.io/radar", 14, "A3AFC6", align="l")
next(N)
notes(s, "المتحدث: عبدالله القحطاني (دقيقة)\n"
         "السلام عليكم. نحن عبدالله القحطاني وعبدالله الخليفة، ومشروعنا «رادار التقنية»: منصة عربية تعمل وحدها كل ساعة، "
         "تتابع الثغرات الأمنية والتحديثات الرسمية وأخبار التقنية، وتجيب عن سؤال واحد: ما الذي يحتاج تصرفاً الآن؟\n"
         "الموقع يعمل الآن على الرابط الظاهر، وسنأخذكم في جولة على صفحاته الثماني.")

# ================================================================== 2 المشكلة
s = new(); title(s, "المشكلة: أكثر من أن يُتابع يدوياً")
stats = [("47,658", "ثغرة نشرتها NVD في آخر 90 يوماً", "أي أكثر من 500 ثغرة كل يوم"),
         ("بالإنجليزية", "أغلب المصادر الرسمية بغير لغة المستخدم", "NVD وCISA ونشرات الشركات والأخبار"),
         ("بلا أولوية", "لا شيء يقول أي ثغرة تُصلَح أولاً", "والمستغلة فعلاً في قائمة منفصلة عند CISA")]
cw = (W - 2 * M - 2 * 0.4) / 3
for i, (big, lab, sub) in enumerate(stats):
    x = W - M - (i + 1) * cw - i * 0.4
    box(s, x, 2.0, cw, 3.2, PAPER, 0.06)
    text(s, x + 0.3, 2.35, cw - 0.6, 1.1, big, 46 if i == 0 else 36, RED if i == 0 else NAVY, True)
    text(s, x + 0.3, 3.55, cw - 0.6, 1.0, lab, 18, INK, True)
    text(s, x + 0.3, 4.55, cw - 0.6, 0.5, sub, 13, MUTED)
text(s, M, 5.75, W - 2 * M, 0.8, "والنتيجة: قد يفوت المستخدم تحديثاً أمنياً مهماً، أو يضيع وقته في ثغرات لا تهدده.", 18, NAVY, True)
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة ونصف)\n"
         "الرقم 47,658 ليس تقديراً: هذا عدد الثغرات التي نشرتها قاعدة NVD الأمريكية في آخر 90 يوماً، وحمّلها الرادار نفسه للاتجاهات.\n"
         "المشكلة ثلاثية: الكمية كبيرة، والمصادر بالإنجليزية، ولا شيء يقول لك من أين تبدأ.")

# ================================================================== 3 الفكرة: ثلاث ركائز
s = new(); title(s, "الفكرة: منصة واحدة لثلاث ركائز")
pillars = [("الثغرات الأمنية", "من NVD وقائمة CISA للثغرات المستغلة، مع درجة خطر لكل ثغرة", RED),
           ("التحديثات الأمنية", "من النشرات الرسمية: Chrome وUbuntu وDebian وCisco وFortinet وOracle", GOLD_D),
           ("أخبار التقنية", "أخبار أمنية وتقنية عامة وذكاء اصطناعي من خمسة مصادر", NAVY)]
for i, (t, d, c) in enumerate(pillars):
    x = W - M - (i + 1) * cw - i * 0.4
    box(s, x, 1.75, cw, 3.0, PAPER, 0.06)
    circle(s, x + cw - 1.1, 2.0, 0.8, c, str(i + 1), 22, WHITE)
    text(s, x + 0.3, 2.95, cw - 0.6, 0.6, t, 24, NAVY, True)
    text(s, x + 0.3, 3.55, cw - 0.6, 1.1, d, 15, MUTED)
box(s, M, 5.1, W - 2 * M, 1.5, NAVY, 0.1)
text(s, M + 0.3, 5.15, W - 2 * M - 0.6, 1.4, [
    [("السؤال الذي تجيب عنه: ", {"bold": True, "color": BRASS}), ("ما الذي يحتاج تصرفاً الآن؟", {"color": WHITE, "bold": True})],
    [("نفصل خطورة الثغرة (CVSS) عن ثبوت استغلالها (CISA)، ثم نجمعهما في درجة خطر شفافة المعادلة.", {"color": "C9D2E3", "size": 16})]], 20, WHITE, anchor="m")
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة)\n"
         "المنصة تغطي ثلاث ركائز منفصلة في الموقع: الثغرات، والتحديثات الرسمية، والأخبار.\n"
         "وأهم فكرة في المربع الأزرق: ثغرة درجتها 9.8 قد لا يكون أحد استغلها، وثغرة درجتها 6.5 قد تكون مستغلة الآن. "
         "لذلك نعرض الأمرين منفصلين، ثم نجمعهما في درجة خطر نشرح معادلتها بعد قليل.")

# ================================================================== 4 كيف يعمل
s = new(); title(s, "كيف يعمل: دورة كل ساعة على جهازنا", "مُجدول مهام ويندوز يبدأ الدورة، ويجلب منذ آخر جلب ناجح فلا يضيع شيء وقت إطفاء الجهاز")
iw, ih = size_of("v2/flow_v2.png"); fw = W - 2 * M; fh = fw * ih / iw
box(s, M - 0.05, 1.85, fw + 0.1, fh + 0.1, LINE, 0.02)
s.shapes.add_picture(A("v2/flow_v2.png"), Inches(M), Inches(1.9), Inches(fw), Inches(fh))
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقتان)\n"
         "على اليمين المصادر: NVD وCISA وخمس خلاصات أخبار، والجديد ست نشرات رسمية للشركات.\n"
         "في الوسط الوكيل: يجلب، ثم يصنف، ثم يلخص بنموذج Qwen3 على جهازنا، ثم يتحقق ويرفض أي ملخص فيه ادعاء ليس في المصدر. "
         "والجديد خطوتان: درجة الخطر، والتحليل (الاتجاهات والتقرير اليومي والخريطة).\n"
         "وعلى اليسار المخرجات: الموقع، وملفات البيانات، وتنبيه تيليجرام، والتقرير اليومي. وكل ما عليه إطار ذهبي أضفناه في الترقية.")

# ================================================================== 5 الأدوات والتكلفة
s = new(); title(s, "الأدوات: مجانية ومفتوحة المصدر")
tools = [("Python", "الوكيل كاملاً، بالمكتبة القياسية فقط"), ("Ollama + Qwen3 8B", "التلخيص محلياً، بلا مفتاح API"),
         ("SQLite", "العناصر والأحداث وتاريخ 90 يوماً والتقارير"), ("مُجدول مهام ويندوز", "التشغيل كل ساعة"),
         ("GitHub Pages", "استضافة مجانية ونشر تلقائي"), ("HTML وJavaScript وSVG", "8 صفحات ورسوم وخريطة، بلا أي مكتبة")]
gw = (W - 2 * M - 3.6 - 0.5 - 0.3) / 2
for i, (t, d) in enumerate(tools):
    col, row = i % 2, i // 2
    x = W - M - (col + 1) * gw - col * 0.3; y = 1.75 + row * 1.5
    box(s, x, y, gw, 1.25, PAPER, 0.08)
    text(s, x + 0.25, y + 0.15, gw - 0.5, 0.5, t, 19, NAVY, True)
    text(s, x + 0.25, y + 0.65, gw - 0.5, 0.5, d, 14, MUTED)
box(s, M, 1.75, 3.6, 4.25, NAVY, 0.06)
text(s, M + 0.2, 2.2, 3.2, 1.3, "0", 96, BRASS, True, align="c")
text(s, M + 0.2, 3.65, 3.2, 0.6, "ريال", 26, WHITE, True, align="c")
text(s, M + 0.3, 4.4, 3.0, 1.3, "التكلفة الكلية للبناء والتشغيل، دون أي اشتراك", 15, "C9D2E3", align="c")
text(s, M, 6.25, W - 2 * M, 0.5, "والترقية لم تُضف أي حزمة برمجية جديدة، ولا أي اتصال بجهة خارجية من الموقع.", 15, NAVY, True)
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة)\n"
         "كل الأدوات مجانية، والتكلفة صفر. والترقية كلها بُنيت بالأدوات نفسها: لا مكتبات جديدة في بايثون، والرسوم البيانية والخريطة مرسومة بـ SVG داخل الموقع.\n"
         "تغيّر عن الخطة: n8n استبدلناه بمُجدول مهام ويندوز لأنه يحتاج Node.js.")

# ================================================================== 6 مبادئ سلامة البيانات
s = new(); title(s, "مبادئ سلامة البيانات", "منصة أمنية تفقد قيمتها إذا اخترعت رقماً أو موقعاً أو ثغرة")
pr = [("لا بيانات مخترعة", "كل رقم محسوب من سجلات حقيقية، وكل عنصر يرتبط بمصدره"),
      ("الخطورة غير الاستغلال", "لا نعتبر ثغرة مستغلة إلا إذا أدرجتها CISA"),
      ("نقص المعلومة ليس حكماً", "العامل غير المعروف يُستبعد، لا يُحسب صفراً"),
      ("لا موقع إلا بنص صريح", "لا نستنتج الدولة من IP ولا من مقر الشركة"),
      ("الحقائق قبل النموذج", "التقرير والاتجاهات مبنية بقواعد، لا يكتبها نموذج"),
      ("الإفصاح عن النقص", "الأيام غير المرصودة «لم تُرصد»، والفشل يظهر برسالته")]
pw3 = (W - 2 * M - 2 * 0.3) / 3
for i, (t, d) in enumerate(pr):
    col, row = i % 3, i // 3
    x = W - M - (col + 1) * pw3 - col * 0.3; y = 2.0 + row * 2.2
    box(s, x, y, pw3, 1.95, PAPER, 0.06)
    circle(s, x + pw3 - 0.8, y + 0.25, 0.55, NAVY, "✓", 16, BRASS)
    text(s, x + 0.25, y + 0.25, pw3 - 1.2, 0.6, t, 19, NAVY, True)
    text(s, x + 0.25, y + 0.95, pw3 - 0.5, 0.9, d, 14.5, MUTED)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقة ونصف)\n"
         "قبل الجولة في الموقع: هذه المبادئ الست بنينا عليها كل ميزة جديدة، ولكل مبدأ اختبار آلي يمنع كسره.\n"
         "مثال: الخريطة كان سهلاً أن نملأها بالنقاط لو استنتجنا الدولة من مقر الشركة، لكننا رفضنا. ومثال آخر: لو قال وصف الثغرة «exploited in the wild» لا نعتبرها مستغلة حتى تدرجها CISA.")

# ================================================================== 7 فاصل: جولة في الموقع
s = new(True)
text(s, M, 1.3, W - 2 * M, 1.0, "جولة في الموقع", 44, WHITE, True)
text(s, M, 2.3, W - 2 * M, 0.6, "ثماني صفحات بالعربية والإنجليزية، بالوضعين الفاتح والداكن، وعلى الجوال", 20, BRASS)
pages = ["الرئيسية", "التنبيهات", "التحديثات", "الإحصائيات", "الاتجاهات", "التقرير اليومي", "الخريطة", "عن المشروع"]
pw4 = (W - 2 * M - 3 * 0.3) / 4
for i, p_ in enumerate(pages):
    col, row = i % 4, i // 4
    x = W - M - (col + 1) * pw4 - col * 0.3; y = 3.4 + row * 1.35
    new_ = i in (2, 4, 5, 6)
    box(s, x, y, pw4, 1.05, "1C2D4E", 0.1, line=BRASS if new_ else None)
    text(s, x + 0.2, y + 0.1, pw4 - 0.4, 0.85, [[(p_, {"bold": True, "color": WHITE})] + ([("   جديدة", {"color": BRASS, "size": 13})] if new_ else [])], 20, WHITE, anchor="m")
text(s, M, 6.45, W - 2 * M, 0.5, "الصفحات بإطار ذهبي أضفناها في الترقية", 14, "A3AFC6")
next(N)
notes(s, "المتحدث: عبدالله الخليفة\n"
         "الآن الجولة في الموقع. إذا كان الإنترنت متاحاً فالأفضل فتح الموقع مباشرة، وهذه الشرائح نسخة احتياطية منه.\n"
         "أربع صفحات جديدة: التحديثات، والاتجاهات، والتقرير اليومي، والخريطة. وبقية الصفحات طُوّرت بإضافة درجة الخطر.")

# ================================================================== 8-17 صفحات الموقع
page_slide("الرئيسية: ما يحتاج انتباهك الآن", None, S + "home.png", [
    ("رادار حي", "كل نقطة ثغرة أو خبر من آخر 24 ساعة: البعد عمرها، واللون خطورتها."),
    ("الأخطر أولاً", "المستغلة فعلاً، ثم الأعلى درجة."),
    ("بحث وفلاتر", "النوع والتاريخ والخطورة ودرجة الخطر، وترتيب «الأعلى خطراً»، وكل نتيجة لها رابط يُشارَك.")],
    "المتحدث: عبدالله الخليفة (دقيقة ونصف)\n"
    "الصفحة الرئيسية. الرادار يعرض كل ما وصل في آخر 24 ساعة، والقائمة بجانبه أخطر أربع ثغرات.\n"
    "تحت الرادار كل ما رصدناه من ثغرات وتحديثات وأخبار، مع بحث وفلاتر. والجديد: شارة «خطر» بجانب كل ثغرة، وترتيب «الأعلى خطراً».")

s = new(); title(s, "تفاصيل الثغرة: لماذا هي خطيرة؟")
w_, h_ = shot(s, S + "detail.png", M + 0.05, 1.5, h=5.3)
cx = M + w_ + 0.5
points(s, cx, 1.5, W - M - cx, [
    ("درجة الخطر 99 من 100", "ثغرة درجتها 9.8، ومدرجة في قائمة CISA للثغرات المستغلة."),
    ("مصدر كل نقطة", "جدول يبيّن قيمة كل عامل ووزنه وكم نقطة أضاف."),
    ("الإجراء المقترح", "بقواعد ثابتة: طبّق ما تطلبه CISA قبل موعده."),
    ("روابط رسمية", "نشرة الشركة ورابط الإصلاح من NVD، والوصف الأصلي.")], 1.3)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقة ونصف)\n"
         "الضغط على أي ثغرة يفتح هذه النافذة. الدرجة 9.8 من CVSS، ودرجة الخطر 99 لأنها مستغلة فعلاً حسب CISA.\n"
         "الجدول يشرح الحساب: CVSS أضافت 36 نقطة، والاستغلال 53، والعمر 10.5. والإصلاح غير معروف فلا يُحسب ضدها ولا لها.\n"
         "والإجراء المقترح ليس من نموذج لغوي، بل قاعدة: المستغلة تأخذ إجراء CISA وموعده.")

# ================================================================== محرك الخطورة
s = new(); title(s, "محرك تقييم الخطورة", "درجة من 0 إلى 100 لأولوية التصرف، معادلتها منشورة ويمكن إعادة حسابها يدوياً")
ws = [("الاستغلال", 50, "1 في قائمة CISA، 0.7 إن كان الاستغلال منشوراً"), ("درجة CVSS", 35, "الدرجة الرسمية من NVD مقسومة على 10"),
      ("العمر ونطاق التعرض", 10, "الحداثة، والهجوم عن بُعد بلا صلاحيات"), ("الإصلاح الرسمي", 5, "وجود رابط إصلاح يخفض الأولوية")]
lx = W / 2 + 0.2; lw = W - M - lx
for i, (t, wv, d) in enumerate(ws):
    y = 1.95 + i * 1.12
    text(s, lx, y, lw, 0.45, [[(t, {"bold": True, "color": NAVY}), (f"   {wv}%", {"bold": True, "color": GOLD_D})]], 18, NAVY)
    box(s, lx + lw * (1 - wv / 50), y + 0.48, lw * wv / 50, 0.16, BRASS, 0.5)
    text(s, lx, y + 0.66, lw, 0.4, d, 13, MUTED)
cd = CategoryChartData(); cd.categories = ["خطر حرج", "خطر عالٍ", "خطر متوسط"]
cd.add_series("بأوزان الخطة الأولى", (15, 4, 538)); cd.add_series("بالأوزان المعتمدة", (15, 27, 190))
gf = s.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, Inches(M), Inches(1.95), Inches(W / 2 - M - 0.3), Inches(3.6), cd)
ch = gf.chart; ch.has_legend = True; ch.legend.position = XL_LEGEND_POSITION.BOTTOM; ch.legend.include_in_layout = False
ch.legend.font.size = Pt(12); ch.legend.font.name = FONT
ca = ch.category_axis; ca.tick_labels.font.size = Pt(13); ca.tick_labels.font.name = FONT; ca.reverse_order = True
va = ch.value_axis; va.visible = False; va.has_major_gridlines = False
plot = ch.plots[0]; plot.gap_width = 60; plot.has_data_labels = True
plot.data_labels.font.size = Pt(12); plot.data_labels.font.bold = True; plot.data_labels.position = XL_LABEL_POSITION.OUTSIDE_END
for ser, c in zip(plot.series, ("A3AFC6", NAVY)):
    ser.format.fill.solid(); ser.format.fill.fore_color.rgb = rgb(c)
box(s, M, 5.75, W - 2 * M, 0.85, PAPER, 0.08)
text(s, M + 0.3, 5.78, W - 2 * M - 0.6, 0.8, [[("تحققنا من الأوزان على 1,190 ثغرة: ", {"bold": True, "color": NAVY}),
     ("بأوزان الخطة الأولى لم تصل لـ«عالٍ» إلا الثغرات المدرجة في CISA، فدمجنا الاستغلال المؤكد والمنشور في عامل واحد.", {})]], 15, INK, anchor="m")
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقتان)\n"
         "على اليمين المعادلة: الاستغلال نصف الدرجة، ثم CVSS، ثم العمر ونطاق التعرض، ثم الإصلاح. والعامل غير المعروف يُستبعد من الحساب بدل أن يُعتبر صفراً.\n"
         "على اليسار قصة التحقق: طبقنا أوزان الخطة كما هي على بياناتنا، فاكتشفنا أن ثغرة 9.8 لها استغلال منشور تبقى «متوسطة». "
         "فعدّلنا الأوزان، فصارت الثغرات العالية 27 بدل 4، وانخفضت المتوسطة من 538 إلى 190.\n"
         "النتيجة: 42 ثغرة تحتاج تصرفاً عاجلاً من 1,204، بدل 73 «حرجة» حسب CVSS وحده، أغلبها غير مستغل.")

page_slide("مركز التنبيهات", None, S + "alerts.png", [
    ("خمسة تبويبات", "الكل، وخطر حرج أو عالٍ، وثبت استغلالها، وحرجة، وعالية."),
    ("أعمدة منفصلة", "الخطورة، ودرجة الخطر، والاستغلال: كل واحد في عموده."),
    ("سجل تيليجرام", "الرسائل التي أُرسلت فعلاً، بحد خمس رسائل ورسالة جامعة لكل دورة.")],
    "المتحدث: عبدالله الخليفة (دقيقة)\n"
    "مركز التنبيهات يجمع ما يحتاج تصرفاً، مرتباً هنا حسب درجة الخطر. والتبويب الجديد «خطر حرج أو عالٍ» فيه 26 ثغرة، مقابل 127 في «الكل».")

page_slide("التحديثات الأمنية: الركيزة الثالثة", None, S + "updates.png", [
    ("ست جهات رسمية", "126 تحديثاً ونشرة من آخر 30 يوماً."),
    ("ثلاثة أنواع", "تحديث أمني 49، ونشرة أمنية 69، وتحديث عام بلا إصلاحات 8."),
    ("تحتاج تصرفاً الآن", "9 تحديثات تصلح ثغرة في قائمة CISA أو ذكرت الشركة أنها مستغلة."),
    ("بلا تخمين", "الإصدار المصحح والمتأثر يظهر فقط إذا ذكرته الشركة.")], "المتحدث: عبدالله الخليفة (دقيقة ونصف)\n"
    "صفحة جديدة للتحديثات الرسمية: من Chrome وUbuntu وDebian وCisco وFortinet وOracle. والملخص هنا مبني من بيانات النشرة نفسها، لا من النموذج.\n"
    "وإذا لم تذكر الشركة رقم الإصدار نكتب «راجع النشرة» ولا نخمّن. ولم نضف Microsoft وApple لأنها لا توفر خلاصة يقرؤها برنامج، وثغراتها تصلنا من NVD.", 1.3)

page_slide("الإحصائيات", None, S + "dashboard.png", [
    ("من القاعدة كاملة", "1,204 ثغرة، و19 مستغلة، وتوزيعها بالساعة واليوم."),
    ("مقياسان جنباً إلى جنب", "الخطورة حسب CVSS، ودرجة الخطر حسب الأولوية."),
    ("لكل ركيزة", "المنتجات والأخبار ومصدر الملخصات والتحديثات حسب الشركة.")],
    "المتحدث: عبدالله الخليفة (دقيقة)\n"
    "الإحصائيات محسوبة من قاعدة البيانات كاملة. والمقارنة المهمة هنا: 73 ثغرة حرجة حسب CVSS، لكن 15 فقط خطرها حرج.")

s = new(); title(s, "الاتجاهات: ماذا تغيّر عبر الزمن؟", "تحليل تاريخي لما حدث، وليس توقعاً")
w1, h1 = shot(s, S + "trends_top.png", W - M - 5.85, 1.85, w=5.8)
w2, h2 = shot(s, S + "trends_charts.png", M + 0.05, 1.85, w=5.8)
text(s, M, 1.85 + max(h1, h2) + 0.25, W - 2 * M, 1.0, [
    [("90 يوماً من NVD: ", {"bold": True, "color": NAVY}), ("47,658 ثغرة حمّلناها مرة واحدة (التاريخ والدرجة ونوع الضعف فقط). ", {}),
     ("كل مؤشر يُقارن بالفترة المساوية قبله، ", {}), ("والأيام قبل بدء الرصد تظهر «لم يُرصد» لا صفراً.", {"bold": True, "color": NAVY})]], 15, INK)
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة ونصف)\n"
         "صفحة الاتجاهات: تختار فترة، وكل مؤشر يُقارن بالفترة التي قبلها. مثلاً في آخر 30 يوماً: الثغرات الحرجة 1,408، بانخفاض 11%، وأضافت CISA 45 ثغرة مقابل 32.\n"
         "وجمل «ماذا تقول الأرقام» محسوبة بقواعد. ونقولها بوضوح: هذا تاريخ لا تنبؤ.")

page_slide("التقرير الأمني اليومي", None, S + "report.png", [
    ("يُبنى تلقائياً", "بعد منتصف الليل لليوم السابق، ويعوّض الأيام الفائتة."),
    ("سبعة أقسام", "ملخص، وأخطر 5 ثغرات، وCISA، والتحديثات، والأخبار، والتوصيات، وجمع البيانات."),
    ("صادق عن نفسه", "يذكر ساعات عمل الرادار في ذلك اليوم، وفشل أي مصدر."),
    ("أرشيف وPDF", "90 يوماً من التقارير، وتصدير للطباعة.")],
    "المتحدث: عبدالله الخليفة (دقيقة ونصف)\n"
    "تقرير يوم 26 نوفمبر: 589 ثغرة، 33 حرجة، 14 خطرها عالٍ أو حرج. ولاحظوا الجملة الأخيرة في الملخص: الرادار كان يعمل من 3:44 إلى 6:05 فقط ذلك اليوم، والتقرير يقولها بنفسه.\n"
    "والتوصيات قواعد مرتبطة بسجلات التقرير، مثل: تحقق إن كنت تستخدم D-Link R32 لأن تفاصيل استغلال ثغرتها منشورة.", 1.3)

page_slide("خريطة التهديدات", None, S + "map.png", [
    ("بنص صريح فقط", "«China-linked hackers» أو «breached a Russian organization»."),
    ("نوعان منفصلان", "منسوبة إليها حسب المصدر، أو مكان الجهة المستهدفة."),
    ("الدليل مقتبس", "تحت كل حادثة الجملة التي حددت الموقع."),
    ("9 بموقع، و83 بلا موقع", "قليلة النقاط، لكنها صادقة.")],
    "المتحدث: عبدالله القحطاني (دقيقة ونصف)\n"
    "أصعب ميزة من ناحية الأمانة. كان سهلاً أن نضع كل خبر عن شركة صينية على الصين، لكن هذا استنتاج قد يكون خاطئاً.\n"
    "مثال حقيقي واجهناه: خبر عن «the Chinese telecom giant accused of stealing»؛ القاعدة الأولى وضعت الصين «ضحية» وهي المتهمة. أصلحناه وصار له اختبار يمنع عودته.", 1.3)

s = new(); title(s, "الجوال واللغة الإنجليزية")
x0 = W - M
for img in ("m_updates.png", "m_map.png", "m_report.png"):
    w_, h_ = shot(s, "v2/dark/" + img, x0 - 2.45, 1.5, h=5.3); x0 -= w_ + 0.3
iw, ih = size_of("v2/dark/trends_en.png"); tw_ = x0 - M - 0.15
shot(s, "v2/dark/trends_en.png", M + 0.05, 1.5, w=tw_)
text(s, M, 1.5 + tw_ * ih / iw + 0.3, tw_, 1.5, ["على الجوال تنطوي الفلاتر، وتتحول الجداول إلى بطاقات، ولا تمرير أفقي في أي صفحة.",
                                                  "وبالإنجليزية يتغير اتجاه الصفحة كاملة."], 15, MUTED)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقة)\n"
         "الصفحات الثماني تعمل على الجوال، واختبرناها على عرض 375 بكسل. والموقع كامل بالإنجليزية.")

# ================================================================== الاختبار
s = new(); title(s, "الاختبار: أربع جولات حية واختبار نهائي", "كل جولة 20 عنصراً روجعت يدوياً مقابل المصدر، وكل ثغرة طوبقت مع NVD")
cd = CategoryChartData(); cd.categories = ["الجولة الأولى", "الجولة الثانية", "الجولة الثالثة", "الجولة الرابعة"]
cd.add_series("دقة التصنيف", (95, 100, 90, 95)); cd.add_series("دقة الخطورة", (88, 100, 100, 100)); cd.add_series("الملخصات السليمة", (30, 75, 79, 65))
gf = s.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(M), Inches(1.85), Inches(8.0), Inches(4.85), cd)
ch = gf.chart; ch.has_legend = True; ch.legend.position = XL_LEGEND_POSITION.BOTTOM; ch.legend.include_in_layout = False
ch.legend.font.size = Pt(13); ch.legend.font.name = FONT
ca = ch.category_axis; ca.reverse_order = True; ca.tick_labels.font.size = Pt(13); ca.tick_labels.font.name = FONT; ca.has_major_gridlines = False
ca.format.line.color.rgb = rgb(MUTED)
va = ch.value_axis; va.maximum_scale = 100; va.minimum_scale = 0; va.has_major_gridlines = True
va.major_gridlines.format.line.color.rgb = rgb(LINE); va.tick_labels.font.size = Pt(11); va.tick_labels.font.color.rgb = rgb(MUTED)
va.format.line.fill.background()
plot = ch.plots[0]; plot.gap_width = 70; plot.overlap = -8; plot.has_data_labels = True
dl = plot.data_labels; dl.number_format = '0"%"'; dl.number_format_is_linked = False; dl.position = XL_LABEL_POSITION.OUTSIDE_END
dl.font.size = Pt(12); dl.font.bold = True; dl.font.color.rgb = rgb(INK)
for ser, c in zip(plot.series, (NAVY, BRASS, TEAL)):
    ser.format.fill.solid(); ser.format.fill.fore_color.rgb = rgb(c)
rx = M + 8.3; rw = W - M - rx
for i, (big, lab) in enumerate((("122", "اختباراً آلياً ناجحاً (كانت 77 قبل الترقية)"),
                                ("8 من 8", "صفحات تعمل بلا أي خطأ، والمنشور يطابق الكود"),
                                ("0", "أسرار في الكود، وسياسة أمان في كل صفحة"))):
    y = 1.9 + i * 1.6
    box(s, rx, y, rw, 1.4, PAPER, 0.08)
    text(s, rx + 0.2, y + 0.08, rw - 0.4, 0.6, big, 26, NAVY, True)
    text(s, rx + 0.2, y + 0.68, rw - 0.4, 0.7, lab, 12.5, MUTED)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقتان)\n"
         "التصنيف والخطورة فوق هدف 90% في كل الجولات بعد الإصلاح. والملخصات نقطة الضعف: من 30% مع النموذج القديم إلى 79%.\n"
         "وعلى اليمين الاختبار النهائي بعد الترقية: 122 اختباراً آلياً، وفحص الموقع المنشور صفحة صفحة، وفحص الأمان.")

# ================================================================== ما كشفه الاختبار
s = new(); title(s, "ما كشفه الاختبار، وكيف أصلحناه")
cards = [("372", "ثغرة استعدناها", "كانت تضيع وقت إطفاء الجهاز لأن الجلب كان من آخر ساعتين فقط"),
         ("9 من 19", "مستغلة فقط حرجة فعلاً", "كان الموقع يعرض كل ثغرة مستغلة «حرجة»، ففصلنا الخطورة عن الاستغلال"),
         ("27 بدل 4", "ثغرة خطرها عالٍ", "أوزان الخطة حصرت «عالٍ» في قائمة CISA، فدمجنا الاستغلال في عامل واحد"),
         ("0", "مواقع مستنتجة", "قاعدة وضعت الصين «ضحية» في خبر هي المتهمة فيه، فصار للضحية شرط فعل هجوم")]
cw4 = (W - 2 * M - 3 * 0.3) / 4
for i, (big, lab, d) in enumerate(cards):
    x = W - M - (i + 1) * cw4 - i * 0.3
    box(s, x, 1.75, cw4, 4.6, PAPER, 0.06)
    text(s, x + 0.25, 2.05, cw4 - 0.5, 1.0, big, 34, RED if i == 0 else NAVY, True)
    text(s, x + 0.25, 3.1, cw4 - 0.5, 0.6, lab, 18, INK, True)
    text(s, x + 0.25, 3.8, cw4 - 0.5, 2.3, d, 14, MUTED)
text(s, M, 6.55, W - 2 * M, 0.45, "كل خطأ صار اختباراً آلياً يمنع عودته.", 16, NAVY, True)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقتان)\n"
         "أربعة أمثلة على أن الاختبار يكشف ما لا تكشفه قراءة الكود: 372 ثغرة كانت تضيع، وخلط الخطورة بالاستغلال، "
         "وأوزان لم تصمد أمام البيانات الحقيقية، وقاعدة جغرافية عكست المتهم والضحية. وكلها صارت اختبارات آلية.")

# ================================================================== الأمان
s = new(); title(s, "الأمان والخصوصية")
items = [("لا أسرار في الكود", "توكن تيليجرام في متغيرات الجهاز فقط، وفحصنا كل ملف في المستودع"),
         ("البيانات لا تغادر الجهاز", "النموذج اللغوي محلي، والموقع لا يتصل بأي جهة خارجية، حتى الخريطة ملف داخله"),
         ("لا تنفيذ لمحتوى خارجي", "كل نص من المصادر يُعرض نصاً عادياً، وسياسة CSP تمنع أي سكربت غريب"),
         ("مراجعة أمنية يومية", "كل يوم 9 صباحاً: تقارن الموقع المنشور بالكود، وتفحص الأسرار وسجل النشر"),
         ("حقوق النشر", "ملخص قصير مع رابط المصدر، دون نسخ المقالات")]
for i, (t, d) in enumerate(items):
    y = 1.65 + i * 1.0
    circle(s, W - M - 0.7, y + 0.08, 0.6, NAVY, "✓", 18, BRASS)
    text(s, M, y, W - 2 * M - 1.0, 0.45, t, 19, NAVY, True)
    text(s, M, y + 0.45, W - 2 * M - 1.0, 0.45, d, 14, MUTED)
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة)\n"
         "الأخبار نص خارجي غير موثوق، فلا تُنفَّذ كـ HTML. والموقع لا يحمّل إلا سكربتاته. وأضفنا مراجعة أمنية آلية كل صباح للقراءة فقط.")

# ================================================================== القيود والتطوير
s = new(); title(s, "قيود نعرفها، وتطوير نقترحه")
half = (W - 2 * M - 0.5) / 2
box(s, W - M - half, 1.65, half, 4.75, PAPER, 0.05)
text(s, W - M - half + 0.3, 1.85, half - 0.6, 0.55, "قيود معروفة", 22, RED, True)
text(s, W - M - half + 0.3, 2.5, half - 0.6, 3.8, [
    [("الملخصات: ", {"bold": True, "color": NAVY}), ("نموذج صغير قد يخطئ، فكل ملخص معلَّم ومعه المصدر", {})],
    [("لا خادم: ", {"bold": True, "color": NAVY}), ("لا تحديث ولا تقرير يومي والجهاز مطفأ", {})],
    [("الخريطة: ", {"bold": True, "color": NAVY}), ("أغلب الأخبار لا تذكر دولة صراحة", {})],
    [("مساعد ذكي: ", {"bold": True, "color": NAVY}), ("يحتاج خادماً، فبنيناه ثم أزلناه", {})]], 15, INK, spacing=1.3)
box(s, M, 1.65, half, 4.75, PAPER, 0.05)
text(s, M + 0.3, 1.85, half - 0.6, 0.55, "تطوير مقترح", 22, TEAL, True)
text(s, M + 0.3, 2.5, half - 0.6, 3.8, [
    [("خادم دائم ", {"bold": True, "color": NAVY}), ("فيكتمل التقرير اليومي كل يوم", {})],
    [("نموذج أكبر ", {"bold": True, "color": NAVY}), ("أو جهاز بكرت شاشة للملخصات", {})],
    [("إرسال التقرير اليومي ", {"bold": True, "color": NAVY}), ("على تيليجرام أو البريد", {})],
    [("استفادة تجارية: ", {"bold": True, "color": NAVY}), ("اشتراك في التقرير اليومي للشركات الصغيرة", {})]], 15, INK, spacing=1.3)
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة ونصف)\n"
         "نذكر القيود بصراحة. وعن المساعد الذكي: بنيناه فعلاً، يجيب من بيانات الموقع فقط، ثم قررنا إزالته لأنه لا يضيف على البحث والصفحات الموجودة. "
         "والمساعد الحقيقي يحتاج خادماً يشغّل نموذجاً أو يحمي مفتاحاً، وهذا خارج الاستضافة المجانية.")

# ================================================================== الخاتمة
s = new(True)
text(s, M, 1.2, W - 2 * M, 1.0, "الخلاصة", 40, WHITE, True)
text(s, M, 2.3, W - 2 * M, 2.4, [
    "منصة تعمل وحدها كل ساعة، وتغطي الثغرات والتحديثات الرسمية والأخبار، بتكلفة صفر.",
    "درجة خطر شفافة تجيب: ما الذي يحتاج تصرفاً الآن؟",
    "والدقة قبل الكثرة: «بيانات غير كافية» أصدق من رقم مخترع."], 22, "E6EAF2", spacing=1.4)
box(s, M, 5.05, W - 2 * M, 1.1, "1C2D4E", 0.1)
text(s, M + 0.3, 5.1, W - 2 * M - 0.6, 1.0, [[("جرّبوه الآن: ", {"bold": True, "color": BRASS}),
     ("nfalqhtan-hue.github.io/radar", {"color": WHITE, "bold": True})]], 24, WHITE, anchor="m")
text(s, M, 6.45, W - 2 * M, 0.6, "شكراً لكم، ونسعد بأسئلتكم", 20, "A3AFC6")
next(N)
notes(s, "المتحدث: عبدالله الخليفة (دقيقة)\n"
         "الخلاصة في ثلاث جمل. ونترك الرابط ظاهراً لمن يريد التجربة أثناء الأسئلة.\n"
         "الشرائح التالية ملحق للأسئلة المتوقعة، لا تُعرض إلا إذا جاء سؤال يحتاجها.")

# ================================================================== ملحق: أسئلة متوقعة
QA = [
    ("كيف تُحسب درجة الخطر؟", "50% للاستغلال (1 إن كانت في قائمة CISA، و0.7 إن كان منشوراً)، و35% لدرجة CVSS، و10% للعمر ونطاق التعرض، و5% للإصلاح. والعامل غير المعروف يُستبعد من الحساب."),
    ("لماذا غيّرتم أوزان الخطة؟", "لأنها حين طُبقت على 1,190 ثغرة حقيقية لم تُوصل أي ثغرة غير مدرجة في CISA إلى «عالٍ»، حتى لو كان استغلالها منشوراً. فدمجنا الاستغلال في عامل واحد."),
    ("لماذا الخريطة فيها نقاط قليلة؟", "لأننا لا نضع دولة إلا إذا ذكرها الخبر صراحة في جملة عن هجوم. أغلب الأخبار لا تذكر دولة، فتبقى «بلا موقع» بدل أن نخمّن."),
    ("ما الفرق بين الخطورة والاستغلال؟", "الخطورة درجة CVSS: ماذا يحدث لو استُغلت. والاستغلال من قائمة CISA: هل استغلها مهاجمون فعلاً. من 19 ثغرة مستغلة عندنا 9 فقط حرجة."),
    ("كيف تضمنون أن الملخص صحيح؟", "لا نضمنه بالكامل. نرفض آلياً أي ملخص فيه لغة أجنبية أو رقم أو ادعاء غير موجود في المصدر، ونعلّم الباقي «ملخص آلي» بجانب الوصف الأصلي."),
    ("من أين جاء تاريخ 90 يوماً؟", "حمّلنا من NVD مرة واحدة 47,658 ثغرة نُشرت في آخر 90 يوماً، بتاريخها ودرجتها ونوع ضعفها فقط، في جدول مستقل لا يظهر في الخلاصة."),
    ("ماذا يحدث إذا انطفأ الجهاز؟", "الموقع يبقى منشوراً بآخر بيانات ويظهر أنه متأخر. وعند التشغيل يجلب الوكيل ما فاته، ويبني تقارير الأيام الفائتة التي عمل فيها."),
    ("لماذا أزلتم المساعد الذكي؟", "الاستضافة الثابتة لا تشغّل نموذجاً ولا تحمي مفتاحاً، فكان مساعداً يبحث في بيانات الموقع فقط، ولم يضف على البحث والصفحات ما يبرر وجوده."),
    ("لماذا لا توجد نشرات Microsoft وApple؟", "لا توفر خلاصة يقرؤها برنامج بشكل موثوق. وثغراتها تصل عبر NVD، فلا تضيع عن الموقع."),
    ("هل الموقع آمن من محتوى خبيث في الأخبار؟", "نعم. كل نص يُعرض نصاً عادياً لا HTML، والروابط تُقبل بـ http وhttps فقط، وسياسة CSP تمنع أي سكربت غير سكربتات الموقع."),
    ("كيف يمكن تطوير المشروع تجارياً؟", "اشتراك في التقرير الأمني اليومي بالعربية للشركات الصغيرة، وتقارير مخصصة حسب منتجاتها، وواجهة API لدرجات الخطر."),
    ("ما أصعب مشكلة واجهتكم؟", "الملخصات العربية: النموذج الأول خلط الصينية والروسية في 14 من 20 ملخصاً. حللناها بتغيير النموذج وبحارس جودة، فارتفع السليم من 30% إلى 79%."),
]
for part in range(0, len(QA), 4):
    s = new()
    title(s, "ملحق: أسئلة متوقعة" + ("" if part == 0 else " (تابع)"))
    chunk = QA[part:part + 4]
    for i, (q, a) in enumerate(chunk):
        y = 1.55 + i * 1.32
        circle(s, W - M - 0.6, y + 0.05, 0.5, BRASS, str(part + i + 1), 15, NAVY)
        text(s, M, y, W - 2 * M - 0.85, 0.45, q, 17, NAVY, True)
        text(s, M, y + 0.45, W - 2 * M - 0.85, 0.85, a, 13.5, MUTED)
    footer(s, next(N))
    notes(s, "ملحق للأسئلة: لا يُعرض إلا عند الحاجة.\n\n" + "\n\n".join(f"س: {q}\nج: {a}" for q, a in chunk))

out = os.path.join(ROOT, "FINAL_PRESENTATION_v2.pptx")
prs.save(out)
print("saved", out, len(prs.slides), "slides")
