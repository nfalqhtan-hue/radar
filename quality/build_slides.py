# -*- coding: utf-8 -*-
"""يبني العرض التقديمي لمشروع رادار التقنية (PowerPoint، عربي من اليمين لليسار، مع ملاحظات المتحدث).
الاستخدام: python quality/build_slides.py   ← يكتب FINAL_PRESENTATION.pptx في مجلد المشروع
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
            pos = 0
            pieces = []
            for m in LATIN.finditer(seg):
                if m.start() > pos: pieces.append((seg[pos:m.start()], "ar-SA"))
                pieces.append((m.group(), "en-US")); pos = m.end()
            if pos < len(seg): pieces.append((seg[pos:], "ar-SA"))
            for piece, lang in pieces:
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
    text(slide, M, H - 0.45, 6, 0.3, "رادار التقنية  |  التقرير النهائي للمشروع", 10, c)
    text(slide, W - M - 1, H - 0.45, 1, 0.3, str(n), 10, c, align="l")

def notes(slide, s):
    slide.notes_slide.notes_text_frame.text = s

def new(dark=False):
    s = prs.slides.add_slide(BLANK); bg(s, INK if dark else WHITE); return s

N = iter(range(1, 99))

# ================================================================== 1 الغلاف
s = new(True)
pic(s, "logo.png", W - M - 1.5, 0.9, 1.5, 1.5)
text(s, M, 2.55, W - 2 * M, 1.2, "رادار التقنية", 60, WHITE, True)
text(s, M, 3.75, W - 2 * M, 1.0, "وكيل ذكاء اصطناعي يرصد الثغرات الأمنية وأخبار التقنية، ويلخصها بالعربية، وينبه بالخطير منها", 22, BRASS)
text(s, M, 5.25, W - 2 * M, 1.2, [
    [("عبدالله طلال القحطاني", {"bold": True, "color": WHITE}), ("   445223022", {"color": "A3AFC6", "size": 16})],
    [("عبدالله يعقوب الخليفة", {"bold": True, "color": WHITE}), ("   445213146", {"color": "A3AFC6", "size": 16})]], 20, WHITE)
text(s, M, 6.65, 6, 0.4, "nfalqhtan-hue.github.io/radar", 14, "A3AFC6", align="l")
next(N)
notes(s, "المتحدث: عبدالله القحطاني (دقيقة واحدة)\n"
         "السلام عليكم. نحن عبدالله القحطاني وعبدالله الخليفة، ومشروعنا «رادار التقنية»: وكيل ذكاء اصطناعي يعمل كل ساعة دون تدخل، "
         "يجمع الثغرات الأمنية وأخبار التقنية من مصادرها الرسمية، ويلخصها بالعربية، وينبهنا بالخطير منها.\n"
         "الموقع يعمل الآن على الرابط الظاهر، وسنعرضه مباشرة بعد قليل.")

# ================================================================== 2 المشكلة
s = new(); title(s, "المشكلة: الثغرات أكثر من أن تُتابع يدوياً")
stats = [("552", "ثغرة نُشرت في NVD خلال 24 ساعة فقط", "من بيانات الرادار نفسه"),
         ("بالإنجليزية", "أغلب المصادر الرسمية بلغة غير لغة المستخدم", "NVD وCISA ومواقع الأخبار"),
         ("بلا أولوية", "قاعدة NVD لا تقول أي ثغرة تُصلَح أولاً", "والمستغلة فعلاً في قائمة منفصلة")]
cw = (W - 2 * M - 2 * 0.4) / 3
for i, (big, lab, sub) in enumerate(stats):
    x = W - M - (i + 1) * cw - i * 0.4
    box(s, x, 2.0, cw, 3.2, PAPER, 0.06)
    text(s, x + 0.3, 2.35, cw - 0.6, 1.1, big, 48 if i == 0 else 36, RED if i == 0 else NAVY, True)
    text(s, x + 0.3, 3.55, cw - 0.6, 1.0, lab, 18, INK, True)
    text(s, x + 0.3, 4.55, cw - 0.6, 0.5, sub, 13, MUTED)
text(s, M, 5.75, W - 2 * M, 0.8, "النتيجة: قد يفوت المستخدم تحديثاً أمنياً مهماً، أو يضيع وقته في ثغرات منخفضة الخطورة.", 18, NAVY, True)
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة ونصف)\n"
         "الرقم 552 ليس تقديراً: هذا عدد الثغرات التي نشرتها قاعدة NVD الأمريكية خلال 24 ساعة، كما سجلها الرادار نفسه.\n"
         "المشكلة ثلاثية: الكمية كبيرة، والمصادر بالإنجليزية، ولا شيء يقول لك من أين تبدأ. والمعلومة الأهم، أي الثغرات استغلها المهاجمون فعلاً، "
         "موجودة في قائمة منفصلة عند وكالة CISA.")

# ================================================================== 3 الفكرة
s = new(); title(s, "الفكرة: وكيل يعمل وحده كل ساعة")
text(s, M, 1.55, W - 2 * M, 1.0, "يجلب، ويصنف، ويلخص بالعربية، ويتحقق، ثم ينشر وينبه. دون أي تدخل منا.", 22, INK)
outs = [("الموقع", "4 صفحات بالعربية والإنجليزية، يتحدث خلال دقيقة من كل دورة", NAVY),
        ("التنبيه", "رسالة تيليجرام لكل ثغرة حرجة أو مستغلة", RED),
        ("التقرير", "تصدير أي نتيجة بحث إلى PDF", GOLD_D)]
for i, (t, d, c) in enumerate(outs):
    x = W - M - (i + 1) * cw - i * 0.4
    box(s, x, 2.75, cw, 2.6, PAPER, 0.06)
    circle(s, x + cw - 1.1, 3.0, 0.8, c, str(i + 1), 22, WHITE)
    text(s, x + 0.3, 3.95, cw - 0.6, 0.6, t, 24, NAVY, True)
    text(s, x + 0.3, 4.5, cw - 0.6, 0.8, d, 15, MUTED)
box(s, M, 5.75, W - 2 * M, 0.95, NAVY, 0.1)
text(s, M + 0.3, 5.8, W - 2 * M - 0.6, 0.85, [[("الفرق عن قارئ الأخبار: ", {"bold": True, "color": BRASS}),
     ("نفصل بين خطورة الثغرة (درجة CVSS) وثبوت استغلالها (قائمة CISA)، ونرتب حسب الخطر الحقيقي.", {"color": WHITE})]], 18, WHITE, anchor="m")
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة)\n"
         "الوكيل يخرج بثلاثة مخرجات: موقع، وتنبيه، وتقرير.\n"
         "وأهم فكرة في المشروع في المربع الأزرق: ثغرة درجتها 9.8 قد لا يكون أحد استغلها، وثغرة درجتها 7.5 قد تكون مستغلة الآن. "
         "لذلك نعرض الأمرين منفصلين، ونرتب المستغلة أولاً.")

# ================================================================== 4 كيف يعمل
s = new(); title(s, "كيف يعمل: ست خطوات في كل دورة", "مُجدول مهام ويندوز يبدأ الدورة كل ساعة، ويجلب منذ آخر جلب ناجح فلا يضيع شيء وقت إطفاء الجهاز")
steps = [("الجلب", "NVD وCISA و5 خلاصات أخبار"), ("التنظيف", "إزالة التكرار وCVE المرفوض"),
         ("التصنيف", "النوع والمنتج والخطورة والاستغلال"), ("التلخيص", "Qwen3 على جهازنا، بالعربية"),
         ("التحقق", "رفض أي ملخص بلا دليل في المصدر"), ("النشر والتنبيه", "الموقع وتيليجرام")]
sw, gap = (W - 2 * M - 5 * 0.3) / 6, 0.3
for i, (t, d) in enumerate(steps):
    x = W - M - (i + 1) * sw - i * gap
    box(s, x, 2.3, sw, 2.5, PAPER, 0.08)
    circle(s, x + sw / 2 - 0.35, 2.55, 0.7, BRASS, str(i + 1), 20, NAVY)
    text(s, x + 0.1, 3.4, sw - 0.2, 0.55, t, 19, NAVY, True, align="c")
    text(s, x + 0.12, 3.95, sw - 0.24, 0.85, d, 13, MUTED, align="c")
    if i < 5: text(s, x - gap - 0.02, 3.3, gap + 0.04, 0.5, "←", 20, BRASS, True, align="c")
box(s, M, 5.15, (W - 2 * M - 0.4) / 2, 1.35, PAPER, 0.08)
text(s, M + 0.25, 5.25, (W - 2 * M - 0.4) / 2 - 0.5, 1.2, [[("SQLite  ", {"bold": True, "color": NAVY}),
     ("يحفظ العناصر وسجل الأحداث والأخطاء. إذا تعطل مصدر واحد تكمل الدورة بالباقي.", {})]], 15, INK, anchor="m")
bx = M + (W - 2 * M - 0.4) / 2 + 0.4
box(s, bx, 5.15, (W - 2 * M - 0.4) / 2, 1.35, PAPER, 0.08)
text(s, bx + 0.25, 5.25, (W - 2 * M - 0.4) / 2 - 0.5, 1.2, [[("Qwen3 8B عبر Ollama  ", {"bold": True, "color": NAVY}),
     ("نموذج مفتوح المصدر على جهازنا: مجاني، والبيانات لا تغادر الجهاز.", {})]], 15, INK, anchor="m")
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقتان)\n"
         "الدورة ست خطوات. الجلب من ثلاثة مصادر رسمية. التنظيف يزيل المكرر والأرقام المرفوضة. "
         "التصنيف يأخذ الخطورة من الدرجة الرسمية لا من تخمين النموذج. التلخيص بنموذج Qwen3 يعمل على جهازنا. "
         "التحقق يرفض أي ملخص فيه لغة أجنبية أو رقم أو ادعاء غير موجود في المصدر. ثم النشر والتنبيه.\n"
         "نقطة مهمة: الجلب يبدأ من آخر جلب ناجح، لا من آخر ساعتين. اكتشفنا هذا الخطأ أثناء التطوير واستعدنا به 372 ثغرة كانت تضيع.")

# ================================================================== 5 الأدوات
s = new(); title(s, "الأدوات: مجانية ومفتوحة المصدر")
tools = [("Python", "الوكيل كاملاً، بالمكتبة القياسية فقط"), ("Ollama + Qwen3 8B", "التلخيص محلياً، بلا مفتاح API"),
         ("SQLite", "قاعدة بيانات في ملف واحد"), ("مُجدول مهام ويندوز", "التشغيل كل ساعة، بدل n8n"),
         ("GitHub Pages", "استضافة مجانية ونشر تلقائي"), ("Telegram Bot API", "التنبيه الفوري")]
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
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة ونصف)\n"
         "كل الأدوات مجانية. تغيّر شيء واحد عن الخطة: كان المخطط n8n للأتمتة، لكن n8n يحتاج Node.js وعقدة تشغيل الأوامر فيه معطلة افتراضياً، "
         "فاستخدمنا مُجدول المهام المدمج في ويندوز. يؤدي الغرض نفسه دون تثبيت أي شيء، وأبقينا ملف n8n جاهزاً في المستودع.")

# ================================================================== 6 عرض الموقع
s = new(); title(s, "الموقع: ما يحتاج انتباهك أولاً")
pic(s, "home.png", M + 0.06, 1.5, 7.9)
cx = M + 8.35; cw2 = W - M - cx
for i, (t, d) in enumerate((("رادار حي", "كل نقطة ثغرة أو خبر من آخر 24 ساعة. البعد عن المركز عمرها، واللون خطورتها، والحلقة تعني أنها مستغلة."),
                            ("الأخطر أولاً", "أربع ثغرات: المستغلة فعلاً، ثم الأعلى درجة."),
                            ("بحث وفلاتر", "رقم CVE أو منتج أو كلمة، مع الخطورة والتاريخ، وكل نتيجة لها رابط يُشارَك."))):
    y = 1.5 + i * 1.75
    text(s, cx, y, cw2, 0.5, t, 20, NAVY, True)
    text(s, cx, y + 0.5, cw2, 1.15, d, 14, MUTED)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقتان، والأفضل عرض الموقع مباشرة هنا)\n"
         "هذه الصفحة الرئيسية. الرادار على اليسار يعرض كل ما وصل في آخر 24 ساعة. والقائمة على اليمين أخطر أربع ثغرات، والمستغلة فعلاً أولاً.\n"
         "إذا كان الإنترنت متاحاً: افتح الموقع، ابحث عن رقم CVE من القائمة، ثم افتح تفاصيله. وإذا لم يكن متاحاً فالشرائح التالية تغطي العرض.")

# ================================================================== 7 التفاصيل والتنبيهات
s = new(); title(s, "تفاصيل كل ثغرة، ومركز للتنبيهات")
half = (W - 2 * M - 0.4) / 2
ph = 3.5; pw = ph * 1280 / 900
pic(s, "detail.png", W - M - half + (half - pw) / 2, 1.55, pw, ph)
pic(s, "alerts.png", M + (half - pw) / 2, 1.55, pw, ph)
text(s, W - M - half, 5.3, half, 1.3, [[("نافذة التفاصيل: ", {"bold": True, "color": NAVY}),
     ("الدرجة من 10، والتصنيف، والتواريخ، والمنتج، وحالة الاستغلال من CISA، والوصف الأصلي، والملخص العربي مع بيان أنه آلي.", {})]], 14, INK)
text(s, M, 5.3, half, 1.3, [[("مركز التنبيهات: ", {"bold": True, "color": NAVY}),
     ("الخطورة والاستغلال في عمودين منفصلين، وسجل الرسائل التي أُرسلت فعلاً على تيليجرام.", {})]], 14, INK)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقة ونصف)\n"
         "على اليمين ثغرة في قائمة CISA للثغرات المستغلة، لكن درجتها 7.5، أي «عالية» لا «حرجة». قبل التطوير كان الموقع يعرضها «حرجة»، وهذا خلط صححناه.\n"
         "وعلى اليسار مركز التنبيهات: من 19 ثغرة مستغلة، 9 فقط حرجة حسب درجتها.")

# ================================================================== 8 الإحصائيات واللغتان
s = new(); title(s, "إحصائيات حقيقية، وموقع بلغتين")
pic(s, "dash.png", W - M - 5.1, 1.55, 5.1, 5.1 * 1300 / 1280)
pic(s, "mobile1.jpg", M + 3.45, 1.55, h=5.15)
pic(s, "home_en.png", M, 1.55, 3.2)
text(s, M, 3.95, 3.2, 2.5, ["بالإنجليزية يتغير اتجاه الصفحة، ويُعرض نص المصدر الأصلي بدل ترجمة آلية.",
                            "وعلى الجوال تنطوي الفلاتر خلف زر واحد."], 14, MUTED)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقة)\n"
         "صفحة الإحصائيات تحسب كل رقم من قاعدة البيانات كاملة: 784 ثغرة رصدناها منذ 25 نوفمبر. والساعات التي سبقت بدء الرصد مخططة حتى لا تُقرأ صفراً.\n"
         "والموقع كامل بالإنجليزية، ويعمل على الجوال.")

# ================================================================== 9 الاختبار
s = new(); title(s, "الاختبار: أربع جولات على عينات حية", "كل جولة 20 عنصراً روجعت يدوياً مقابل المصدر، وكل ثغرة طوبقت مع NVD")
cd = CategoryChartData(); cd.categories = ["الجولة الأولى", "الجولة الثانية", "الجولة الثالثة", "الجولة الرابعة"]
cd.add_series("دقة التصنيف", (95, 100, 90, 95)); cd.add_series("دقة الخطورة", (88, 100, 100, 100)); cd.add_series("الملخصات السليمة", (30, 75, 79, 65))
gf = s.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(M), Inches(1.85), Inches(8.6), Inches(4.85), cd)
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
rx = M + 8.9; rw = W - M - rx
for i, (big, lab) in enumerate((("90%", "هدف الخطة لدقة التصنيف والخطورة، وتحقق في كل الجولات بعد الإصلاح"),
                                ("3/3", "تنبيه ثغرات حرجة معروفة (Log4Shell وPAN-OS وCitrix Bleed)"),
                                ("77", "اختباراً آلياً تعمل مع كل تعديل"))):
    y = 1.9 + i * 1.6
    box(s, rx, y, rw, 1.4, PAPER, 0.08)
    text(s, rx + 0.2, y + 0.08, rw - 0.4, 0.6, big, 26, NAVY, True)
    text(s, rx + 0.2, y + 0.68, rw - 0.4, 0.7, lab, 12.5, MUTED)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقتان)\n"
         "التصنيف والخطورة فوق الهدف في كل الجولات بعد الإصلاح. الأخضر هو نقطة الضعف: الملخصات. بدأت بـ 30% مع النموذج القديم لأنه كان يخلط الصينية والروسية، "
         "ووصلت إلى 79%.\n"
         "لماذا 65% في الجولة الرابعة؟ لأنها عينة جديدة كلياً، ونحن نقيس بأمانة على عينة لم نرها. وبعدها أضفنا فحص الادعاءات الذي سحب 36 ملخصاً من الموقع.")

# ================================================================== 10 ما كشفه الاختبار
s = new(); title(s, "ما كشفه الاختبار، وكيف أصلحناه")
cards = [("372", "ثغرة استعدناها", "كانت تضيع وقت إطفاء الجهاز لأن الجلب كان من آخر ساعتين فقط"),
         ("9", "فقط من 19 مستغلة حرجة فعلاً", "كان الموقع يعرض كل ثغرة مستغلة «حرجة»، ففصلنا الخطورة عن الاستغلال"),
         ("36", "ملخصاً سحبناه", "قالت «دون مصادقة» أو «المفوضية الأوروبية» والمصدر لا يذكرهما"),
         ("6", "رسائل في الدورة بدل 106", "حد 5 رسائل للأهم ورسالة واحدة تجمع الباقي")]
cw4 = (W - 2 * M - 3 * 0.3) / 4
for i, (big, lab, d) in enumerate(cards):
    x = W - M - (i + 1) * cw4 - i * 0.3
    box(s, x, 1.75, cw4, 4.6, PAPER, 0.06)
    text(s, x + 0.25, 2.05, cw4 - 0.5, 1.0, big, 38, RED if i == 0 else NAVY, True)
    text(s, x + 0.25, 3.1, cw4 - 0.5, 0.6, lab, 18, INK, True)
    text(s, x + 0.25, 3.8, cw4 - 0.5, 2.3, d, 14, MUTED)
text(s, M, 6.55, W - 2 * M, 0.45, "كل خطأ صار اختباراً آلياً يمنع عودته.", 16, NAVY, True)
footer(s, next(N))
notes(s, "المتحدث: عبدالله الخليفة (دقيقتان)\n"
         "أهم ما تعلمناه أن الاختبار يكشف ما لا تكشفه قراءة الكود. أربعة أمثلة:\n"
         "1) 372 ثغرة كانت تضيع لأن الجلب كان من آخر ساعتين، فإذا أُطفئ الجهاز ضاع ما نُشر في غيابه.\n"
         "2) كل ثغرة مستغلة كانت تظهر «حرجة»، والصحيح أن 9 فقط من 19.\n"
         "3) النموذج كان يضيف «دون مصادقة» من عنده، وأحياناً «المفوضية الأوروبية» من قائمة المصطلحات. صار أي ادعاء يحتاج دليلاً في المصدر.\n"
         "4) في التجربة الأولى خرجت 106 رسالة تنبيه في دورة واحدة، والآن 6 على الأكثر.")

# ================================================================== 11 الأمان
s = new(); title(s, "الأمان والخصوصية")
items = [("لا أسرار في الكود", "توكن تيليجرام في متغيرات الجهاز فقط، وفحصنا المستودع كاملاً"),
         ("البيانات لا تغادر الجهاز", "النموذج اللغوي محلي، لا خدمة ذكاء اصطناعي خارجية"),
         ("لا تنفيذ لمحتوى خارجي", "كل نص من الأخبار يُعرض نصاً عادياً، وسياسة CSP تمنع أي سكربت غريب"),
         ("تعليمات محمية", "النموذج يتجاهل أي أوامر داخل نص الخبر"),
         ("حقوق النشر", "ملخص قصير مع رابط المصدر، دون نسخ المقالات")]
for i, (t, d) in enumerate(items):
    y = 1.65 + i * 1.0
    circle(s, W - M - 0.7, y + 0.08, 0.6, NAVY, "✓", 18, BRASS)
    text(s, M, y, W - 2 * M - 1.0, 0.45, t, 19, NAVY, True)
    text(s, M, y + 0.45, W - 2 * M - 1.0, 0.45, d, 14, MUTED)
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة)\n"
         "الأخبار نص خارجي غير موثوق، فتعاملنا معها على هذا الأساس: لا تُنفَّذ كـ HTML، ولا يُطيع النموذج أي أوامر داخلها، "
         "والموقع لا يحمّل إلا سكربتاته هو.")

# ================================================================== 12 القيود والتطوير
s = new(); title(s, "قيود نعرفها، وتطوير نقترحه")
half = (W - 2 * M - 0.5) / 2
box(s, W - M - half, 1.65, half, 4.75, PAPER, 0.05)
text(s, W - M - half + 0.3, 1.85, half - 0.6, 0.55, "قيود معروفة", 22, RED, True)
text(s, W - M - half + 0.3, 2.5, half - 0.6, 3.8, [
    [("الملخصات: ", {"bold": True, "color": NAVY}), ("نموذج صغير قد يخطئ في المعنى، فكل ملخص معلَّم ومعه المصدر", {})],
    [("لا خادم: ", {"bold": True, "color": NAVY}), ("الموقع لا يتحدث والجهاز مطفأ، وما فات يُجلب لاحقاً", {})],
    [("المنتج المتأثر: ", {"bold": True, "color": NAVY}), ("عُرف لـ 641 من 784 ثغرة", {})],
    [("السرعة: ", {"bold": True, "color": NAVY}), ("15 إلى 30 ثانية للملخص على المعالج", {})]], 15, INK, spacing=1.3)
box(s, M, 1.65, half, 4.75, PAPER, 0.05)
text(s, M + 0.3, 1.85, half - 0.6, 0.55, "تطوير مقترح", 22, TEAL, True)
text(s, M + 0.3, 2.5, half - 0.6, 3.8, [
    [("نموذج أكبر ", {"bold": True, "color": NAVY}), ("(qwen3:14b) أو جهاز بكرت شاشة", {})],
    [("خادم دائم ", {"bold": True, "color": NAVY}), ("بدل الجهاز الشخصي", {})],
    [("قناة تيليجرام عامة ", {"bold": True, "color": NAVY}), ("وملخص أسبوعي تلقائي", {})],
    [("استفادة تجارية: ", {"bold": True, "color": NAVY}), ("تقارير أمنية للشركات الصغيرة، وواجهة API بالعربية", {})]], 15, INK, spacing=1.3)
footer(s, next(N))
notes(s, "المتحدث: عبدالله القحطاني (دقيقة ونصف)\n"
         "نذكر القيود بصراحة لأنها موجودة. أهمها الملخصات، وحلها نموذج أكبر أو جهاز أقوى. "
         "والتطوير التجاري الأقرب: الموقع يصدّر الآن تقارير PDF، ويمكن تحويلها لخدمة تقارير شهرية للشركات الصغيرة.")

# ================================================================== 13 الخاتمة
s = new(True)
text(s, M, 1.2, W - 2 * M, 1.0, "الخلاصة", 40, WHITE, True)
text(s, M, 2.3, W - 2 * M, 2.4, [
    "وكيل يعمل وحده كل ساعة، من الجلب إلى النشر والتنبيه، بتكلفة صفر.",
    "حقق أهداف الخطة في التصنيف والخطورة والتنبيه.",
    "والدقة قبل الكثرة: ما فيه شك يُحجب، والمصدر بجانب كل ملخص."], 22, "E6EAF2", spacing=1.4)
box(s, M, 5.05, W - 2 * M, 1.1, "1C2D4E", 0.1)
text(s, M + 0.3, 5.1, W - 2 * M - 0.6, 1.0, [[("جرّبوه الآن: ", {"bold": True, "color": BRASS}),
     ("nfalqhtan-hue.github.io/radar", {"color": WHITE, "bold": True})]], 24, WHITE, anchor="m")
text(s, M, 6.45, W - 2 * M, 0.6, "شكراً لكم، ونسعد بأسئلتكم", 20, "A3AFC6")
next(N)
notes(s, "المتحدث: عبدالله الخليفة (دقيقة)\n"
         "الخلاصة في ثلاث جمل كما في الشريحة. ونترك الرابط ظاهراً لمن يريد التجربة أثناء الأسئلة.\n"
         "الشرائح التالية ملحق للأسئلة المتوقعة: لا تُعرض إلا إذا جاء سؤال يحتاجها.")

# ================================================================== ملحق: أسئلة متوقعة
QA = [
    ("لماذا لم تستخدموا ChatGPT أو واجهة API مدفوعة؟", "لأن الهدف تكلفة صفر، ولأن النموذج المحلي يُبقي البيانات على جهازنا. هو أضعف في العربية، فعوضنا بفحوص جودة آلية وبعرض المصدر بجانب كل ملخص."),
    ("كيف تضمنون أن الملخص صحيح؟", "لا نضمنه بالكامل، ونقولها بوضوح. نرفض آلياً أي ملخص فيه لغة أجنبية أو رقم أو ادعاء غير موجود في المصدر، ونعلّم الباقي «ملخص آلي»، والوصف الأصلي ورابطه بجانبه."),
    ("ما الفرق بين الخطورة والاستغلال؟", "الخطورة درجة CVSS من NVD: ماذا يحدث لو استُغلت الثغرة. والاستغلال من قائمة CISA: هل استغلها مهاجمون فعلاً. من 19 ثغرة مستغلة عندنا 9 فقط حرجة."),
    ("لماذا تركتم n8n؟", "n8n يحتاج Node.js غير المثبت، وعقدة تشغيل الأوامر فيه معطلة افتراضياً. مُجدول مهام ويندوز مدمج ويؤدي الغرض نفسه، وملف n8n جاهز في المستودع."),
    ("ماذا يحدث إذا انطفأ الجهاز؟", "الموقع يبقى منشوراً بآخر بيانات، ويظهر عليه أنه متأخر. وعند التشغيل يجلب الوكيل كل ما فاته منذ آخر جلب ناجح، حتى 7 أيام."),
    ("لماذا انخفضت الملخصات السليمة في الجولة 4 إلى 65%؟", "لأنها عينة جديدة لم نضبط عليها شيئاً، وهذا قياس أصدق. وبعدها أضفنا فحص الادعاءات الذي سحب 36 ملخصاً غير دقيق من الموقع."),
    ("كيف تمنعون إغراق المستخدم بالتنبيهات؟", "خمس رسائل للأهم في كل دورة (المستغلة أولاً ثم الأعلى درجة)، ورسالة واحدة تجمع الباقي، ولا تتكرر رسالة لنفس الثغرة."),
    ("هل الموقع آمن من محتوى خبيث في الأخبار؟", "نعم. كل نص يُعرض نصاً عادياً لا HTML، والروابط تُقبل بـ http وhttps فقط، وسياسة CSP تمنع أي سكربت غير سكربتات الموقع."),
    ("كيف يمكن تطوير المشروع تجارياً؟", "تقارير أمنية مخصصة للشركات الصغيرة (الموقع يصدّر PDF الآن)، وتقارير شهرية، وواجهة API لبيانات الثغرات بالعربية، وإعلانات ورعايات."),
    ("ما أصعب مشكلة واجهتكم؟", "الملخصات العربية: النموذج الأول كان يخلط الصينية والروسية في 14 من 20 ملخصاً. حللناها بتغيير النموذج وبحارس جودة، فارتفع السليم من 30% إلى 79%."),
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

out = os.path.join(ROOT, "FINAL_PRESENTATION.pptx")
prs.save(out)
print("saved", out, len(prs.slides), "slides")
