"""Build a .docx version of a report with the same fixed structure as templates/report.html."""
import base64
import os
import re
from html.parser import HTMLParser

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.image.image import Image as DocxImage
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Mm, Pt, RGBColor

from report_texts import SEVERITIES

FONT = "Arial"
MONO = "Consolas"
BRAND = RGBColor(0x21, 0xA0, 0x38)
BRAND_DARK = RGBColor(0x10, 0x7F, 0x3E)
MUTED = RGBColor(0x6B, 0x72, 0x80)
RED = RGBColor(0xE5, 0x48, 0x4D)
SEV_HEX = {"critical": "8E1B3B", "high": "E5484D", "medium": "F59E0B", "low": "2F80ED", "info": "8A94A6"}
HEAD_FILL = "F3F5F7"
GRADIENT = ["F2E913", "8CC63F", "21A038", "1D9BD7", "42E3B4"]
MAX_IMG_MM = 165
CALLOUT_COLORS = {  # border, fill
    "note": ("2F80ED", "EAF2FD"), "warning": ("D97706", "FEF3DD"),
    "danger": ("E5484D", "FDECEC"), "tip": ("21A038", "EAF6EC"),
}

BLOCK_TAGS = {"p", "div", "h3", "h4", "ul", "ol", "pre", "blockquote", "table", "figure", "hr"}
VOID_TAGS = {"br", "img", "hr"}


# ---------------------------------------------------------------- tiny HTML tree
class Node:
    def __init__(self, tag, attrs=None, parent=None):
        self.tag, self.attrs, self.parent, self.children = tag, dict(attrs or {}), parent, []


class TreeBuilder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("root")
        self.cur = self.root

    def handle_starttag(self, tag, attrs):
        node = Node(tag, attrs, self.cur)
        self.cur.children.append(node)
        if tag not in VOID_TAGS:
            self.cur = node

    def handle_endtag(self, tag):
        n = self.cur
        while n is not self.root and n.tag != tag:
            n = n.parent
        if n is not self.root:
            self.cur = n.parent

    def handle_data(self, data):
        self.cur.children.append(data)


def parse_html(html):
    b = TreeBuilder()
    b.feed(html or "")
    b.close()
    return b.root


def text_of(node):
    if isinstance(node, str):
        return node
    return "".join(text_of(c) for c in node.children)


# ---------------------------------------------------------------- docx helpers
# Word rejects files whose property children are out of schema order, so insert in order.
ORDER = {
    "tblPr": ["tblStyle", "tblpPr", "tblOverlap", "bidiVisual", "tblStyleRowBandSize", "tblStyleColBandSize",
              "tblW", "jc", "tblCellSpacing", "tblInd", "tblBorders", "shd", "tblLayout", "tblCellMar", "tblLook"],
    "pPr": ["pStyle", "keepNext", "keepLines", "pageBreakBefore", "framePr", "widowControl", "numPr",
            "suppressLineNumbers", "pBdr", "shd", "tabs", "suppressAutoHyphens", "kinsoku", "wordWrap",
            "overflowPunct", "topLinePunct", "autoSpaceDE", "autoSpaceDN", "bidi", "adjustRightInd", "snapToGrid",
            "spacing", "ind", "contextualSpacing", "mirrorIndents", "suppressOverlap", "jc", "textDirection",
            "textAlignment", "textboxTightWrap", "outlineLvl", "divId", "cnfStyle", "rPr", "sectPr", "pPrChange"],
    "tcPr": ["cnfStyle", "tcW", "gridSpan", "hMerge", "vMerge", "tcBorders", "shd", "noWrap", "tcMar",
             "textDirection", "tcFitText", "vAlign", "hideMark"],
}


def put(parent, child):
    """Insert/replace `child` in a w:*Pr element respecting the schema order."""
    order = ORDER[parent.tag.split("}")[1]]
    name = child.tag.split("}")[1]
    for old in parent.findall(child.tag):
        parent.remove(old)
    idx = order.index(name)
    for i, existing in enumerate(parent):
        ename = existing.tag.split("}")[1]
        if ename in order and order.index(ename) > idx:
            parent.insert(i, child)
            return child
    parent.append(child)
    return child

def shade(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    put(tc_pr, shd)


def para_shade(par, fill, left_border=None):
    p_pr = par._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    put(p_pr, shd)
    if left_border:
        bdr = OxmlElement("w:pBdr")
        left = OxmlElement("w:left")
        for k, v in (("val", "single"), ("sz", "18"), ("space", "6"), ("color", left_border)):
            left.set(qn("w:" + k), v)
        bdr.append(left)
        put(p_pr, bdr)


def bottom_border(par, color="21A038", size="12"):
    p_pr = par._p.get_or_add_pPr()
    bdr = OxmlElement("w:pBdr")
    b = OxmlElement("w:bottom")
    for k, v in (("val", "single"), ("sz", size), ("space", "4"), ("color", color)):
        b.set(qn("w:" + k), v)
    bdr.append(b)
    put(p_pr, bdr)


def add_field(par, instr, size=8, color=MUTED):
    run = par.add_run()
    run.font.size, run.font.color.rgb = Pt(size), color
    for kind, text in (("begin", None), ("instr", instr), ("separate", None), ("text", "1"), ("end", None)):
        if kind == "instr":
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        elif kind == "text":
            el = OxmlElement("w:t")
            el.text = text
        else:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        run._r.append(el)


def set_cell_margins(table, mm=1.6):
    tbl_pr = table._tbl.tblPr
    mar = OxmlElement("w:tblCellMar")
    for side in ("top", "bottom", "left", "right"):
        el = OxmlElement("w:" + side)
        el.set(qn("w:w"), str(int(mm * 56.7 if side in ("top", "bottom") else mm * 113)))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    put(tbl_pr, mar)


def no_borders(table):
    tbl_pr = table._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement("w:" + side)
        el.set(qn("w:val"), "nil")
        borders.append(el)
    put(tbl_pr, borders)


def set_widths(table, widths_mm):
    """Fixed column widths (Word and LibreOffice both honour these)."""
    table.autofit = False
    tbl_pr = table._tbl.tblPr
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    put(tbl_pr, layout)
    for col, w in zip(table.columns, widths_mm):
        col.width = Mm(w)
    for row in table.rows:
        for cell, w in zip(row.cells, widths_mm):
            cell.width = Mm(w)


def keep_with_next(par):
    par.paragraph_format.keep_with_next = True


def cell_text(cell, text, bold=False, color=None, size=9.5, mono=False, align=None):
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    if align:
        p.alignment = align
    r = p.add_run(text)
    r.bold, r.font.size = bold, Pt(size)
    if mono:
        r.font.name = MONO
    if color:
        r.font.color.rgb = color
    return r


# ---------------------------------------------------------------- renderer
class Renderer:
    def __init__(self, doc, L, upload_dir):
        self.doc, self.L, self.upload_dir = doc, L, upload_dir
        self.figure_no = 0
        self.callout = None  # (border, fill) while rendering inside a callout block

    # images ------------------------------------------------------------
    def image_blob(self, src):
        src = src or ""
        if src.startswith("/uploads/"):
            name = os.path.basename(src)
            path = os.path.join(self.upload_dir, name)
            if re.match(r"^[0-9a-f]{32}\.(png|jpg|gif|webp)$", name) and os.path.exists(path):
                with open(path, "rb") as fh:
                    return fh.read()
        m = re.match(r"data:image/[a-z+.-]+;base64,(.*)$", src, re.S)
        if m:
            try:
                return base64.b64decode(m.group(1))
            except ValueError:
                return None
        return None

    def add_picture(self, run, src):
        blob = self.image_blob(src)
        if not blob:
            return False
        import io
        try:
            info = DocxImage.from_blob(blob)
            dpi = info.horz_dpi or 96
            width_mm = min(info.px_width * 25.4 / max(dpi, 72), MAX_IMG_MM)
            run.add_picture(io.BytesIO(blob), width=Mm(width_mm))
            return True
        except Exception:  # unsupported format (e.g. WebP) — leave a marker instead
            run.add_text("[image]")
            return False

    # inline ------------------------------------------------------------
    def inline(self, par, nodes, fmt=None):
        fmt = fmt or {}
        for n in nodes:
            if isinstance(n, str):
                text = n if fmt.get("pre") else re.sub(r"\s+", " ", n)
                if not text:
                    continue
                if fmt.get("pre"):
                    lines = text.split("\n")
                    for i, line in enumerate(lines):
                        r = par.add_run(line)
                        self.style_run(r, fmt)
                        if i < len(lines) - 1:
                            r.add_break()
                else:
                    self.style_run(par.add_run(text), fmt)
                continue
            t = n.tag
            if t == "br":
                par.add_run().add_break()
            elif t == "img":
                self.add_picture(par.add_run(), n.attrs.get("src"))
            elif t in ("b", "strong"):
                self.inline(par, n.children, dict(fmt, bold=True))
            elif t in ("i", "em"):
                self.inline(par, n.children, dict(fmt, italic=True))
            elif t == "u":
                self.inline(par, n.children, dict(fmt, underline=True))
            elif t in ("s", "strike"):
                self.inline(par, n.children, dict(fmt, strike=True))
            elif t == "code":
                self.inline(par, n.children, dict(fmt, mono=True))
            elif t == "sub":
                self.inline(par, n.children, dict(fmt, sub=True))
            elif t == "sup":
                self.inline(par, n.children, dict(fmt, sup=True))
            elif t == "a":
                self.inline(par, n.children, dict(fmt, link=True))
            else:
                self.inline(par, n.children, fmt)

    @staticmethod
    def style_run(r, fmt):
        r.bold = fmt.get("bold") or None
        r.italic = fmt.get("italic") or None
        r.underline = fmt.get("underline") or fmt.get("link") or None
        r.font.strike = fmt.get("strike") or None
        r.font.subscript = fmt.get("sub") or None
        r.font.superscript = fmt.get("sup") or None
        if fmt.get("mono"):
            r.font.name = MONO
            r.font.size = Pt(8.5 if fmt.get("pre") else 9)
        if fmt.get("link"):
            r.font.color.rgb = BRAND_DARK
        if fmt.get("pre"):
            r.font.color.rgb = RGBColor(0x1F, 0x1F, 0x22)

    # blocks ------------------------------------------------------------
    def new_par(self, container, style=None):
        p = container.add_paragraph(style=style)
        p.paragraph_format.space_after = Pt(4)
        if self.callout:
            para_shade(p, self.callout[1], left_border=self.callout[0])
            p.paragraph_format.space_after = Pt(0)
        return p

    def blocks(self, container, nodes, level=0):
        pending = []

        def flush():
            if any(isinstance(x, str) and x.strip() or not isinstance(x, str) for x in pending):
                self.inline(self.new_par(container), pending)
            pending.clear()

        for n in nodes:
            if isinstance(n, str) or n.tag not in BLOCK_TAGS:
                pending.append(n)
                continue
            flush()
            t = n.tag
            callout = re.search(r"callout-(\w+)", n.attrs.get("class", "")) if t == "div" else None
            if callout and callout.group(1) in CALLOUT_COLORS and not self.callout:
                self.callout = CALLOUT_COLORS[callout.group(1)]
                self.blocks(container, n.children, level)
                self.callout = None
                self.new_par(container).paragraph_format.space_after = Pt(0)
            elif t in ("p", "div"):
                if any(not isinstance(c, str) and c.tag in BLOCK_TAGS for c in n.children):
                    self.blocks(container, n.children, level)
                else:
                    self.inline(self.new_par(container), n.children)
            elif t in ("h3", "h4"):
                p = self.new_par(container)
                p.paragraph_format.space_before = Pt(6)
                keep_with_next(p)
                self.inline(p, n.children, {"bold": True})
                for r in p.runs:
                    r.font.size = Pt(11.5 if t == "h3" else 10.5)
            elif t in ("ul", "ol"):
                self.list(container, n, level)
            elif t == "pre":
                p = self.new_par(container)
                para_shade(p, "F4F6F8", left_border="21A038")
                self.inline(p, n.children, {"mono": True, "pre": True})
            elif t == "blockquote":
                p = self.new_par(container)
                para_shade(p, "EAF6EC", left_border="21A038")
                self.inline(p, n.children, {"italic": True})
            elif t == "table":
                self.table(container, n)
            elif t == "figure":
                self.figure(container, n)
            elif t == "hr":
                bottom_border(self.new_par(container), color="D9DDE3", size="6")
        flush()

    def list(self, container, node, level):
        i = 0
        for li in node.children:
            if isinstance(li, str) or li.tag != "li":
                continue
            i += 1
            inline_nodes = [c for c in li.children if isinstance(c, str) or c.tag not in ("ul", "ol")]
            nested = [c for c in li.children if not isinstance(c, str) and c.tag in ("ul", "ol")]
            p = self.new_par(container)
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.left_indent = Mm(6 + 6 * level)
            p.paragraph_format.first_line_indent = Mm(-4.5)
            p.add_run(("%d." % i if node.tag == "ol" else "•") + "\t")
            p.paragraph_format.tab_stops.add_tab_stop(Mm(6 + 6 * level))
            self.inline(p, inline_nodes)
            for sub in nested:
                self.list(container, sub, level + 1)

    def table(self, container, node):
        rows = []
        for sect in node.children:
            if isinstance(sect, str):
                continue
            trs = [sect] if sect.tag == "tr" else [c for c in sect.children if not isinstance(c, str) and c.tag == "tr"]
            for tr in trs:
                rows.append([c for c in tr.children if not isinstance(c, str) and c.tag in ("td", "th")])
        if not rows:
            return
        cols = max(len(r) for r in rows)
        tbl = container.add_table(rows=len(rows), cols=cols)
        tbl.style = "Table Grid"
        set_cell_margins(tbl)
        set_widths(tbl, [174.0 / cols] * cols)
        for ri, row in enumerate(rows):
            for ci, cell_node in enumerate(row):
                cell = tbl.cell(ri, ci)
                p = cell.paragraphs[0]
                p.paragraph_format.space_after = Pt(0)
                self.inline(p, cell_node.children, {"bold": cell_node.tag == "th"})
                for r in p.runs:
                    r.font.size = Pt(9.5)
                if cell_node.tag == "th":
                    shade(cell, HEAD_FILL)
        self.new_par(container).paragraph_format.space_after = Pt(2)

    def figure(self, container, node):
        imgs, caption = [], ""
        def walk(n):
            nonlocal caption
            for c in n.children:
                if isinstance(c, str):
                    continue
                if c.tag == "img":
                    imgs.append(c.attrs.get("src"))
                elif c.tag == "figcaption":
                    caption = text_of(c).strip()
                else:
                    walk(c)
        walk(node)
        for src in imgs:
            p = self.new_par(container)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            keep_with_next(p)
            self.add_picture(p.add_run(), src)
        self.figure_no += 1
        cap = self.new_par(container)
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap.paragraph_format.space_after = Pt(8)
        r = cap.add_run("%s %d" % (self.L["figure"], self.figure_no) + (" — " + caption if caption else ""))
        r.italic, r.font.size, r.font.color.rgb = True, Pt(9), MUTED

    def html(self, container, html):
        self.blocks(container, parse_html(html).children)


# ---------------------------------------------------------------- document
def heading(doc, text, num=None, level=1):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14 if level == 1 else 10)
    p.paragraph_format.space_after = Pt(6)
    keep_with_next(p)
    if num:
        r = p.add_run(num + " ")
        r.font.color.rgb = BRAND
    r2 = p.add_run(text)
    # Heading styles make the text show up in Word's navigation pane.
    p.style = doc.styles["Heading 1" if level == 1 else "Heading 2"]
    if level == 1:
        bottom_border(p)
    for r in p.runs:
        r.bold = True
        r.font.name = FONT
        r.font.size = Pt(16 if level == 1 else 12.5)
    r2.font.color.rgb = RGBColor(0x1F, 0x1F, 0x22)
    return p


def sub_label(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(2)
    keep_with_next(p)
    r = p.add_run(text.upper())
    r.bold, r.font.size, r.font.color.rgb = True, Pt(9), BRAND_DARK
    return p


def kv_table(doc, rows, key_width_mm=55):
    t = doc.add_table(rows=len(rows), cols=2)
    t.style = "Table Grid"
    set_cell_margins(t)
    for i, (k, v) in enumerate(rows):
        shade(t.cell(i, 0), HEAD_FILL)
        cell_text(t.cell(i, 0), k, bold=True, color=RGBColor(0x3F, 0x46, 0x50))
        cell_text(t.cell(i, 1), v or "—")
    set_widths(t, [key_width_mm, 174 - key_width_mm])
    return t


def severity_cell(cell, sev, L):
    shade(cell, SEV_HEX[sev])
    cell_text(cell, L["severity"][sev], bold=True, color=RGBColor(0xFF, 0xFF, 0xFF), size=9)


def build_docx(report, findings, counts, L, brand, upload_dir, logo_path, generated):
    doc = Document()
    # base styles
    normal = doc.styles["Normal"]
    normal.font.name, normal.font.size = FONT, Pt(10.5)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
    for name in ("Heading 1", "Heading 2"):
        st = doc.styles[name]
        st.font.name, st.font.color.rgb = FONT, RGBColor(0x1F, 0x1F, 0x22)

    sec = doc.sections[0]
    sec.page_width, sec.page_height = Mm(210), Mm(297)
    sec.top_margin, sec.bottom_margin = Mm(22), Mm(20)
    sec.left_margin = sec.right_margin = Mm(18)
    sec.different_first_page_header_footer = True

    # header / footer for pages 2+
    hp = sec.header.paragraphs[0]
    hp.text = ""
    r = hp.add_run("%s · %s" % (brand, L["cover_kind"]))
    r.font.size, r.font.color.rgb = Pt(8), MUTED
    hp.add_run("\t\t")
    r = hp.add_run(report["title"])
    r.font.size, r.font.color.rgb = Pt(8), MUTED
    fp = sec.footer.paragraphs[0]
    class_rgb = RGBColor.from_string(report["class_color"].lstrip("#"))
    r = fp.add_run(report["class_label"].upper())
    r.bold, r.font.size, r.font.color.rgb = True, Pt(8), class_rgb
    fp.add_run("\t\t")
    r = fp.add_run("%s " % L["page"])
    r.font.size, r.font.color.rgb = Pt(8), MUTED
    add_field(fp, "PAGE")
    r = fp.add_run(" %s " % L["of"])
    r.font.size, r.font.color.rgb = Pt(8), MUTED
    add_field(fp, "NUMPAGES")

    R = Renderer(doc, L, upload_dir)

    # ------------------------------------------------------------ cover
    top = doc.add_table(rows=1, cols=2)
    no_borders(top)
    set_widths(top, [120, 54])
    c0 = top.cell(0, 0).paragraphs[0]
    if os.path.exists(logo_path):
        c0.add_run().add_picture(logo_path, width=Mm(11))
        c0.add_run("  ")
    r = c0.add_run(brand)
    r.bold, r.font.size, r.font.color.rgb = True, Pt(18), BRAND
    c1 = top.cell(0, 1).paragraphs[0]
    c1.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    r = c1.add_run(report["class_label"].upper())
    r.bold, r.font.size, r.font.color.rgb = True, Pt(9), class_rgb

    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_before = Mm(55)
    p = doc.add_paragraph()
    r = p.add_run(L["cover_kind"].upper())
    r.bold, r.font.size, r.font.color.rgb = True, Pt(10), BRAND
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(6)
    r = p.add_run(report["title"])
    r.bold, r.font.size = True, Pt(28)
    if report["system_name"]:
        p = doc.add_paragraph()
        r = p.add_run(report["system_name"])
        r.font.size, r.font.color.rgb = Pt(14), MUTED

    bar = doc.add_table(rows=1, cols=len(GRADIENT))
    no_borders(bar)
    bar.alignment = WD_TABLE_ALIGNMENT.LEFT
    for i, color in enumerate(GRADIENT):
        cell = bar.cell(0, i)
        shade(cell, color)
        cp = cell.paragraphs[0]
        cp.paragraph_format.space_after = Pt(0)
        cp.add_run().font.size = Pt(2)
    set_widths(bar, [12] * len(GRADIENT))

    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_before = Mm(60)
    meta = doc.add_table(rows=4, cols=2)
    no_borders(meta)
    period = "%s — %s" % (_d(report["start_date"]), _d(report["end_date"]))
    for i, (k, v) in enumerate([(L["client"], report["client"]), (L["test_type"], report["test_type"]),
                                (L["period"], period), (L["version"], report["version"])]):
        cell_text(meta.cell(i, 0), k, color=MUTED, size=10)
        cell_text(meta.cell(i, 1), v or "—", bold=True, size=10)
    set_widths(meta, [50, 124])
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # ------------------------------------------------------------ document control + TOC
    heading(doc, L["doc_control"])
    kv_table(doc, [
        (L["report"], report["title"]), (L["client"], report["client"]), (L["system"], report["system_name"]),
        (L["test_type"], report["test_type"]), (L["period"], period), (L["authors"], report["authors"]),
        (L["version"], report["version"]), (L["classification"], report["class_label"]),
        (L["date"], generated),
    ])
    heading(doc, L["toc"])
    toc = [("1.", L["s_exec"], 0), ("1.1.", L["s_summary"], 1), ("2.", L["s_scope"], 0),
           ("3.", L["s_method"], 0), ("3.1.", L["a_scale"], 1), ("4.", L["s_details"], 0)]
    toc += [("4.%d." % i, "%s %s" % (f["code"], f["title"]), 1) for i, f in enumerate(findings, 1)]
    toc += [("5.", L["s_concl"], 0)]
    for num, text, lvl in toc:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.left_indent = Mm(8 * lvl)
        r = p.add_run("%s  %s" % (num, text))
        r.font.size = Pt(10.5 if lvl == 0 else 9.5)
        if lvl:
            r.font.color.rgb = MUTED
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # ------------------------------------------------------------ 1. executive summary
    heading(doc, L["s_exec"], "1.")
    R.html(doc, report["executive_summary"])
    heading(doc, L["s_summary"], "1.1.", level=2)
    total = sum(counts.values())
    st = doc.add_table(rows=len(SEVERITIES) + 1, cols=2)
    st.style = "Table Grid"
    set_cell_margins(st)
    for i, sev in enumerate(SEVERITIES):
        severity_cell(st.cell(i, 0), sev, L)
        cell_text(st.cell(i, 1), str(counts[sev]), bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
    shade(st.cell(len(SEVERITIES), 0), HEAD_FILL)
    cell_text(st.cell(len(SEVERITIES), 0), L["total"], bold=True)
    cell_text(st.cell(len(SEVERITIES), 1), str(total), bold=True, color=BRAND, align=WD_ALIGN_PARAGRAPH.CENTER)
    set_widths(st, [50, 25])
    doc.add_paragraph()

    if findings:
        ft = doc.add_table(rows=len(findings) + 1, cols=5)
        ft.style = "Table Grid"
        set_cell_margins(ft)
        for i, h in enumerate([L["id"], L["name"], L["level"], L["cvss"], L["status_l"]]):
            shade(ft.cell(0, i), "21A038")
            cell_text(ft.cell(0, i), h, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
        for ri, f in enumerate(findings, 1):
            cell_text(ft.cell(ri, 0), f["code"], mono=True, size=9)
            cell_text(ft.cell(ri, 1), f["title"])
            severity_cell(ft.cell(ri, 2), f["severity"], L)
            cell_text(ft.cell(ri, 3), f["cvss_score"] or "—", mono=True, size=9)
            cell_text(ft.cell(ri, 4), L["status"].get(f["status"], f["status"]))
        set_widths(ft, [16, 78, 30, 16, 34])
    else:
        doc.add_paragraph(L["no_findings"])

    # ------------------------------------------------------------ 2. scope, 3. methodology
    heading(doc, L["s_scope"], "2.")
    R.html(doc, report["scope"])
    heading(doc, L["s_method"], "3.")
    R.html(doc, report["methodology"])
    heading(doc, L["a_scale"], "3.1.", level=2)
    sc = doc.add_table(rows=len(L["scale"]) + 1, cols=3)
    sc.style = "Table Grid"
    set_cell_margins(sc)
    for i, h in enumerate([L["level"], "CVSS v3.1", L["f_description"]]):
        shade(sc.cell(0, i), "21A038")
        cell_text(sc.cell(0, i), h, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
    for ri, (sev, rng, text) in enumerate(L["scale"], 1):
        severity_cell(sc.cell(ri, 0), sev, L)
        cell_text(sc.cell(ri, 1), rng, mono=True, size=9)
        cell_text(sc.cell(ri, 2), text)
    set_widths(sc, [32, 26, 116])

    # ------------------------------------------------------------ 4. findings
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    heading(doc, L["s_details"], "4.")
    if not findings:
        doc.add_paragraph(L["no_findings"])
    for i, f in enumerate(findings, 1):
        h = heading(doc, "%s %s" % (f["code"], f["title"]), "4.%d." % i, level=2)
        h.runs[-1].font.color.rgb = RGBColor(0x1F, 0x1F, 0x22)
        rows = 3 + (1 if f["cvss_vector"] else 0)
        mt = doc.add_table(rows=rows, cols=4)
        mt.style = "Table Grid"
        set_cell_margins(mt)
        set_widths(mt, [38, 50, 30, 56])
        shade(mt.cell(0, 0), HEAD_FILL)
        cell_text(mt.cell(0, 0), L["level"], bold=True)
        severity_cell(mt.cell(0, 1), f["severity"], L)
        shade(mt.cell(0, 2), HEAD_FILL)
        cell_text(mt.cell(0, 2), L["cvss"], bold=True)
        cell_text(mt.cell(0, 3), f["cvss_score"] or "—", mono=True, size=9)
        extra = [(L["status_l"], L["status"].get(f["status"], f["status"]), False)]
        if f["cvss_vector"]:
            extra.append((L["vector"], f["cvss_vector"], True))
        extra.append((L["assets"], f["assets"] or "—", True))
        for ri, (k, v, mono) in enumerate(extra, 1):
            shade(mt.cell(ri, 0), HEAD_FILL)
            cell_text(mt.cell(ri, 0), k, bold=True)
            merged = mt.cell(ri, 1).merge(mt.cell(ri, 3))
            cell_text(merged, v, mono=mono, size=8.5 if mono else 9.5)
        for key in ("description", "impact", "reproduction", "recommendation", "refs"):
            if f[key] and text_of(parse_html(f[key])).strip() or "<img" in (f[key] or ""):
                sub_label(doc, L["f_" + key])
                R.html(doc, f[key])

    # ------------------------------------------------------------ 5. conclusion
    heading(doc, L["s_concl"], "5.")
    R.html(doc, report["conclusion"])

    doc.core_properties.title = report["title"]
    doc.core_properties.subject = L["cover_kind"]
    doc.core_properties.author = report["authors"] or brand
    return doc


def _d(value):
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", value or "")
    return "%s.%s.%s" % (m.group(3), m.group(2), m.group(1)) if m else (value or "")
