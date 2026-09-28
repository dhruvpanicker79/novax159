"""Render a Markdown document as an academic paper PDF.

    python scripts/md_to_paper.py docs/10_RESEARCH_PAPER.md --out out/

This is the sibling of `md_to_pdf.py`. That one produces a clean technical
document with a sans face and coloured headings, which is right for the working
docs. This one reproduces the look of a LaTeX `article`: a Times serif face
throughout, a title page carrying the abstract and keywords, an automatically
generated table of contents with dotted leaders and real page numbers, numbered
headings taken verbatim from the source, a running header and a centred page
number. It exists because the research document has to match the format the
reference SIH submissions use.

Structure expected of the source (the front matter is everything before the
first horizontal rule):

    # Title
    ### Subtitle
    **Label:** value          <- one centred line each
    ---
    ## Abstract
    ...prose...
    **Keywords:** ...
    ---
    ## Contents              <- the manual list here is DISCARDED and replaced
    ...                         with a generated TOC
    ---
    # 1. First section

Two passes are required, because a table of contents cannot know page numbers
until the document has been laid out once. `BaseDocTemplate.multiBuild` handles
that; headings notify their page as they are drawn.

Fonts: a real Times TrueType face is registered when one can be found, because
the built-in Times-Roman is WinAnsi-encoded and has no glyph for the rupee sign
or arrows. Falls back to the built-in face and degrades those characters to
ASCII, exactly as `md_to_pdf.py` does.

Smart App Control note: importing `md_to_pdf` first is deliberate - it installs
the PIL stub that lets ReportLab import at all on these machines (ADR-0012).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import md_to_pdf as base  # noqa: E402  - installs the PIL stub on import

from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.pdfbase import pdfmetrics  # noqa: E402
from reportlab.pdfbase.ttfonts import TTFont  # noqa: E402
from reportlab.platypus import (  # noqa: E402
    BaseDocTemplate,
    Frame,
    HRFlowable,
    ListFlowable,
    ListItem,
    PageBreak,
    NextPageTemplate,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
)
from reportlab.platypus.tableofcontents import TableOfContents  # noqa: E402

INK = colors.HexColor("#000000")
MUTED = colors.HexColor("#333333")
RULE = colors.HexColor("#999999")
LINK = colors.HexColor("#0b3d91")

#: Serif families to try, best first. Times New Roman on Windows; the URW and
#: Liberation clones elsewhere. The reference document uses Nimbus Roman, which
#: is metrically the same face.
_SERIF_CANDIDATES = [
    ("TimesNewRoman", "times.ttf", "timesbd.ttf", "timesi.ttf", "timesbi.ttf"),
    ("LiberationSerif", "LiberationSerif-Regular.ttf", "LiberationSerif-Bold.ttf",
     "LiberationSerif-Italic.ttf", "LiberationSerif-BoldItalic.ttf"),
    ("DejaVuSerif", "DejaVuSerif.ttf", "DejaVuSerif-Bold.ttf",
     "DejaVuSerif-Italic.ttf", "DejaVuSerif-BoldItalic.ttf"),
    ("NimbusRoman", "NimbusRoman-Regular.otf", "NimbusRoman-Bold.otf",
     "NimbusRoman-Italic.otf", "NimbusRoman-BoldItalic.otf"),
]


def register_serif() -> None:
    """Point `md_to_pdf.FONTS` at a serif family so `inline()` agrees with us."""
    base.register_fonts()  # picks up a monospace face and sets the unicode flag
    mono = base.FONTS["mono"]

    for name, regular, bold, italic, bolditalic in _SERIF_CANDIDATES:
        paths = [base._find(f) for f in (regular, bold, italic, bolditalic)]
        if not paths[0] or not paths[1]:
            continue
        try:
            pdfmetrics.registerFont(TTFont(name, str(paths[0])))
            pdfmetrics.registerFont(TTFont(f"{name}-B", str(paths[1])))
            pdfmetrics.registerFont(TTFont(f"{name}-I", str(paths[2] or paths[0])))
            pdfmetrics.registerFont(TTFont(f"{name}-BI", str(paths[3] or paths[1])))
            pdfmetrics.registerFontFamily(
                name, normal=name, bold=f"{name}-B",
                italic=f"{name}-I", boldItalic=f"{name}-BI")
        except Exception:  # noqa: BLE001 - try the next family
            continue
        base.FONTS.update(sans=name, bold=f"{name}-B", italic=f"{name}-I",
                          bolditalic=f"{name}-BI", mono=mono, unicode=True)
        return

    # No TrueType serif anywhere: use the built-in Times and let inline()
    # degrade the characters it cannot draw.
    base.FONTS.update(sans="Times-Roman", bold="Times-Bold",
                      italic="Times-Italic", bolditalic="Times-BoldItalic",
                      mono=mono, unicode=False)


def build_styles() -> dict[str, ParagraphStyle]:
    register_serif()
    F = base.FONTS
    sheet = getSampleStyleSheet()
    s: dict[str, ParagraphStyle] = {}

    s["body"] = ParagraphStyle(
        "body", parent=sheet["Normal"], fontName=F["sans"], fontSize=10.5,
        leading=14.5, textColor=INK, alignment=TA_JUSTIFY, spaceAfter=8,
        firstLineIndent=0)

    # Headings: sizes follow LaTeX article at 10pt - \section 14.4pt,
    # \subsection 12pt, \subsubsection 10.95pt, all bold, flush left.
    s["h1"] = ParagraphStyle(
        "h1", parent=s["body"], fontName=F["bold"], fontSize=14.4, leading=18,
        spaceBefore=20, spaceAfter=9, alignment=TA_LEFT, keepWithNext=1)
    s["h2"] = ParagraphStyle(
        "h2", parent=s["body"], fontName=F["bold"], fontSize=12, leading=15,
        spaceBefore=14, spaceAfter=7, alignment=TA_LEFT, keepWithNext=1)
    s["h3"] = ParagraphStyle(
        "h3", parent=s["body"], fontName=F["bold"], fontSize=11, leading=14,
        spaceBefore=11, spaceAfter=5, alignment=TA_LEFT, keepWithNext=1)
    s["h4"] = ParagraphStyle(
        "h4", parent=s["body"], fontName=F["bolditalic"], fontSize=10.5,
        leading=13.5, spaceBefore=9, spaceAfter=4, alignment=TA_LEFT,
        keepWithNext=1)

    s["title"] = ParagraphStyle(
        "title", parent=s["body"], fontName=F["bold"], fontSize=19.5,
        leading=22.5, alignment=TA_CENTER, spaceBefore=2, spaceAfter=7)
    s["subtitle"] = ParagraphStyle(
        "subtitle", parent=s["body"], fontName=F["italic"], fontSize=12.5,
        leading=15, alignment=TA_CENTER, spaceAfter=12, textColor=MUTED)
    s["meta"] = ParagraphStyle(
        "meta", parent=s["body"], fontSize=10.2, leading=13,
        alignment=TA_CENTER, spaceAfter=2)
    s["abstracthead"] = ParagraphStyle(
        "abstracthead", parent=s["body"], fontName=F["bold"], fontSize=11,
        leading=14, alignment=TA_CENTER, spaceBefore=11, spaceAfter=6)
    s["abstract"] = ParagraphStyle(
        "abstract", parent=s["body"], fontSize=9, leading=11.4,
        leftIndent=10 * mm, rightIndent=10 * mm, alignment=TA_JUSTIFY,
        spaceAfter=6)
    s["keywords"] = ParagraphStyle(
        "keywords", parent=s["abstract"], spaceBefore=6)
    s["tochead"] = ParagraphStyle(
        "tochead", parent=s["body"], fontName=F["bold"], fontSize=14.4,
        leading=18, alignment=TA_LEFT, spaceBefore=0, spaceAfter=14)

    s["quote"] = ParagraphStyle(
        "quote", parent=s["body"], fontName=F["italic"], fontSize=10,
        leading=13.8, leftIndent=10 * mm, rightIndent=6 * mm,
        spaceBefore=7, spaceAfter=9, textColor=MUTED)
    s["code"] = ParagraphStyle(
        "code", parent=sheet["Code"], fontName=F["mono"], fontSize=8,
        leading=10.4, textColor=INK, backColor=colors.HexColor("#f4f4f4"),
        borderPadding=6, spaceBefore=6, spaceAfter=9)
    s["cell"] = ParagraphStyle(
        "cell", parent=s["body"], fontSize=8.6, leading=11.6, spaceAfter=0,
        alignment=TA_LEFT)
    s["cellhead"] = ParagraphStyle(
        "cellhead", parent=s["cell"], fontName=F["bold"])
    s["listitem"] = ParagraphStyle(
        "listitem", parent=s["body"], spaceAfter=3, alignment=TA_LEFT)

    # TOC levels: section, subsection, subsubsection.
    # `endDots` is what the TOC uses to draw the leader; the default is a
    # spaced dot, which reads as too loose next to a LaTeX document.
    s["toc0"] = ParagraphStyle(
        "toc0", parent=s["body"], fontName=F["bold"], fontSize=10.5,
        leading=15.5, spaceBefore=7, alignment=TA_LEFT, firstLineIndent=0,
        endDots=".")
    s["toc1"] = ParagraphStyle(
        "toc1", parent=s["body"], fontSize=10, leading=14, leftIndent=8 * mm,
        alignment=TA_LEFT, endDots=".")
    s["toc2"] = ParagraphStyle(
        "toc2", parent=s["body"], fontSize=9.6, leading=13.2,
        leftIndent=16 * mm, alignment=TA_LEFT, textColor=MUTED, endDots=".")
    return s


class Heading(Paragraph):
    """A heading that reports its page number to the table of contents."""

    def __init__(self, text: str, style: ParagraphStyle, level: int, plain: str):
        super().__init__(text, style)
        self.toc_level = level
        self.toc_text = plain


def _plain(text: str) -> str:
    """Strip inline markup so a heading reads cleanly in the contents."""
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\*(.+?)\*", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text.strip()


def parse_front_matter(lines: list[str], styles: dict) -> list:
    """Title, subtitle and the centred metadata block."""
    flow: list = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("### "):
            flow.append(Paragraph(base.inline(line[4:]), styles["subtitle"]))
        elif line.startswith("# "):
            flow.append(Paragraph(base.inline(line[2:]), styles["title"]))
        else:
            flow.append(Paragraph(base.inline(line), styles["meta"]))
    return flow


def parse_body(lines: list[str], styles: dict, width: float) -> list:
    """The block parser, adapted from md_to_pdf.parse for paper output.

    Differences: headings become `Heading` so they can notify the TOC, and
    there is no coloured rule under level-1 headings. Sections flow on rather
    than starting a new page, which is what LaTeX's article class does and what
    the reference document shows.
    """
    flow: list = []
    i, n = 0, len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("```"):
            i += 1
            block: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            if block:
                flow.append(Preformatted("\n".join(block), styles["code"]))
            continue

        if re.fullmatch(r"-{3,}|\*{3,}|_{3,}", stripped):
            i += 1
            continue  # section breaks are carried by the headings themselves

        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            level = len(heading.group(1))
            text = heading.group(2)
            key = {1: "h1", 2: "h2", 3: "h3"}.get(level, "h4")
            if level <= 3:
                flow.append(Heading(base.inline(text), styles[key],
                                    level - 1, _plain(text)))
            else:
                flow.append(Paragraph(base.inline(text), styles[key]))
            i += 1
            continue

        if "|" in stripped and i + 1 < n and re.fullmatch(
                r"\|?[\s:|-]+\|[\s:|-]*", lines[i + 1].strip()):
            rows = []
            while i < n and "|" in lines[i]:
                rows.append(lines[i])
                i += 1
            if len(rows) >= 2:
                flow.append(Spacer(1, 3))
                flow.append(base._table(rows, styles, width))
                flow.append(Spacer(1, 10))
            continue

        if stripped.startswith(">"):
            block = []
            while i < n and lines[i].strip().startswith(">"):
                block.append(lines[i].strip().lstrip(">").strip())
                i += 1
            flow.append(Paragraph(base.inline(" ".join(block)), styles["quote"]))
            continue

        if re.match(r"^\s*([-*+]|\d+\.)\s+", line):
            items = []
            ordered = bool(re.match(r"^\s*\d+\.", line))
            while i < n and re.match(r"^\s*([-*+]|\d+\.)\s+", lines[i]):
                text = re.sub(r"^\s*([-*+]|\d+\.)\s+", "", lines[i])
                i += 1
                while (i < n and lines[i].strip()
                       and not re.match(r"^\s*([-*+]|\d+\.)\s+", lines[i])
                       and not lines[i].strip().startswith(("#", "|", "```", ">"))):
                    text += " " + lines[i].strip()
                    i += 1
                items.append(ListItem(
                    Paragraph(base.inline(text), styles["listitem"]),
                    leftIndent=14))
            flow.append(ListFlowable(
                items, bulletType="1" if ordered else "bullet",
                bulletFontSize=8, bulletColor=INK, leftIndent=15,
                bulletOffsetY=1, spaceBefore=2, spaceAfter=9))
            continue

        if not stripped:
            i += 1
            continue

        block = []
        while (i < n and lines[i].strip()
               and not re.match(r"^(#{1,6})\s", lines[i].strip())
               and not lines[i].strip().startswith((">", "```"))
               and not re.match(r"^\s*([-*+]|\d+\.)\s+", lines[i])
               and not re.fullmatch(r"-{3,}|\*{3,}|_{3,}", lines[i].strip())):
            block.append(lines[i].strip())
            i += 1
        if block:
            flow.append(Paragraph(base.inline(" ".join(block)), styles["body"]))

    return flow


class PaperTemplate(BaseDocTemplate):
    """Two-pass document with a running header and a notifying TOC."""

    def __init__(self, path: str, header: str, **kwargs):
        super().__init__(path, pagesize=A4,
                         leftMargin=25 * mm, rightMargin=25 * mm,
                         topMargin=25 * mm, bottomMargin=22 * mm, **kwargs)
        self.header = header
        frame = Frame(self.leftMargin, self.bottomMargin,
                      self.width, self.height, id="body",
                      leftPadding=0, rightPadding=0,
                      topPadding=0, bottomPadding=0)
        self.addPageTemplates([
            PageTemplate(id="title", frames=[frame], onPage=self._title_page),
            PageTemplate(id="main", frames=[frame], onPage=self._page),
        ])

    def _number(self, canvas_obj) -> None:
        canvas_obj.setFont(base.FONTS["sans"], 10)
        canvas_obj.setFillColor(INK)
        canvas_obj.drawCentredString(A4[0] / 2, 13 * mm, str(canvas_obj.getPageNumber()))

    def _title_page(self, canvas_obj, _doc) -> None:
        canvas_obj.saveState()
        self._number(canvas_obj)
        canvas_obj.restoreState()

    def _page(self, canvas_obj, _doc) -> None:
        canvas_obj.saveState()
        canvas_obj.setFont(base.FONTS["sans"], 9)
        canvas_obj.setFillColor(MUTED)
        canvas_obj.drawString(25 * mm, A4[1] - 16 * mm, self.header)
        canvas_obj.setStrokeColor(RULE)
        canvas_obj.setLineWidth(0.4)
        canvas_obj.line(25 * mm, A4[1] - 18 * mm, A4[0] - 25 * mm, A4[1] - 18 * mm)
        self._number(canvas_obj)
        canvas_obj.restoreState()

    def afterFlowable(self, flowable) -> None:  # noqa: N802 - ReportLab's name
        if isinstance(flowable, Heading):
            self.notify("TOCEntry",
                        (flowable.toc_level, flowable.toc_text, self.page))


def split_source(markdown: str) -> tuple[list[str], list[str], list[str]]:
    """Return (front matter, abstract block, body) split on horizontal rules."""
    lines = markdown.replace("\r\n", "\n").split("\n")
    breaks = [i for i, line in enumerate(lines)
              if re.fullmatch(r"-{3,}", line.strip())]
    if len(breaks) < 3:
        return lines, [], []
    front = lines[:breaks[0]]
    abstract = lines[breaks[0] + 1:breaks[1]]
    # Everything after the (discarded) manual contents section.
    body = lines[breaks[2] + 1:]
    return front, abstract, body


def render(source: Path, target: Path, header: str) -> Path:
    markdown = source.read_text(encoding="utf-8")
    styles = build_styles()
    front, abstract, body = split_source(markdown)

    target.parent.mkdir(parents=True, exist_ok=True)
    title_match = re.search(r"^#\s+(.*)$", markdown, re.M)
    doc = PaperTemplate(
        str(target), header,
        title=_plain(title_match.group(1)) if title_match else source.stem,
        author="CyberKavach", subject="Smart India Hackathon 2026")

    flow: list = parse_front_matter(front, styles)

    # Fold hard-wrapped source lines back into paragraphs. Emitting one
    # Paragraph per source line leaves orphan words on their own justified
    # lines, which is what a first cut of this did.
    buffer: list[str] = []

    def flush(style: str = "abstract") -> None:
        if buffer:
            flow.append(Paragraph(base.inline(" ".join(buffer)), styles[style]))
            buffer.clear()

    keywords: list[str] = []
    for raw in abstract:
        line = raw.strip()
        if not line:
            flush()
            continue
        if line.startswith("## "):
            flush()
            flow.append(Paragraph(_plain(line[3:]), styles["abstracthead"]))
        elif line.startswith("**Keywords:**") or keywords:
            flush()
            keywords.append(line)
        else:
            buffer.append(line)
    flush()
    if keywords:
        flow.append(Paragraph(base.inline(" ".join(keywords)), styles["keywords"]))

    # Page 1 is the bare title page; every page after it carries the running
    # header, so switch templates before the first break.
    flow.append(NextPageTemplate("main"))
    flow.append(PageBreak())
    flow.append(Paragraph("Contents", styles["tochead"]))
    toc = TableOfContents()
    toc.levelStyles = [styles["toc0"], styles["toc1"], styles["toc2"]]
    toc.dotsMinLevel = 99  # built-in spaced leader off; styles carry endDots
    flow.append(toc)

    flow.extend(parse_body(body, styles, doc.width))

    doc.multiBuild(flow)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out"))
    parser.add_argument("--header", default="SIH 2026  CyberKavach")
    args = parser.parse_args()

    target = args.out / f"{args.source.stem}.pdf"
    render(args.source, target, args.header)
    print(f"  {args.source}  ->  {target}  "
          f"({target.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
