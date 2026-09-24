"""Render a Markdown document to PDF.

    python scripts/md_to_pdf.py docs/07_RELATED_WORK.md
    python scripts/md_to_pdf.py docs/*.md --out pdf/

Written because the team will need every document as a PDF for submission, and
because none of the usual paths work on these machines: Playwright is not
installed, `wkhtmltopdf` is not available, and Pandoc is not either.

Smart App Control note. Pillow's compiled `_imaging` extension is blocked on
the development machines (the same policy that blocks numpy and cryptography -
ADR-0012, ADR-0017). ReportLab imports PIL unconditionally even when only
drawing text, so this module installs a stub into `sys.modules` before
importing it. Nothing here renders images, so the stub is never exercised; if
someone later adds image support, this is the first thing that will need to go.

Supports the subset of Markdown the project documents actually use: ATX
headings, pipe tables, fenced code blocks, bullet and numbered lists,
blockquotes, horizontal rules, and inline bold / italic / code / links.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import types
from pathlib import Path


def _stub_pil() -> None:
    """Pre-empt `import PIL` so ReportLab loads without the blocked extension."""
    if "PIL" in sys.modules:
        return
    pil = types.ModuleType("PIL")
    image = types.ModuleType("PIL.Image")

    class _Image:  # noqa: D401 - placeholder only
        """Stand-in for PIL.Image. Never instantiated; we draw text only."""

    def _unavailable(*_args, **_kwargs):
        raise RuntimeError(
            "PIL is stubbed out: Smart App Control blocks its compiled extension. "
            "This renderer does not support images.")

    image.Image = _Image
    image.open = image.new = image.frombytes = _unavailable
    pil.Image = image
    # pypdf and others read PIL.__version__ during their own import, so the
    # stub has to carry one or it breaks unrelated libraries in the process.
    pil.__version__ = "0.0.0+securemailscope-stub"
    image.__version__ = pil.__version__
    sys.modules["PIL"] = pil
    sys.modules["PIL.Image"] = image


_stub_pil()

from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.platypus import (  # noqa: E402
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# --------------------------------------------------------------------------- #
# Palette
# --------------------------------------------------------------------------- #

INK = colors.HexColor("#16202e")
MUTED = colors.HexColor("#5b6675")
FAINT = colors.HexColor("#8c99ad")
ACCENT = colors.HexColor("#0f5fb5")
RULE = colors.HexColor("#d7dee8")
BAND = colors.HexColor("#eef3f9")
CODE_BG = colors.HexColor("#f4f6fa")


# --------------------------------------------------------------------------- #
# Fonts
# --------------------------------------------------------------------------- #

#: (regular, bold, italic, bold-italic) candidates, best first. The built-in
#: Helvetica cannot render em dashes, curly quotes or ellipses - they come out
#: as replacement boxes - so a TrueType face is registered when one is
#: available. Falls back cleanly on a machine with none of them.
_SANS_CANDIDATES = [
    ("Calibri", "calibri.ttf", "calibrib.ttf", "calibrii.ttf", "calibriz.ttf"),
    ("Arial", "arial.ttf", "arialbd.ttf", "ariali.ttf", "arialbi.ttf"),
    ("DejaVuSans", "DejaVuSans.ttf", "DejaVuSans-Bold.ttf",
     "DejaVuSans-Oblique.ttf", "DejaVuSans-BoldOblique.ttf"),
    ("LiberationSans", "LiberationSans-Regular.ttf", "LiberationSans-Bold.ttf",
     "LiberationSans-Italic.ttf", "LiberationSans-BoldItalic.ttf"),
]
_MONO_CANDIDATES = [
    ("Consolas", "consola.ttf"),
    ("CourierNew", "cour.ttf"),
    ("DejaVuSansMono", "DejaVuSansMono.ttf"),
    ("LiberationMono", "LiberationMono-Regular.ttf"),
]
_FONT_DIRS = [
    Path(r"C:\Windows\Fonts"),
    Path("/usr/share/fonts/truetype/dejavu"),
    Path("/usr/share/fonts/truetype/liberation"),
    Path("/usr/share/fonts"),
    Path("/Library/Fonts"),
]

FONTS = {"sans": "Helvetica", "bold": "Helvetica-Bold",
         "italic": "Helvetica-Oblique", "bolditalic": "Helvetica-BoldOblique",
         "mono": "Courier", "unicode": False}


def _find(filename: str) -> Path | None:
    for directory in _FONT_DIRS:
        candidate = directory / filename
        if candidate.exists():
            return candidate
    return None


def register_fonts() -> None:
    """Register a Unicode TrueType family if one can be found."""
    from reportlab.pdfbase import pdfmetrics  # noqa: PLC0415
    from reportlab.pdfbase.ttfonts import TTFont  # noqa: PLC0415

    for name, regular, bold, italic, bolditalic in _SANS_CANDIDATES:
        paths = [_find(f) for f in (regular, bold, italic, bolditalic)]
        if not paths[0] or not paths[1]:
            continue
        try:
            pdfmetrics.registerFont(TTFont(name, str(paths[0])))
            pdfmetrics.registerFont(TTFont(f"{name}-B", str(paths[1])))
            pdfmetrics.registerFont(TTFont(
                f"{name}-I", str(paths[2] or paths[0])))
            pdfmetrics.registerFont(TTFont(
                f"{name}-BI", str(paths[3] or paths[1])))
            pdfmetrics.registerFontFamily(
                name, normal=name, bold=f"{name}-B",
                italic=f"{name}-I", boldItalic=f"{name}-BI")
        except Exception:  # noqa: BLE001 - try the next family
            continue
        FONTS.update(sans=name, bold=f"{name}-B", italic=f"{name}-I",
                     bolditalic=f"{name}-BI", unicode=True)
        break

    for name, filename in _MONO_CANDIDATES:
        path = _find(filename)
        if not path:
            continue
        try:
            pdfmetrics.registerFont(TTFont(name, str(path)))
        except Exception:  # noqa: BLE001
            continue
        FONTS["mono"] = name
        break


def build_styles() -> dict[str, ParagraphStyle]:
    register_fonts()
    base = getSampleStyleSheet()
    s: dict[str, ParagraphStyle] = {}
    s["body"] = ParagraphStyle(
        "body", parent=base["Normal"], fontName=FONTS["sans"], fontSize=9.5,
        leading=14.2, textColor=INK, alignment=TA_JUSTIFY, spaceAfter=7)
    s["h1"] = ParagraphStyle(
        "h1", parent=s["body"], fontName=FONTS["bold"], fontSize=19, leading=23,
        textColor=INK, spaceBefore=4, spaceAfter=10, alignment=TA_LEFT)
    s["h2"] = ParagraphStyle(
        "h2", parent=s["body"], fontName=FONTS["bold"], fontSize=13.5, leading=17,
        textColor=INK, spaceBefore=17, spaceAfter=7, alignment=TA_LEFT)
    s["h3"] = ParagraphStyle(
        "h3", parent=s["body"], fontName=FONTS["bold"], fontSize=11, leading=14,
        textColor=ACCENT, spaceBefore=12, spaceAfter=5, alignment=TA_LEFT)
    s["h4"] = ParagraphStyle(
        "h4", parent=s["body"], fontName=FONTS["bolditalic"], fontSize=9.8,
        leading=13, textColor=MUTED, spaceBefore=9, spaceAfter=4, alignment=TA_LEFT)
    s["quote"] = ParagraphStyle(
        "quote", parent=s["body"], fontName=FONTS["italic"], fontSize=9.5,
        leading=14, textColor=MUTED, leftIndent=11, borderColor=ACCENT,
        borderWidth=0, spaceBefore=6, spaceAfter=8)
    s["code"] = ParagraphStyle(
        "code", parent=base["Code"], fontName=FONTS["mono"], fontSize=8.2, leading=11,
        textColor=INK, backColor=CODE_BG, borderPadding=6, leftIndent=2,
        spaceBefore=5, spaceAfter=8)
    s["cell"] = ParagraphStyle(
        "cell", parent=s["body"], fontSize=8.3, leading=11.4, spaceAfter=0,
        alignment=TA_LEFT)
    s["cellhead"] = ParagraphStyle(
        "cellhead", parent=s["cell"], fontName=FONTS["bold"], textColor=INK)
    s["listitem"] = ParagraphStyle(
        "listitem", parent=s["body"], spaceAfter=3, alignment=TA_LEFT)
    return s


# --------------------------------------------------------------------------- #
# Inline markdown
# --------------------------------------------------------------------------- #

_CODE_SPAN = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*(.+?)\*\*", re.S)
_ITALIC = re.compile(r"(?<![\*\w])\*(?!\s)(.+?)(?<!\s)\*(?!\*)", re.S)
_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def inline(text: str) -> str:
    """Convert inline Markdown into ReportLab's mini-HTML."""
    placeholders: list[str] = []

    def stash(match: re.Match) -> str:
        placeholders.append(html.escape(match.group(1)))
        return f"\x00{len(placeholders) - 1}\x00"

    text = _CODE_SPAN.sub(stash, text)
    text = html.escape(text)
    text = _LINK.sub(
        lambda m: f'<link href="{html.escape(m.group(2), quote=True)}" '
                  f'color="#0f5fb5">{m.group(1)}</link>', text)
    text = _BOLD.sub(r"<b>\1</b>", text)
    text = _ITALIC.sub(r"<i>\1</i>", text)
    if not FONTS["unicode"]:
        # Built-in Helvetica has no glyph for these; render them as boxes and
        # the document looks broken. Degrade to ASCII instead.
        for fancy, plain in (("—", "-"), ("–", "-"), ("…", "..."),
                             ("“", '"'), ("”", '"'),
                             ("‘", "'"), ("’", "'")):
            text = text.replace(fancy, plain)

    for index, code in enumerate(placeholders):
        text = text.replace(
            f"\x00{index}\x00",
            f'<font face="{FONTS["mono"]}" size="8.6" color="#243447">{code}</font>')
    return text


# --------------------------------------------------------------------------- #
# Block parsing
# --------------------------------------------------------------------------- #


def _table(rows: list[str], styles: dict[str, ParagraphStyle], width: float):
    """Build a Table from Markdown pipe rows (header, separator, body...)."""
    def cells(line: str) -> list[str]:
        line = line.strip()
        if line.startswith("|"):
            line = line[1:]
        if line.endswith("|"):
            line = line[:-1]
        return [c.strip() for c in line.split("|")]

    header = cells(rows[0])
    body = [cells(r) for r in rows[2:] if r.strip()]
    columns = len(header)
    body = [r + [""] * (columns - len(r)) if len(r) < columns else r[:columns]
            for r in body]

    data = [[Paragraph(inline(c), styles["cellhead"]) for c in header]]
    data += [[Paragraph(inline(c), styles["cell"]) for c in row] for row in body]

    # Give the first column more room; it is almost always the label column.
    if columns == 1:
        widths = [width]
    else:
        first = width * min(0.42, max(0.22, 1.6 / columns))
        rest = (width - first) / (columns - 1)
        widths = [first] + [rest] * (columns - 1)

    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BAND),
        ("LINEBELOW", (0, 0), (-1, 0), 0.7, RULE),
        ("LINEBELOW", (0, 1), (-1, -2), 0.3, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafbfd")]),
    ]))
    return table


def parse(markdown: str, styles: dict[str, ParagraphStyle], width: float) -> list:
    flow: list = []
    lines = markdown.replace("\r\n", "\n").split("\n")
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # fenced code
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

        # horizontal rule
        if re.fullmatch(r"-{3,}|\*{3,}|_{3,}", stripped):
            flow.append(Spacer(1, 5))
            flow.append(HRFlowable(width="100%", thickness=0.6, color=RULE,
                                   spaceBefore=0, spaceAfter=9))
            i += 1
            continue

        # headings
        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            level = len(heading.group(1))
            key = {1: "h1", 2: "h2", 3: "h3"}.get(level, "h4")
            flow.append(Paragraph(inline(heading.group(2)), styles[key]))
            if level == 1:
                flow.append(HRFlowable(width="100%", thickness=1.1, color=ACCENT,
                                       spaceBefore=1, spaceAfter=11))
            i += 1
            continue

        # table
        if "|" in stripped and i + 1 < n and re.fullmatch(
                r"\|?[\s:|-]+\|[\s:|-]*", lines[i + 1].strip()):
            rows = []
            while i < n and "|" in lines[i]:
                rows.append(lines[i])
                i += 1
            if len(rows) >= 2:
                flow.append(Spacer(1, 3))
                flow.append(_table(rows, styles, width))
                flow.append(Spacer(1, 9))
            continue

        # blockquote
        if stripped.startswith(">"):
            block = []
            while i < n and lines[i].strip().startswith(">"):
                block.append(lines[i].strip().lstrip(">").strip())
                i += 1
            flow.append(Paragraph(inline(" ".join(block)), styles["quote"]))
            continue

        # lists
        if re.match(r"^\s*([-*+]|\d+\.)\s+", line):
            items = []
            ordered = bool(re.match(r"^\s*\d+\.", line))
            while i < n and re.match(r"^\s*([-*+]|\d+\.)\s+", lines[i]):
                text = re.sub(r"^\s*([-*+]|\d+\.)\s+", "", lines[i])
                i += 1
                # fold continuation lines
                while (i < n and lines[i].strip()
                       and not re.match(r"^\s*([-*+]|\d+\.)\s+", lines[i])
                       and not lines[i].strip().startswith(("#", "|", "```", ">"))):
                    text += " " + lines[i].strip()
                    i += 1
                items.append(ListItem(Paragraph(inline(text), styles["listitem"]),
                                      leftIndent=14))
            flow.append(ListFlowable(
                items, bulletType="1" if ordered else "bullet",
                bulletFontSize=7.5, bulletColor=ACCENT, leftIndent=15,
                bulletOffsetY=1, spaceBefore=2, spaceAfter=8))
            continue

        # blank
        if not stripped:
            i += 1
            continue

        # paragraph
        block = []
        while (i < n and lines[i].strip()
               and not re.match(r"^(#{1,6})\s", lines[i].strip())
               and not lines[i].strip().startswith((">", "```"))
               and not re.match(r"^\s*([-*+]|\d+\.)\s+", lines[i])
               and not re.fullmatch(r"-{3,}|\*{3,}|_{3,}", lines[i].strip())):
            block.append(lines[i].strip())
            i += 1
        if block:
            flow.append(Paragraph(inline(" ".join(block)), styles["body"]))

    return flow


# --------------------------------------------------------------------------- #
# Page furniture
# --------------------------------------------------------------------------- #


def make_decorator(title: str, subtitle: str):
    def decorate(canvas_obj, doc):
        canvas_obj.saveState()
        width, height = A4

        canvas_obj.setFont(FONTS["bold"], 7.5)
        canvas_obj.setFillColor(FAINT)
        canvas_obj.drawString(20 * mm, height - 12 * mm, title.upper())
        if subtitle:
            canvas_obj.setFont(FONTS["sans"], 7.5)
            canvas_obj.drawRightString(width - 20 * mm, height - 12 * mm, subtitle)
        canvas_obj.setStrokeColor(RULE)
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(20 * mm, height - 14 * mm, width - 20 * mm, height - 14 * mm)

        canvas_obj.line(20 * mm, 14 * mm, width - 20 * mm, 14 * mm)
        canvas_obj.setFont(FONTS["sans"], 7.5)
        canvas_obj.setFillColor(FAINT)
        canvas_obj.drawString(20 * mm, 9.5 * mm, "SecureMailScope")
        canvas_obj.drawRightString(width - 20 * mm, 9.5 * mm, f"Page {doc.page}")
        canvas_obj.restoreState()

    return decorate


def render(source: Path, target: Path, title: str | None = None,
           subtitle: str = "") -> Path:
    markdown = source.read_text(encoding="utf-8")

    if title is None:
        first = re.search(r"^#\s+(.*)$", markdown, re.M)
        title = first.group(1).strip() if first else source.stem
    title = re.sub(r"^\d+\s*[—-]\s*", "", title)

    target.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(target), pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=20 * mm, bottomMargin=20 * mm,
        title=title, author="SecureMailScope",
        subject="Smart India Hackathon 2026")

    styles = build_styles()
    flow = parse(markdown, styles, doc.width)
    decorate = make_decorator(title, subtitle)
    doc.build(flow, onFirstPage=decorate, onLaterPages=decorate)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("pdf"))
    parser.add_argument("--subtitle", default="Smart India Hackathon 2026")
    args = parser.parse_args()

    written: set[Path] = set()
    for source in args.sources:
        if not source.exists():
            print(f"  skipped (missing): {source}")
            continue
        target = args.out / f"{source.stem}.pdf"
        # docs/README.md and testbed/README.md share a stem; without this the
        # second silently overwrites the first.
        if target in written:
            parent = source.resolve().parent.name
            target = args.out / f"{parent}-{source.stem}.pdf"
        written.add(target)
        render(source, target, subtitle=args.subtitle)
        print(f"  {source}  ->  {target}  ({target.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
