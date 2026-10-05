"""Server-rendered inline SVG charts.

Every chart here is driven by rows actually stored in the database — there are no
decorative or placeholder visualizations. Charts are emitted as inline SVG so the
dashboard stays self-contained (no CDN, no JavaScript charting library), which also
means it works on an air-gapped Kali box.

Colour policy
-------------
* **Severity** is an ordered *status* encoding, so it uses the reserved status palette
  and is always rendered beside its textual label — colour never carries the meaning
  alone.
* **Finding lifecycle** and **technology** are *categorical*, so they use the fixed
  categorical slot order (never cycled, never generated). The five-slot lifecycle
  palette was validated against this dashboard's surface (#171d26): lightness band,
  chroma floor, CVD separation, normal-vision floor and 3:1 contrast all pass.
* Series past the last slot fold into "Other" rather than inventing a hue.
* Grid and axes are recessive; marks are thin; only selective direct labels are drawn.

Each mark carries an SVG ``<title>`` so browsers show a native tooltip on hover,
and every chart is accompanied in the templates by the same data as a table.
"""
from __future__ import annotations

import html
from dataclasses import dataclass

# --- surfaces and ink (dark dashboard) ---
SURFACE = "#171d26"
INK_PRIMARY = "#e6edf3"
INK_SECONDARY = "#c3c2b7"
INK_MUTED = "#898781"
GRIDLINE = "#2c3340"
BASELINE = "#383f4b"

# --- status palette (reserved; never reused as a series colour) ---
STATUS = {
    "critical": "#d03b3b",
    "serious": "#ec835a",
    "warning": "#fab219",
    "good": "#0ca30c",
}

# Severity is ordered; it maps onto status plus one neutral for Informational.
SEVERITY_COLOR = {
    "Critical": STATUS["critical"],
    "High": STATUS["serious"],
    "Medium": STATUS["warning"],
    "Low": "#3987e5",
    "Informational": INK_MUTED,
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

# --- categorical slots, fixed order, validated for this surface ---
CATEGORICAL = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181",
               "#008300", "#9085e9", "#e66767"]
OTHER_COLOR = INK_MUTED

FONT = ('font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif"')


def _esc(text: str) -> str:
    return html.escape(str(text), quote=True)


def _svg(width: int, height: int, body: str, label: str) -> str:
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{_esc(label)}" '
            f'preserveAspectRatio="xMinYMin meet">{body}</svg>')


def empty_state(message: str = "no data yet") -> str:
    return (f'<div class="chart-empty">{_esc(message)}</div>')


# ---------------------------------------------------------------------------
# Severity bars — magnitude by ordered status category
# ---------------------------------------------------------------------------
def severity_bars(counts: dict[str, int], *, width: int = 420, row_h: int = 26) -> str:
    """Horizontal bars, one per severity, ordered most-severe first."""
    rows = [(s, counts.get(s, 0)) for s in SEVERITY_ORDER]
    if not any(v for _, v in rows):
        return empty_state("no findings recorded")

    label_w, value_w, pad = 96, 36, 6
    plot_w = width - label_w - value_w - pad
    height = row_h * len(rows) + 8
    maximum = max(v for _, v in rows) or 1
    parts: list[str] = []

    for i, (severity, value) in enumerate(rows):
        y = i * row_h + 4
        bar_h = 12
        bar_y = y + (row_h - bar_h) / 2 - 2
        colour = SEVERITY_COLOR[severity]
        bar_w = (value / maximum) * plot_w if value else 0
        parts.append(
            f'<text x="0" y="{bar_y + bar_h - 2}" {FONT} font-size="11" '
            f'fill="{INK_SECONDARY}">{_esc(severity)}</text>')
        if bar_w:
            parts.append(
                f'<rect x="{label_w}" y="{bar_y}" width="{bar_w:.1f}" height="{bar_h}" '
                f'rx="4" ry="4" fill="{colour}">'
                f'<title>{_esc(severity)}: {value} finding(s)</title></rect>')
        parts.append(
            f'<text x="{label_w + max(bar_w, 0) + pad:.1f}" y="{bar_y + bar_h - 2}" {FONT} '
            f'font-size="11" font-variant-numeric="tabular-nums" '
            f'fill="{INK_PRIMARY}">{value}</text>')

    total = sum(v for _, v in rows)
    return _svg(width, height, "".join(parts),
                f"Findings by severity, {total} total")


# ---------------------------------------------------------------------------
# Lifecycle donut — categorical identity
# ---------------------------------------------------------------------------
@dataclass
class Slice:
    label: str
    value: int
    color: str


def lifecycle_donut(counts: dict[str, int], *, size: int = 168) -> str:
    """Donut of finding-lifecycle states with a legend rendered by the template."""
    items = [(k, v) for k, v in counts.items() if v]
    if not items:
        return empty_state("no findings recorded")
    items.sort(key=lambda kv: -kv[1])
    slices = [Slice(k, v, CATEGORICAL[i] if i < len(CATEGORICAL) else OTHER_COLOR)
              for i, (k, v) in enumerate(items)]

    total = sum(s.value for s in slices)
    cx = cy = size / 2
    radius, stroke = size / 2 - 14, 18
    circumference = 2 * 3.141592653589793 * radius
    # 2px surface gap between adjacent segments.
    gap = 2.0
    offset = 0.0
    parts = [f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" '
             f'stroke="{GRIDLINE}" stroke-width="{stroke}"/>']
    for s in slices:
        length = circumference * (s.value / total)
        dash = max(length - gap, 0.5)
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="{s.color}" '
            f'stroke-width="{stroke}" stroke-dasharray="{dash:.2f} {circumference - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})">'
            f'<title>{_esc(s.label)}: {s.value} ({s.value / total:.0%})</title></circle>')
        offset += length
    parts.append(
        f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" {FONT} font-size="22" '
        f'font-weight="700" fill="{INK_PRIMARY}">{total}</text>')
    parts.append(
        f'<text x="{cx}" y="{cy + 14}" text-anchor="middle" {FONT} font-size="10" '
        f'fill="{INK_MUTED}">findings</text>')
    return _svg(size, size, "".join(parts), f"Finding lifecycle, {total} total")


def legend(counts: dict[str, int]) -> list[tuple[str, int, str]]:
    """(label, value, colour) triples so the template can render a real legend."""
    items = [(k, v) for k, v in counts.items() if v]
    items.sort(key=lambda kv: -kv[1])
    return [(k, v, CATEGORICAL[i] if i < len(CATEGORICAL) else OTHER_COLOR)
            for i, (k, v) in enumerate(items)]


# ---------------------------------------------------------------------------
# Posture gauge — a single headline number, banded
# ---------------------------------------------------------------------------
def posture_gauge(score: float | None, band: str, *, width: int = 260,
                  height: int = 104) -> str:
    """A hero figure with a banded track. Not a chart for its own sake."""
    if score is None:
        return empty_state("posture not computed")
    colour = {"Strong": STATUS["good"], "Adequate": "#3987e5",
              "Weak": STATUS["warning"], "Poor": STATUS["critical"]}.get(band, "#3987e5")
    track_y, track_h = height - 22, 8
    track_w = width - 8
    filled = track_w * max(0.0, min(1.0, score / 100))
    # Place the "/ 100" suffix past the headline number rather than at a fixed
    # offset, so 8.0 and 100.0 both read correctly.
    headline = f"{score:.1f}"
    headline_w = sum(10.0 if ch == "." else 20.4 for ch in headline)
    parts = [
        f'<text x="0" y="40" {FONT} font-size="34" font-weight="700" '
        f'fill="{INK_PRIMARY}">{headline}</text>',
        f'<text x="{headline_w + 7:.1f}" y="40" {FONT} font-size="13" '
        f'fill="{INK_MUTED}">/ 100</text>',
        f'<text x="0" y="60" {FONT} font-size="12" fill="{colour}">{_esc(band)}</text>',
        f'<rect x="0" y="{track_y}" width="{track_w}" height="{track_h}" rx="4" ry="4" '
        f'fill="{GRIDLINE}"/>',
        f'<rect x="0" y="{track_y}" width="{filled:.1f}" height="{track_h}" rx="4" ry="4" '
        f'fill="{colour}"><title>Velora Security Posture Score {score:.1f} of 100 '
        f'({_esc(band)})</title></rect>',
        f'<text x="0" y="{height - 2}" {FONT} font-size="9" fill="{INK_MUTED}">'
        f'Velora Security Posture Score — not CVSS</text>',
    ]
    return _svg(width, height, "".join(parts),
                f"Security posture {score:.1f} of 100, {band}")


# ---------------------------------------------------------------------------
# Scan-history sparkline — change over time, single series
# ---------------------------------------------------------------------------
def scan_sparkline(values: list[int], *, width: int = 300, height: int = 64,
                   label: str = "findings per scan") -> str:
    """A single-series line. No legend: the caption names the series."""
    if len(values) < 2:
        return empty_state("at least two scans are needed for a trend")
    pad = 6
    plot_w, plot_h = width - pad * 2, height - pad * 2 - 10
    lowest, highest = min(values), max(values)
    span = (highest - lowest) or 1
    step = plot_w / (len(values) - 1)

    points = []
    for i, value in enumerate(values):
        x = pad + i * step
        y = pad + plot_h - ((value - lowest) / span) * plot_h
        points.append((x, y))

    path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}"
                    for i, (x, y) in enumerate(points))
    area = (f"M{points[0][0]:.1f},{pad + plot_h:.1f} "
            + " ".join(f"L{x:.1f},{y:.1f}" for x, y in points)
            + f" L{points[-1][0]:.1f},{pad + plot_h:.1f} Z")
    parts = [
        f'<path d="{area}" fill="#3987e5" fill-opacity="0.14"/>',
        f'<path d="{path}" fill="none" stroke="#3987e5" stroke-width="2" '
        f'stroke-linejoin="round" stroke-linecap="round"/>',
    ]
    # Direct-label only the endpoints, never every point.
    for index in (0, len(values) - 1):
        x, y = points[index]
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="#3987e5" '
            f'stroke="{SURFACE}" stroke-width="2">'
            f'<title>scan {index + 1}: {values[index]} finding(s)</title></circle>')
    parts.append(
        f'<text x="{pad}" y="{height - 1}" {FONT} font-size="9" fill="{INK_MUTED}">'
        f'{_esc(label)} — oldest to newest</text>')
    parts.append(
        f'<text x="{width - pad}" y="{height - 1}" text-anchor="end" {FONT} font-size="9" '
        f'font-variant-numeric="tabular-nums" fill="{INK_SECONDARY}">'
        f'{values[0]} → {values[-1]}</text>')
    return _svg(width, height, "".join(parts), f"{label}: {values[0]} to {values[-1]}")


# ---------------------------------------------------------------------------
# Categorical bars — technology / category distribution
# ---------------------------------------------------------------------------
def category_bars(counts: dict[str, int], *, width: int = 420, row_h: int = 24,
                  max_slots: int = 6, label: str = "distribution") -> str:
    """Top-N categorical bars; everything past ``max_slots`` folds into 'Other'."""
    items = [(k, v) for k, v in counts.items() if v]
    if not items:
        return empty_state("nothing recorded")
    items.sort(key=lambda kv: -kv[1])
    head, tail = items[:max_slots], items[max_slots:]
    if tail:
        head.append(("Other", sum(v for _, v in tail)))

    label_w, value_w, pad = 132, 32, 6
    plot_w = width - label_w - value_w - pad
    height = row_h * len(head) + 6
    maximum = max(v for _, v in head) or 1
    parts: list[str] = []
    for i, (name, value) in enumerate(head):
        colour = OTHER_COLOR if name == "Other" else CATEGORICAL[i % len(CATEGORICAL)]
        bar_h = 11
        bar_y = i * row_h + (row_h - bar_h) / 2
        bar_w = (value / maximum) * plot_w
        # Keep the label inside its column so it never touches the bar.
        max_chars = max(6, int((label_w - 10) / 6.3))
        display = name if len(name) <= max_chars else name[: max_chars - 1] + "…"
        parts.append(
            f'<text x="0" y="{bar_y + bar_h - 1}" {FONT} font-size="11" '
            f'fill="{INK_SECONDARY}">{_esc(display)}</text>')
        parts.append(
            f'<rect x="{label_w}" y="{bar_y}" width="{max(bar_w, 1):.1f}" height="{bar_h}" '
            f'rx="4" ry="4" fill="{colour}">'
            f'<title>{_esc(name)}: {value}</title></rect>')
        parts.append(
            f'<text x="{label_w + bar_w + pad:.1f}" y="{bar_y + bar_h - 1}" {FONT} '
            f'font-size="11" font-variant-numeric="tabular-nums" '
            f'fill="{INK_PRIMARY}">{value}</text>')
    return _svg(width, height, "".join(parts), f"{label}, {len(head)} categories")


# ---------------------------------------------------------------------------
# Confidence / validation-status stacked bar — one row, categorical segments
# ---------------------------------------------------------------------------
def stacked_bar(counts: dict[str, int], *, width: int = 420, height: int = 30) -> str:
    """A single stacked row with a 2px surface gap between segments."""
    items = [(k, v) for k, v in counts.items() if v]
    if not items:
        return empty_state("nothing recorded")
    items.sort(key=lambda kv: -kv[1])
    total = sum(v for _, v in items)
    bar_h, gap = 14, 2
    x = 0.0
    parts: list[str] = []
    for i, (name, value) in enumerate(items):
        colour = CATEGORICAL[i % len(CATEGORICAL)]
        seg_w = (value / total) * width
        draw_w = max(seg_w - gap, 1)
        parts.append(
            f'<rect x="{x:.1f}" y="4" width="{draw_w:.1f}" height="{bar_h}" rx="3" ry="3" '
            f'fill="{colour}"><title>{_esc(name)}: {value} ({value / total:.0%})</title>'
            f'</rect>')
        x += seg_w
    parts.append(
        f'<text x="0" y="{height - 2}" {FONT} font-size="9" fill="{INK_MUTED}">'
        f'{total} total — see the table below for exact values</text>')
    return _svg(width, height, "".join(parts), f"Distribution across {len(items)} states")


# ---------------------------------------------------------------------------
# Score bars — one measure across categories, on a fixed 0..100 domain
# ---------------------------------------------------------------------------
def score_bars(scores: dict[str, float | None], *, width: int = 420,
               row_h: int = 26, label: str = "category scores") -> str:
    """Bars for a single measure, so every bar shares one hue.

    The domain is fixed at 0..100 — not rescaled to the observed maximum — because a
    posture score of 54 must not look like a full bar just because it is the highest
    one present. A category with no score renders as an explicit gap labelled
    "not assessed"; it is never drawn as zero and never as full.
    """
    if not scores:
        return empty_state("nothing scored")
    rows = sorted(scores.items(), key=lambda kv: (kv[1] is None, -(kv[1] or 0)))

    label_w, value_w, pad = 150, 44, 6
    plot_w = width - label_w - value_w - pad
    height = row_h * len(rows) + 14
    parts: list[str] = [
        # Recessive reference gridlines at the band boundaries.
        *[f'<line x1="{label_w + plot_w * frac:.1f}" y1="0" '
          f'x2="{label_w + plot_w * frac:.1f}" y2="{height - 14}" '
          f'stroke="{GRIDLINE}" stroke-width="1"/>' for frac in (0.5, 0.7, 0.85)],
    ]
    max_chars = max(6, int((label_w - 10) / 6.3))
    for i, (name, value) in enumerate(rows):
        bar_h = 12
        bar_y = i * row_h + (row_h - bar_h) / 2
        display = name if len(name) <= max_chars else name[: max_chars - 1] + "…"
        parts.append(
            f'<text x="0" y="{bar_y + bar_h - 2}" {FONT} font-size="11" '
            f'fill="{INK_SECONDARY}">{_esc(display)}</text>')
        if value is None:
            parts.append(
                f'<text x="{label_w}" y="{bar_y + bar_h - 2}" {FONT} font-size="11" '
                f'font-style="italic" fill="{INK_MUTED}">not assessed</text>')
            continue
        clamped = max(0.0, min(100.0, float(value)))
        # Same thresholds as velora.posture.band_for, so a bar's colour never
        # contradicts the band label shown beside it.
        colour = (STATUS["good"] if clamped >= 90 else "#3987e5" if clamped >= 75
                  else STATUS["warning"] if clamped >= 55 else STATUS["critical"])
        parts.append(
            f'<rect x="{label_w}" y="{bar_y}" width="{plot_w}" height="{bar_h}" '
            f'rx="4" ry="4" fill="{GRIDLINE}"/>')
        parts.append(
            f'<rect x="{label_w}" y="{bar_y}" width="{plot_w * clamped / 100:.1f}" '
            f'height="{bar_h}" rx="4" ry="4" fill="{colour}">'
            f'<title>{_esc(name)}: {clamped:.1f} of 100</title></rect>')
        parts.append(
            f'<text x="{width}" y="{bar_y + bar_h - 2}" text-anchor="end" {FONT} '
            f'font-size="11" font-variant-numeric="tabular-nums" '
            f'fill="{INK_PRIMARY}">{clamped:.1f}</text>')
    parts.append(
        f'<text x="{label_w}" y="{height - 2}" {FONT} font-size="9" fill="{INK_MUTED}">'
        f'0 — 100 (fixed scale); bands at 50 / 70 / 85</text>')
    return _svg(width, height, "".join(parts), f"{label}, {len(rows)} categories")
