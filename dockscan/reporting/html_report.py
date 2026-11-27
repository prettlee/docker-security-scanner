"""Self-contained interactive HTML security dashboard generator."""

from datetime import datetime, timezone
import html
from pathlib import Path
from typing import List, Union

from dockscan.models.finding import SEVERITY_ORDER, Finding, ScanReport


def _esc(value: object) -> str:
    """HTML-escape any dynamic value safely (including quotes)."""
    return html.escape(str(value), quote=True)


def _render_severity_bar(report: ScanReport) -> str:
    """Render a proportional horizontal bar chart for finding severities."""
    total = len(report.findings)
    if total == 0:
        return (
            '<div class="bar-track">'
            '<div class="bar-seg seg-pass" style="width:100%" title="Clean"></div>'
            "</div>"
        )

    counts = report.severity_counts()
    segments: List[str] = []
    for level in SEVERITY_ORDER:
        count = counts.get(level, 0)
        if count <= 0:
            continue
        pct = (count / total) * 100.0
        cls = f"seg-{level.lower()}"
        segments.append(
            f'<div class="bar-seg {cls}" style="width:{pct:.2f}%" '
            f'title="{_esc(level)}: {count}"></div>'
        )
    return f'<div class="bar-track">{"".join(segments)}</div>'


def _render_finding_card(finding: Finding) -> str:
    """Render a single Finding as an escaped, filterable HTML card."""
    sev_lower = finding.severity.lower()
    display_loc = finding.file_path or finding.location
    if finding.line_number is not None and finding.file_path:
        display_loc = f"{finding.file_path}:{finding.line_number}"

    score_str = (
        f"{finding.confidence_score:.2f}"
        if finding.confidence_score is not None
        else "N/A"
    )

    meta_items: List[str] = [
        f'<div class="meta-item"><span class="meta-label">Location</span><code>{_esc(display_loc)}</code></div>',
        f'<div class="meta-item"><span class="meta-label">Source</span><span>{_esc(finding.source)} ({_esc(finding.detector)})</span></div>',
        f'<div class="meta-item"><span class="meta-label">Confidence</span><span>{_esc(finding.confidence)} ({_esc(score_str)})</span></div>',
    ]
    if finding.package:
        meta_items.append(
            f'<div class="meta-item"><span class="meta-label">Package</span><code>{_esc(finding.package)}</code></div>'
        )
    if finding.detected_version:
        meta_items.append(
            f'<div class="meta-item"><span class="meta-label">Detected Version</span><code>{_esc(finding.detected_version)}</code></div>'
        )
    if finding.cve:
        meta_items.append(
            f'<div class="meta-item"><span class="meta-label">CVE / Advisory</span><code>{_esc(finding.cve)}</code></div>'
        )
    if finding.fixed_version:
        meta_items.append(
            f'<div class="meta-item"><span class="meta-label">Fixed Version</span><code>{_esc(finding.fixed_version)}</code></div>'
        )
    if (
        finding.redacted_secret
        and finding.redacted_secret != "(none)"
        and not finding.package
    ):
        meta_items.append(
            f'<div class="meta-item"><span class="meta-label">Evidence</span><code>{_esc(finding.redacted_secret)}</code></div>'
        )
    if finding.occurrences > 1:
        meta_items.append(
            f'<div class="meta-item"><span class="meta-label">Occurrences</span><span>{finding.occurrences}</span></div>'
        )

    search_blob = " ".join(
        [
            finding.rule_id,
            finding.title,
            finding.severity,
            finding.category,
            display_loc,
            finding.package or "",
            finding.cve or "",
            finding.description,
        ]
    ).lower()

    return (
        f'<article class="finding-card sev-border-{_esc(sev_lower)}" '
        f'data-severity="{_esc(sev_lower)}" '
        f'data-category="{_esc(finding.category.lower())}" '
        f'data-search="{_esc(search_blob)}">'
        '<div class="finding-header">'
        '<div class="finding-title-group">'
        f'<span class="badge badge-{_esc(sev_lower)}">{_esc(finding.severity.upper())}</span>'
        f'<span class="rule-pill">{_esc(finding.rule_id)}</span>'
        f'<span class="cat-pill">{_esc(finding.category)}</span>'
        f'<h3>{_esc(finding.title)}</h3>'
        "</div>"
        "</div>"
        f'<div class="meta-grid">{"".join(meta_items)}</div>'
        f'<p class="finding-desc">{_esc(finding.description)}</p>'
        f'<div class="remediation"><strong>Remediation:</strong> {_esc(finding.remediation)}</div>'
        "</article>"
    )


def format_html_report(report: ScanReport) -> str:
    """Render a self-contained interactive HTML dashboard for a `ScanReport`."""
    counts = report.severity_counts()
    categories = report.category_counts()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    warnings_html = ""
    if report.warnings:
        warning_items = "".join(
            f"<li>{_esc(w)}</li>" for w in report.warnings
        )
        warnings_html = (
            '<section class="warnings-box">'
            f"<strong>Warnings ({len(report.warnings)})</strong>"
            f"<ul>{warning_items}</ul>"
            "</section>"
        )

    category_options = "".join(
        f'<option value="{_esc(cat.lower())}">{_esc(cat)} ({count})</option>'
        for cat, count in sorted(categories.items())
    )

    if report.findings:
        findings_html = "".join(_render_finding_card(f) for f in report.findings)
    else:
        findings_html = (
            '<div class="empty-state">'
            "<h3>PASS — No security issues detected</h3>"
            "<p>No secrets, misconfigurations, or known vulnerabilities were found in this scan.</p>"
            "</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dockscan Security Report — {_esc(report.target)}</title>
  <style>
    :root {{
      --bg: #0b1020;
      --panel: #131a2e;
      --panel-alt: #1a233d;
      --border: #263252;
      --text: #e6ecf8;
      --muted: #9aa8c7;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #38bdf8;
      --pass: #22c55e;
      --accent: #6366f1;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .container {{ max-width: 1120px; margin: 0 auto; padding: 28px 20px 56px; }}
    header {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      margin-bottom: 24px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 18px;
    }}
    h1 {{ margin: 0 0 6px; font-size: 1.5rem; letter-spacing: 0.02em; }}
    .subtitle {{ color: var(--muted); font-size: 0.92rem; }}
    .subtitle code {{ color: var(--text); background: var(--panel-alt); padding: 2px 6px; border-radius: 4px; }}
    .stats-meta {{ text-align: right; color: var(--muted); font-size: 0.85rem; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 16px;
    }}
    .card-label {{ font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }}
    .card-value {{ font-size: 1.85rem; font-weight: 700; margin-top: 4px; }}
    .val-critical {{ color: var(--crit); }}
    .val-high {{ color: var(--high); }}
    .val-medium {{ color: var(--med); }}
    .val-low {{ color: var(--low); }}
    .bar-track {{
      display: flex;
      height: 10px;
      background: var(--panel);
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid var(--border);
      margin-bottom: 22px;
    }}
    .bar-seg {{ height: 100%; }}
    .seg-critical {{ background: var(--crit); }}
    .seg-high {{ background: var(--high); }}
    .seg-medium {{ background: var(--med); }}
    .seg-low {{ background: var(--low); }}
    .seg-pass {{ background: var(--pass); }}
    .warnings-box {{
      background: rgba(234, 179, 8, 0.12);
      border: 1px solid rgba(234, 179, 8, 0.45);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 20px;
      color: #fde68a;
    }}
    .warnings-box ul {{ margin: 6px 0 0 18px; padding: 0; }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 14px;
      margin-bottom: 18px;
    }}
    .filter-buttons {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .filter-btn {{
      background: var(--panel-alt);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 11px;
      font-size: 0.85rem;
      cursor: pointer;
    }}
    .filter-btn.active {{ background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 600; }}
    .filter-controls {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    input[type="search"], select {{
      background: var(--panel-alt);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 10px;
      font-size: 0.88rem;
    }}
    .findings-list {{ display: flex; flex-direction: column; gap: 14px; }}
    .finding-card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-left-width: 4px;
      border-radius: 10px;
      padding: 16px 18px;
    }}
    .sev-border-critical {{ border-left-color: var(--crit); }}
    .sev-border-high {{ border-left-color: var(--high); }}
    .sev-border-medium {{ border-left-color: var(--med); }}
    .sev-border-low {{ border-left-color: var(--low); }}
    .finding-title-group {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }}
    .finding-title-group h3 {{ margin: 0; font-size: 1.05rem; }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.74rem;
      font-weight: 700;
      letter-spacing: 0.04em;
    }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fdba74; }}
    .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: #fde047; }}
    .badge-low {{ background: rgba(56, 189, 248, 0.2); color: #7dd3fc; }}
    .rule-pill, .cat-pill {{
      font-size: 0.76rem;
      padding: 2px 7px;
      border-radius: 5px;
      background: var(--panel-alt);
      color: var(--muted);
      border: 1px solid var(--border);
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      margin: 12px 0;
      padding: 10px 12px;
      background: var(--panel-alt);
      border-radius: 8px;
      font-size: 0.86rem;
    }}
    .meta-label {{ display: block; color: var(--muted); font-size: 0.74rem; text-transform: uppercase; }}
    .meta-item code {{ word-break: break-all; color: #c7d2fe; }}
    .finding-desc {{ margin: 8px 0; color: var(--text); font-size: 0.92rem; }}
    .remediation {{
      font-size: 0.88rem;
      color: #bbf7d0;
      background: rgba(34, 197, 94, 0.08);
      border: 1px solid rgba(34, 197, 94, 0.25);
      border-radius: 6px;
      padding: 8px 10px;
    }}
    .empty-state {{
      background: var(--panel);
      border: 1px solid rgba(34, 197, 94, 0.4);
      border-radius: 10px;
      padding: 28px;
      text-align: center;
      color: #bbf7d0;
    }}
    .hidden {{ display: none !important; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>DOCKSCAN SECURITY REPORT</h1>
        <div class="subtitle">Target: <code>{_esc(report.target)}</code> &middot; Image ID: <code>{_esc(report.image_id or "(unknown)")}</code></div>
      </div>
      <div class="stats-meta">
        <div>Scanned: {report.layers_scanned} layer(s), {report.files_scanned} file(s), {report.packages_scanned} package(s)</div>
        <div>Generated: {_esc(generated_at)}</div>
      </div>
    </header>

    <section class="cards">
      <div class="card"><div class="card-label">Total Findings</div><div class="card-value">{len(report.findings)}</div></div>
      <div class="card"><div class="card-label">Critical</div><div class="card-value val-critical">{counts["Critical"]}</div></div>
      <div class="card"><div class="card-label">High</div><div class="card-value val-high">{counts["High"]}</div></div>
      <div class="card"><div class="card-label">Medium</div><div class="card-value val-medium">{counts["Medium"]}</div></div>
      <div class="card"><div class="card-label">Low</div><div class="card-value val-low">{counts["Low"]}</div></div>
    </section>

    {_render_severity_bar(report)}
    {warnings_html}

    <section class="toolbar">
      <div class="filter-buttons" id="sev-filters">
        <button class="filter-btn active" data-sev="all" type="button">All ({len(report.findings)})</button>
        <button class="filter-btn" data-sev="critical" type="button">Critical ({counts["Critical"]})</button>
        <button class="filter-btn" data-sev="high" type="button">High ({counts["High"]})</button>
        <button class="filter-btn" data-sev="medium" type="button">Medium ({counts["Medium"]})</button>
        <button class="filter-btn" data-sev="low" type="button">Low ({counts["Low"]})</button>
      </div>
      <div class="filter-controls">
        <select id="cat-filter" aria-label="Filter by category">
          <option value="all">All categories</option>
          {category_options}
        </select>
        <input id="search-input" type="search" placeholder="Filter rule, path, package, CVE...">
      </div>
    </section>

    <section class="findings-list" id="findings-list">
      {findings_html}
    </section>
  </div>

  <script>
    (function() {{
      var activeSev = "all";
      var catFilter = document.getElementById("cat-filter");
      var searchInput = document.getElementById("search-input");
      var buttons = document.querySelectorAll("#sev-filters .filter-btn");
      var cards = document.querySelectorAll(".finding-card");

      function applyFilters() {{
        var cat = catFilter ? catFilter.value : "all";
        var q = searchInput ? searchInput.value.trim().toLowerCase() : "";
        cards.forEach(function(card) {{
          var sevOk = activeSev === "all" || card.getAttribute("data-severity") === activeSev;
          var catOk = cat === "all" || card.getAttribute("data-category") === cat;
          var textOk = !q || (card.getAttribute("data-search") || "").indexOf(q) !== -1;
          card.classList.toggle("hidden", !(sevOk && catOk && textOk));
        }});
      }}

      buttons.forEach(function(btn) {{
        btn.addEventListener("click", function() {{
          buttons.forEach(function(b) {{ b.classList.remove("active"); }});
          btn.classList.add("active");
          activeSev = btn.getAttribute("data-sev") || "all";
          applyFilters();
        }});
      }});
      if (catFilter) catFilter.addEventListener("change", applyFilters);
      if (searchInput) searchInput.addEventListener("input", applyFilters);
    }})();
  </script>
</body>
</html>
"""


def write_html_report(report: ScanReport, output_path: Union[str, Path]) -> Path:
    """Write a self-contained HTML security dashboard to `output_path`."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(format_html_report(report), encoding="utf-8")
    return path
