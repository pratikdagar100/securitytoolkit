"""Report generator.

Assembles a full case report (case info, authorization scope, targets,
timeline, findings by category, evidence, risk assessment, recommendations) and
renders it to JSON, CSV, HTML and (optionally) PDF.
"""
from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from security_toolkit.core import risk_engine
from security_toolkit.core.models import Finding

try:
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors as _rl_colors
    _HAVE_REPORTLAB = True
except Exception:  # pragma: no cover
    _HAVE_REPORTLAB = False

SEVERITY_COLORS = {
    "CRITICAL": "#8b0000", "HIGH": "#c0392b", "MEDIUM": "#e67e22",
    "LOW": "#f1c40f", "INFO": "#3498db",
}


def build_report_data(case: Dict[str, Any], targets: List[Dict[str, Any]],
                      findings: List[Dict[str, Any]], events: List[Dict[str, Any]],
                      evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    finding_objs = [Finding(**{k: v for k, v in f.items()
                              if k in Finding.__dataclass_fields__}) for f in findings]
    scores = risk_engine.score(finding_objs)
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_category.setdefault(f.get("category", "OTHER"), []).append(f)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": case,
        "targets": targets,
        "authorized_scope": [t.get("scope") or t.get("value") for t in targets
                             if t.get("authorized")],
        "scores": scores,
        "findings": findings,
        "findings_by_category": by_category,
        "timeline": sorted(events, key=lambda e: e.get("timestamp", "")),
        "evidence": evidence,
    }


class Reporter:
    def __init__(self, data: Dict[str, Any]) -> None:
        self.data = data

    # -- JSON ------------------------------------------------------------
    def to_json(self, path: Path) -> Path:
        Path(path).write_text(json.dumps(self.data, indent=2, default=str), encoding="utf-8")
        return Path(path)

    # -- CSV -------------------------------------------------------------
    def to_csv(self, path: Path) -> Path:
        cols = ["finding_id", "severity", "confidence", "category", "module",
                "title", "target", "evidence", "recommendation", "timestamp"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for f in self.data["findings"]:
            writer.writerow(f)
        Path(path).write_text(buf.getvalue(), encoding="utf-8")
        return Path(path)

    # -- HTML ------------------------------------------------------------
    def to_html(self, path: Path) -> Path:
        d = self.data
        case = d["case"]
        s = d["scores"]
        hist = s["severity_histogram"]

        def esc(x: Any) -> str:
            return html.escape(str(x or ""))

        rows = []
        order = {sev: i for i, sev in enumerate(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])}
        for f in sorted(d["findings"], key=lambda x: order.get(x.get("severity"), 9)):
            color = SEVERITY_COLORS.get(f.get("severity"), "#666")
            rows.append(f"""
      <tr>
        <td><span class="pill" style="background:{color}">{esc(f.get('severity'))}</span></td>
        <td>{esc(f.get('confidence'))}</td>
        <td>{esc(f.get('category'))}</td>
        <td><strong>{esc(f.get('title'))}</strong><br><span class="muted">{esc(f.get('target'))}</span></td>
        <td>{esc(f.get('evidence'))}</td>
        <td>{esc(f.get('recommendation'))}</td>
      </tr>""")

        chips = " ".join(
            f'<span class="chip" style="border-color:{SEVERITY_COLORS[k]}">'
            f'<b style="color:{SEVERITY_COLORS[k]}">{v}</b> {k}</span>'
            for k, v in hist.items())

        timeline = "".join(
            f'<li><code>{esc(e.get("timestamp"))}</code> — '
            f'<b>{esc(e.get("category"))}</b> {esc(e.get("target"))} '
            f'<span class="muted">({esc(e.get("severity"))})</span> {esc(e.get("evidence"))}</li>'
            for e in d["timeline"]) or "<li class='muted'>No timeline events recorded.</li>"

        evidence_rows = "".join(
            f'<tr><td>{esc(ev.get("evidence_id"))}</td><td>{esc(ev.get("source"))}</td>'
            f'<td>{esc(ev.get("description"))}</td><td><code>{esc(ev.get("sha256"))[:20]}…</code></td></tr>'
            for ev in d["evidence"]) or '<tr><td colspan="4" class="muted">No evidence stored.</td></tr>'

        html_doc = f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Investigation Report — {esc(case.get('case_id'))}</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin:0;
        background:#0f1216; color:#e6e6e6; }}
 .wrap {{ max-width:1080px; margin:0 auto; padding:32px 20px 80px; }}
 h1 {{ font-size:1.6rem; margin:0 0 4px; }}
 h2 {{ margin-top:2rem; border-bottom:1px solid #2a2f37; padding-bottom:6px; }}
 .muted {{ color:#9aa4b2; }}
 .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin:18px 0; }}
 .card {{ background:#171b21; border:1px solid #262c35; border-radius:12px; padding:16px; }}
 .card .n {{ font-size:1.9rem; font-weight:700; }}
 table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:.9rem; }}
 th,td {{ text-align:left; padding:10px; border-bottom:1px solid #262c35; vertical-align:top; }}
 th {{ color:#9aa4b2; font-weight:600; }}
 .pill {{ color:#fff; padding:2px 8px; border-radius:20px; font-size:.75rem; font-weight:700; }}
 .chip {{ border:1px solid #333; border-radius:20px; padding:4px 10px; margin-right:6px; font-size:.8rem; }}
 code {{ background:#0b0e12; padding:1px 5px; border-radius:5px; }}
 ul {{ line-height:1.7; }}
</style></head><body><div class="wrap">
 <h1>Cyber Investigation Report</h1>
 <div class="muted">Case {esc(case.get('case_id'))} — {esc(case.get('name'))} · generated {esc(d['generated_at'])}</div>

 <h2>Executive Summary</h2>
 <div class="grid">
   <div class="card"><div class="muted">Risk Score</div><div class="n" style="color:#c0392b">{s['risk_score']}</div></div>
   <div class="card"><div class="muted">Security Score</div><div class="n" style="color:#27ae60">{s['security_score']}</div></div>
   <div class="card"><div class="muted">Confidence</div><div class="n">{s['confidence_score']}</div></div>
   <div class="card"><div class="muted">Findings</div><div class="n">{s['total_findings']}</div></div>
 </div>
 <div>{chips}</div>

 <h2>Case Information</h2>
 <table>
  <tr><th>Case ID</th><td>{esc(case.get('case_id'))}</td></tr>
  <tr><th>Name</th><td>{esc(case.get('name'))}</td></tr>
  <tr><th>Purpose</th><td>{esc(case.get('purpose'))}</td></tr>
  <tr><th>Authorized by</th><td>{esc(case.get('authorized_by'))}</td></tr>
  <tr><th>Status</th><td>{esc(case.get('status'))}</td></tr>
  <tr><th>Created</th><td>{esc(case.get('created_at'))} by {esc(case.get('created_by'))}</td></tr>
 </table>

 <h2>Authorization Scope</h2>
 <p class="muted">{esc(', '.join(d['authorized_scope']) or 'No explicitly authorized scope recorded.')}</p>

 <h2>Findings</h2>
 <table>
  <thead><tr><th>Severity</th><th>Confidence</th><th>Category</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead>
  <tbody>{''.join(rows) or '<tr><td colspan=6 class=muted>No findings.</td></tr>'}</tbody>
 </table>

 <h2>Timeline</h2>
 <ul>{timeline}</ul>

 <h2>Evidence</h2>
 <table><thead><tr><th>Evidence ID</th><th>Source</th><th>Description</th><th>SHA-256</th></tr></thead>
 <tbody>{evidence_rows}</tbody></table>

 <h2>Conclusion</h2>
 <p class="muted">This report was produced by the CyberShield Investigations Toolkit. Findings
 marked with lower confidence are indicators requiring analyst validation and must not be
 treated as confirmed compromise without corroborating evidence.</p>
</div></body></html>"""
        Path(path).write_text(html_doc, encoding="utf-8")
        return Path(path)

    # -- PDF -------------------------------------------------------------
    def to_pdf(self, path: Path) -> Path:
        if not _HAVE_REPORTLAB:
            raise RuntimeError("PDF export requires 'reportlab' (pip install reportlab)")
        d = self.data
        case = d["case"]
        s = d["scores"]
        doc = SimpleDocTemplate(str(path), pagesize=LETTER)
        styles = getSampleStyleSheet()
        story: List[Any] = []
        story.append(Paragraph("Cyber Investigation Report", styles["Title"]))
        story.append(Paragraph(f"Case {case.get('case_id')} — {case.get('name')}", styles["Heading2"]))
        story.append(Paragraph(f"Generated: {d['generated_at']}", styles["Normal"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            f"Risk Score: {s['risk_score']} &nbsp; Security Score: {s['security_score']} "
            f"&nbsp; Findings: {s['total_findings']}", styles["Normal"]))
        story.append(Spacer(1, 12))

        table_data = [["Severity", "Category", "Finding", "Target"]]
        order = {sev: i for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])}
        for f in sorted(d["findings"], key=lambda x: order.get(x.get("severity"), 9)):
            table_data.append([f.get("severity"), f.get("category"),
                               Paragraph(html.escape(str(f.get("title"))), styles["Normal"]),
                               f.get("target")])
        table = Table(table_data, colWidths=[60, 80, 240, 120])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _rl_colors.HexColor("#222b36")),
            ("TEXTCOLOR", (0, 0), (-1, 0), _rl_colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, _rl_colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(table)
        doc.build(story)
        return Path(path)
