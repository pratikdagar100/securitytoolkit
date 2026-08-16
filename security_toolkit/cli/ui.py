"""Terminal presentation helpers.

Professional, consistent output: findings are printed as structured blocks, not
a bare "VULNERABLE". Colour is used when the stream is a TTY.
"""
from __future__ import annotations

import os
import sys
from typing import Dict, List

from security_toolkit.core.models import Finding

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

_COLORS = {
    "CRITICAL": "\033[97;41m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
    "LOW": "\033[94m", "INFO": "\033[96m", "RESET": "\033[0m",
    "BOLD": "\033[1m", "DIM": "\033[2m", "GREEN": "\033[92m",
}


def c(text: str, key: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['RESET']}"


def banner() -> str:
    line = "=" * 52
    return (f"{c(line, 'DIM')}\n"
            f"        {c('SECURITY INVESTIGATION TOOLKIT', 'BOLD')}\n"
            f"        CyberShield Investigations Toolkit\n"
            f"{c(line, 'DIM')}")


def rule(char: str = "-", width: int = 52) -> str:
    return char * width


def print_finding(f: Finding) -> None:
    sev = f.severity
    print(c(rule(), "DIM"))
    print(f"{c('Finding:', 'BOLD')} {f.title}")
    print(c(rule(), "DIM"))
    print(f"\n{c('Target:', 'BOLD')}\n{f.target or 'n/a'}")
    print(f"\n{c('Severity:', 'BOLD')}\n{c(sev, sev)}")
    print(f"\n{c('Confidence:', 'BOLD')}\n{f.confidence}")
    if f.evidence:
        print(f"\n{c('Evidence:', 'BOLD')}\n{f.evidence}")
    if f.impact:
        print(f"\n{c('Impact:', 'BOLD')}\n{f.impact}")
    if f.recommendation:
        print(f"\n{c('Recommendation:', 'BOLD')}\n{f.recommendation}")
    if f.reference:
        print(f"\n{c('Reference:', 'BOLD')}\n{f.reference}")
    if f.case_id:
        print(f"\n{c('Case:', 'BOLD')}\n{f.case_id}")
    print(c(rule(), "DIM"))


def _render(value, indent: int, lines: List[str], max_items: int = 12) -> None:
    pad = "  " * indent
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{c(str(k), 'BOLD')}:")
                _render(v, indent + 1, lines, max_items)
            else:
                shown = v if not isinstance(v, (dict, list)) else "(empty)"
                lines.append(f"{pad}{c(str(k), 'BOLD')}: {str(shown)[:200]}")
    elif isinstance(value, list):
        for item in value[:max_items]:
            if isinstance(item, (dict, list)):
                _render(item, indent, lines, max_items)
                lines.append(f"{pad}{c('-', 'DIM')}")
            else:
                lines.append(f"{pad}- {str(item)[:200]}")
        if len(value) > max_items:
            lines.append(f"{pad}{c(f'... (+{len(value) - max_items} more)', 'DIM')}")
    else:
        lines.append(f"{pad}{str(value)[:200]}")


def print_collected(raw: Dict) -> None:
    """Show the raw information a module gathered (not just findings)."""
    if not raw:
        return
    # Keep the console readable: skip bulky internal blobs.
    skip = {"strings_sample", "processes"}
    visible = {k: v for k, v in raw.items() if k not in skip and v not in (None, "", [], {})}
    if not visible:
        return
    print("\n" + c(rule("="), "DIM"))
    print(c("COLLECTED INFORMATION", "BOLD"))
    print(c(rule("="), "DIM"))
    lines: List[str] = []
    _render(visible, 1, lines)
    print("\n".join(lines))
    # Note any large sections we intentionally summarized instead of dumping.
    if "processes" in raw:
        print(f"  {c('processes', 'BOLD')}: {raw.get('process_count', len(raw['processes']))} "
              f"(full list stored in the case evidence)")


def summarize(findings: List[Finding], scores: Dict) -> None:
    hist = scores["severity_histogram"]
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if hist.get(sev):
            parts.append(c(f"{hist[sev]} {sev}", sev))
    print("\n" + c(rule("="), "DIM"))
    print(c("SUMMARY", "BOLD"))
    print(c(rule("="), "DIM"))
    print("  " + "   ".join(parts) if parts else "  No findings.")
    print(f"  Risk Score:     {c(str(scores['risk_score']), 'HIGH')}/100")
    print(f"  Security Score: {c(str(scores['security_score']), 'GREEN')}/100")
    print(f"  Confidence:     {scores['confidence_score']}/100")
