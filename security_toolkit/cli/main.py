"""Unified CLI: interactive menu + scriptable subcommands.

Examples
--------
    security-toolkit case create --name "Acme review" --authorized-by "CISO"
    security-toolkit case target --case CASE-2026-001 --target example.com --authorized
    security-toolkit recon   --case CASE-2026-001 --target example.com
    security-toolkit network --case CASE-2026-001 --target scanme.nmap.org --profile QUICK
    security-toolkit web     --case CASE-2026-001 --target https://example.com
    security-toolkit logs    --target ./auth.log
    security-toolkit file    --target ./sample.bin
    security-toolkit report  --case CASE-2026-001 --format html

Authorization cannot be bypassed by a flag: assessment/intrusive operations
require an in-scope target (or explicit --authorized) and, for lab operations,
an interactive confirmation.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, List, Optional

from security_toolkit import __version__, __cli_name__
from security_toolkit.core.authorization import (
    AuthorizationContext, AuthorizationError, PASSIVE, ASSESSMENT, AUTHORIZED_LAB, PROFILES,
)
from security_toolkit.core.case_manager import Workspace, CaseManager
from security_toolkit.core.config import load_config
from security_toolkit.core.logger import audit
from security_toolkit.core.models import Finding
from security_toolkit.core import risk_engine
from security_toolkit.modules import registry
from security_toolkit.cli import ui


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _confirm(prompt: str) -> bool:
    try:
        return input(f"\n{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _build_auth(args: argparse.Namespace, cm: CaseManager) -> AuthorizationContext:
    scopes: List[str] = []
    case_id = getattr(args, "case", None) or ""
    if case_id:
        scopes = cm.authorized_scopes(case_id)
    profile = (getattr(args, "profile_auth", None) or PASSIVE).upper()
    confirm = (lambda p: True) if getattr(args, "yes", False) else _confirm
    return AuthorizationContext(
        profile=profile, case_id=case_id, scopes=scopes,
        authorized=getattr(args, "authorized", False),
        user=cm.ws.user, confirm=confirm,
    )


def _persist(ws: Workspace, case_id: str, result, module_name: str) -> None:
    for f in result.findings:
        f.case_id = f.case_id or case_id
        ws.db.save_finding(f.to_dict(), created_by=ws.user)
    for e in result.events:
        e.case_id = e.case_id or case_id
        ws.db.save_event(e.to_dict(), created_by=ws.user)
    ws.db.save_scan(case_id, module_name, result.target, result.profile,
                    result.to_dict(), created_by=ws.user, timestamp=result.started_at)
    if case_id:
        store = ws.evidence_store(case_id)
        store.store_json(case_id, result.to_dict(), source=f"module:{module_name}",
                         description=f"Raw {module_name} scan result for {result.target}")


def _emit(result, output: Optional[str], fmt: str) -> None:
    print("\n" + ui.banner())
    print(f"\nModule: {result.module}   Target: {result.target}   Profile: {result.profile}\n")
    for f in result.findings:
        ui.print_finding(f)
    scores = risk_engine.score(result.findings)
    ui.summarize(result.findings, scores)
    if result.errors:
        print("\n" + ui.c("Notes:", "DIM"))
        for err in result.errors:
            print(f"  - {err}")
    if output:
        import json
        Path(output).write_text(json.dumps(result.to_dict(), indent=2, default=str),
                                encoding="utf-8")
        print(f"\nRaw result written to {output}")


def _run_module(args: argparse.Namespace, module_name: str, **opts: Any) -> int:
    ws = Workspace(load_config(getattr(args, "config", None)))
    cm = CaseManager(ws)
    cls = registry.get_module(module_name)
    if cls is None:
        print(f"Unknown module: {module_name}", file=sys.stderr)
        return 2
    module = cls(ws.config)
    auth = _build_auth(args, cm)
    start = time.monotonic()
    try:
        result = module.run(args.target, auth, **opts)
    except AuthorizationError as exc:
        print(ui.c(f"\n[authorization denied] {exc}", "HIGH"), file=sys.stderr)
        audit(f"{module_name}.denied", case_id=auth.case_id, user=ws.user,
              module=module_name, target=getattr(args, "target", ""),
              status="DENIED", result=str(exc))
        ws.close()
        return 3
    except Exception as exc:  # keep the CLI robust
        print(ui.c(f"\n[error] {module_name}: {exc}", "HIGH"), file=sys.stderr)
        ws.close()
        return 1
    duration = round(time.monotonic() - start, 2)
    if auth.case_id:
        _persist(ws, auth.case_id, result, module_name)
    audit(f"{module_name}.run", case_id=auth.case_id, user=ws.user, module=module_name,
          target=result.target, status="OK", duration=duration,
          result=f"{len(result.findings)} findings")
    _emit(result, getattr(args, "output", None), getattr(args, "format", "json"))
    ws.close()
    return 0


# --------------------------------------------------------------------------- #
# Subcommand handlers
# --------------------------------------------------------------------------- #
def cmd_case(args: argparse.Namespace) -> int:
    ws = Workspace(load_config(args.config))
    cm = CaseManager(ws)
    action = args.case_action
    if action == "create":
        case = cm.create_case(args.name, purpose=args.purpose or
                              "Authorized security investigation",
                              authorized_by=args.authorized_by or "", notes=args.notes or "")
        print(ui.c("Case created:", "GREEN"))
        for k, v in case.to_dict().items():
            print(f"  {k:14}: {v}")
    elif action == "list":
        cases = cm.list_cases()
        if not cases:
            print("No cases yet. Create one with: security-toolkit case create --name ...")
        for cse in cases:
            print(f"  {cse['case_id']}  [{cse['status']:8}]  {cse['name']}")
    elif action == "show":
        cse = cm.get_case(args.case)
        if not cse:
            print("Case not found.", file=sys.stderr); ws.close(); return 2
        print(ui.c(f"Case {cse['case_id']} — {cse['name']}", "BOLD"))
        for k, v in cse.items():
            print(f"  {k:14}: {v}")
        print(ui.c("\nTargets:", "BOLD"))
        for t in cm.list_targets(args.case):
            flag = "AUTHORIZED" if t["authorized"] else "unauthorized"
            print(f"  {t['value']:30} {t['target_type']:8} [{flag}] scope={t['scope']}")
        findings = ws.db.list_findings(args.case)
        print(ui.c(f"\nFindings: {len(findings)}", "BOLD"))
    elif action == "target":
        t = cm.add_target(args.case, args.target, authorized=args.authorized,
                          scope=args.scope or "", notes=args.notes or "")
        print(ui.c("Target added:", "GREEN"))
        print(f"  {t.value}  ({t.target_type})  authorized={t.authorized}  scope={t.scope}")
    elif action == "status":
        ok = cm.set_status(args.case, args.value)
        print("Updated." if ok else "Case not found.")
    ws.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    ws = Workspace(load_config(args.config))
    cm = CaseManager(ws)
    case = cm.get_case(args.case)
    if not case:
        print("Case not found.", file=sys.stderr); ws.close(); return 2
    from security_toolkit.reporting import build_report_data, Reporter
    data = build_report_data(
        case, cm.list_targets(args.case), ws.db.list_findings(args.case),
        ws.db.list_events(args.case), ws.db.list_evidence(args.case))
    reporter = Reporter(data)
    out_dir = Path(args.output) if args.output else ws.case_dir(args.case) / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    fmt = (args.format or "html").lower()
    stem = out_dir / f"{args.case}_report"
    try:
        if fmt == "json":
            path = reporter.to_json(stem.with_suffix(".json"))
        elif fmt == "csv":
            path = reporter.to_csv(stem.with_suffix(".csv"))
        elif fmt == "pdf":
            path = reporter.to_pdf(stem.with_suffix(".pdf"))
        else:
            path = reporter.to_html(stem.with_suffix(".html"))
    except Exception as exc:
        print(ui.c(f"[error] report: {exc}", "HIGH"), file=sys.stderr); ws.close(); return 1
    print(ui.c(f"Report written: {path}", "GREEN"))
    print(f"  Risk score: {data['scores']['risk_score']}/100 · "
          f"{data['scores']['total_findings']} findings")
    ws.close()
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    ws = Workspace(load_config(args.config))
    if args.evidence_action == "list":
        rows = ws.db.list_evidence(args.case)
        if not rows:
            print("No evidence recorded for this case.")
        for r in rows:
            print(f"  {r['evidence_id']}  {r['source']:22}  {r['sha256'][:16]}…  {r['description']}")
    elif args.evidence_action == "verify":
        store = ws.evidence_store(args.case)
        for r in ws.db.list_evidence(args.case):
            ok = store.verify(r["evidence_id"])
            state = ui.c("PASS", "GREEN") if ok else ui.c("FAIL", "HIGH")
            print(f"  {r['evidence_id']}  {state}")
    elif args.evidence_action == "custody":
        for r in ws.db.list_custody(args.case):
            print(f"  {r['timestamp']}  {r['action']:8}  {r['evidence_id']}  by {r['user']}  {r['description']}")
    ws.close()
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    from security_toolkit.integrations.nmap import NmapAdapter
    from security_toolkit.integrations.amass import AmassAdapter
    from security_toolkit.integrations.nuclei import NucleiAdapter
    from security_toolkit.integrations.zap import ZapAdapter
    from security_toolkit.integrations.metasploit import MetasploitAdapter
    from security_toolkit.integrations.yara import YaraAdapter
    adapters = {
        "nmap": NmapAdapter(config), "amass": AmassAdapter(config),
        "nuclei": NucleiAdapter(config), "zap": ZapAdapter(config),
        "metasploit": MetasploitAdapter(config), "yara": YaraAdapter(config),
    }
    print(ui.c("External tool integrations:", "BOLD"))
    for name, adapter in adapters.items():
        if adapter.available():
            ver = adapter.version() or "unknown"
            print(f"  {name:12} {ui.c('INSTALLED', 'GREEN')}  version={ver}  ({adapter.path() or 'python-binding'})")
        else:
            print(f"  {name:12} {ui.c('not found', 'DIM')}")
    print(f"\n  VirusTotal API key: {'configured' if config.api_key('virustotal') else 'not set'}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    if args.config_action == "init":
        target = Path(args.output) if args.output else Path.cwd() / "config.yaml"
        example = Path(__file__).resolve().parents[2] / "config.example.yaml"
        if example.exists():
            target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            print(ui.c(f"Wrote starter config to {target}", "GREEN"))
        else:
            print("config.example.yaml not found in package root.", file=sys.stderr)
            return 1
    else:
        config = load_config(args.config)
        print(ui.c("Effective configuration:", "BOLD"))
        print(f"  source:    {config.source or '(defaults)'}")
        print(f"  workspace: {config.workspace}")
        print(f"  profile:   {config.get('profiles.default')}")
        print(f"  seclists:  {config.get('wordlists.seclists_path') or '(not set)'}")
    return 0


# --------------------------------------------------------------------------- #
# Argument parser
# --------------------------------------------------------------------------- #
def _add_scan_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--target", required=True, help="target IP/CIDR/domain/URL/file")
    p.add_argument("--case", help="case id to attach findings/evidence to")
    p.add_argument("--profile", dest="profile", help="scan profile (module-specific)")
    p.add_argument("--profile-auth", dest="profile_auth", choices=PROFILES,
                   help="authorization profile (default PASSIVE)")
    p.add_argument("--authorized", action="store_true",
                   help="assert explicit authorization for assessment operations")
    p.add_argument("--yes", action="store_true", help="auto-confirm lab prompts")
    p.add_argument("--timeout", type=int, help="request/scan timeout override")
    p.add_argument("--output", help="write raw JSON result to this path")
    p.add_argument("--format", default="json", help="output format hint")
    p.add_argument("--config", help="path to config.yaml")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=__cli_name__,
        description="CyberShield Investigations Toolkit — authorized security "
                    "investigation & assessment platform.")
    parser.add_argument("--version", action="version",
                        version=f"{__cli_name__} {__version__}")
    parser.add_argument("--config", help="path to config.yaml")
    sub = parser.add_subparsers(dest="command")

    # case
    pc = sub.add_parser("case", help="case management")
    csub = pc.add_subparsers(dest="case_action", required=True)
    cc = csub.add_parser("create"); cc.add_argument("--name", required=True)
    cc.add_argument("--purpose"); cc.add_argument("--authorized-by", dest="authorized_by")
    cc.add_argument("--notes")
    csub.add_parser("list")
    cs = csub.add_parser("show"); cs.add_argument("--case", required=True)
    ct = csub.add_parser("target")
    ct.add_argument("--case", required=True); ct.add_argument("--target", required=True)
    ct.add_argument("--authorized", action="store_true"); ct.add_argument("--scope")
    ct.add_argument("--notes")
    cst = csub.add_parser("status"); cst.add_argument("--case", required=True)
    cst.add_argument("--value", required=True, help="ACTIVE/CLOSED/SUSPENDED")

    # scan modules
    for name, help_text in [
        ("recon", "passive reconnaissance / OSINT"),
        ("network", "network host/service discovery"),
        ("web", "website security assessment"),
        ("api", "API security analysis"),
        ("sqli", "SQL injection exposure check"),
        ("xss", "reflected XSS exposure check"),
        ("availability", "availability / DoS symptom analysis"),
        ("logs", "log & SOC analysis (target = log file)"),
        ("host", "local device assessment (target optional)"),
        ("file", "malware / file triage (target = file)"),
    ]:
        sp = sub.add_parser(name, help=help_text)
        if name == "host":
            sp.add_argument("--target", default="localhost")
            sp.add_argument("--case"); sp.add_argument("--profile")
            sp.add_argument("--profile-auth", dest="profile_auth", choices=PROFILES)
            sp.add_argument("--authorized", action="store_true")
            sp.add_argument("--yes", action="store_true")
            sp.add_argument("--timeout", type=int); sp.add_argument("--output")
            sp.add_argument("--format", default="json"); sp.add_argument("--config")
        else:
            _add_scan_flags(sp)
        if name == "sqli" or name == "xss":
            sp.add_argument("--lab", action="store_true",
                           help="AUTHORIZED_LAB mode (requires --profile-auth AUTHORIZED_LAB)")

    # report / evidence / tools / config
    pr = sub.add_parser("report", help="generate a case report")
    pr.add_argument("--case", required=True)
    pr.add_argument("--format", default="html", help="json/csv/html/pdf")
    pr.add_argument("--output", help="output directory"); pr.add_argument("--config")

    pe = sub.add_parser("evidence", help="evidence management")
    esub = pe.add_subparsers(dest="evidence_action", required=True)
    for act in ("list", "verify", "custody"):
        ep = esub.add_parser(act); ep.add_argument("--case", required=True)
        ep.add_argument("--config")

    pt = sub.add_parser("tools", help="show external tool integration status")
    pt.add_argument("--config")

    pcfg = sub.add_parser("config", help="configuration")
    cfgsub = pcfg.add_subparsers(dest="config_action", required=True)
    cfgsub.add_parser("show").add_argument("--config")
    ci = cfgsub.add_parser("init"); ci.add_argument("--output"); ci.add_argument("--config")

    sub.add_parser("menu", help="interactive menu")
    return parser


SCAN_COMMANDS = {"recon", "network", "web", "api", "sqli", "xss",
                 "availability", "logs", "host", "file"}


def _dispatch(args: argparse.Namespace) -> int:
    cmd = args.command
    if cmd == "case":
        return cmd_case(args)
    if cmd == "report":
        return cmd_report(args)
    if cmd == "evidence":
        return cmd_evidence(args)
    if cmd == "tools":
        return cmd_tools(args)
    if cmd == "config":
        return cmd_config(args)
    if cmd in SCAN_COMMANDS:
        opts: dict = {}
        if getattr(args, "profile", None):
            opts["profile"] = args.profile
        if getattr(args, "lab", False):
            opts["lab"] = True
        return _run_module(args, args.command, **opts)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    registry.load_plugins()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command or args.command == "menu":
        from security_toolkit.cli.menu import interactive_menu
        return interactive_menu(getattr(args, "config", None))
    try:
        return _dispatch(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
