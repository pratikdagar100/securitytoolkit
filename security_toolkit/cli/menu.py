"""Interactive menu (the ``security-toolkit`` no-argument experience)."""
from __future__ import annotations

import time
from typing import Optional

from security_toolkit.core.authorization import AuthorizationContext, AuthorizationError, PROFILES
from security_toolkit.core.case_manager import Workspace, CaseManager
from security_toolkit.core.config import load_config
from security_toolkit.core import risk_engine
from security_toolkit.modules import registry
from security_toolkit.cli import ui

MENU = """
   #  Option                          What it does
 ---  ------------------------------  --------------------------------------------------
  1.  Case Management                 Create/list cases and mark which targets you may test
  2.  Reconnaissance / OSINT          Passively look up public info (DNS, IP, WHOIS, certificate)
  3.  Network Assessment              Find open ports and running services on a host/network
  4.  Website Security Assessment     Check a site's headers, HTTPS, cookies, CORS, TLS certificate
  5.  SQL Injection Exposure Check    Safely test URL parameters for signs of SQL injection
  6.  XSS Exposure Check              Safely test URL parameters for reflected cross-site scripting
  7.  API Security Assessment         Check an API's methods, auth, headers and rate limiting
  8.  Availability / DoS Symptom      Measure response time/failures to spot slowness (not an attack)
  9.  Log & SOC Analysis              Scan a log file for brute-force logins and scanning attempts
 10.  Host Security Assessment        Inspect THIS computer: processes, listening ports, users
 11.  Malware / File Triage           Safely examine a file (hashes, strings) without running it
 12.  Device Info (MAC lookup)        Identify a device from its MAC address (+ optional IP)
 13.  Evidence Management             List the evidence collected and stored for a case
 14.  Generate Report                 Build a JSON/CSV/HTML/PDF report for a case
 15.  External Tools Status           Show which optional tools (Nmap, Amass, ...) are installed
 16.  Configuration                   Show where your workspace and settings live
  0.  Exit                            Quit the toolkit
"""

MODULE_FOR_CHOICE = {
    "2": "recon", "3": "network", "4": "web", "5": "sqli", "6": "xss",
    "7": "api", "8": "availability", "9": "logs", "10": "host", "11": "file",
}


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val or default


def _confirm(prompt: str) -> bool:
    return input(f"\n{prompt} [y/N] ").strip().lower() in ("y", "yes")


def _run_choice(ws: Workspace, cm: CaseManager, module_name: str) -> None:
    default_target = "localhost" if module_name in ("host",) else ""
    target = _ask("Target (IP/CIDR/domain/URL/file)", default_target)
    if not target:
        print("No target provided."); return
    case_id = _ask("Case id (blank to skip persistence)")
    profile = _ask("Authorization profile (PASSIVE/ASSESSMENT/AUTHORIZED_LAB)", "PASSIVE").upper()
    if profile not in PROFILES:
        profile = "PASSIVE"
    scopes = cm.authorized_scopes(case_id) if case_id else []
    authorized = False
    if profile != "PASSIVE" and not scopes:
        authorized = _confirm("Target not in a recorded authorized scope. "
                               "Assert explicit authorization?")
    auth = AuthorizationContext(profile=profile, case_id=case_id, scopes=scopes,
                                authorized=authorized, user=ws.user, confirm=_confirm)
    cls = registry.get_module(module_name)
    module = cls(ws.config)
    try:
        result = module.run(target, auth)
    except AuthorizationError as exc:
        print(ui.c(f"\n[authorization denied] {exc}", "HIGH")); return
    except Exception as exc:
        print(ui.c(f"\n[error] {exc}", "HIGH")); return

    for f in result.findings:
        ui.print_finding(f)
    ui.print_collected(result.raw)
    ui.summarize(result.findings, risk_engine.score(result.findings))
    if result.errors:
        print("\nNotes:")
        for e in result.errors:
            print(f"  - {e}")
    if case_id:
        from security_toolkit.cli.main import _persist
        _persist(ws, case_id, result, module_name)
        print(ui.c(f"\nFindings + evidence saved to case {case_id}.", "GREEN"))


def _case_menu(cm: CaseManager) -> None:
    print("\n[a] create  [l] list  [t] add target  [s] show")
    action = input("Choice: ").strip().lower()
    if action == "a":
        name = _ask("Case name")
        case = cm.create_case(name, authorized_by=_ask("Authorized by"))
        print(ui.c(f"Created {case.case_id}", "GREEN"))
    elif action == "l":
        for c in cm.list_cases():
            print(f"  {c['case_id']}  [{c['status']}]  {c['name']}")
    elif action == "t":
        case_id = _ask("Case id")
        target = _ask("Target")
        authorized = _confirm("Mark as AUTHORIZED (in-scope)?")
        t = cm.add_target(case_id, target, authorized=authorized,
                          scope=_ask("Scope", target if authorized else ""))
        print(ui.c(f"Added {t.value} ({t.target_type})", "GREEN"))
    elif action == "s":
        case_id = _ask("Case id")
        c = cm.get_case(case_id)
        if c:
            for k, v in c.items():
                print(f"  {k}: {v}")


def _device_lookup(ws: Workspace, cm: CaseManager) -> None:
    mac = _ask("MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    if not mac:
        print("No MAC provided."); return
    ip = _ask("Device IP (optional, press Enter to skip)")
    case_id = _ask("Case id (blank to skip saving)")
    auth = AuthorizationContext(profile="PASSIVE", case_id=case_id, user=ws.user)
    module = registry.get_module("device")(ws.config)
    try:
        result = module.run(mac, auth, ip=ip or None)
    except Exception as exc:
        print(ui.c(f"\n[error] {exc}", "HIGH")); return
    for f in result.findings:
        ui.print_finding(f)
    ui.print_collected(result.raw)
    ui.summarize(result.findings, risk_engine.score(result.findings))
    if result.errors:
        print("\nNotes:")
        for e in result.errors:
            print(f"  - {e}")
    if case_id:
        from security_toolkit.cli.main import _persist
        _persist(ws, case_id, result, "device")
        print(ui.c(f"\nSaved to case {case_id}.", "GREEN"))


def interactive_menu(config_path: Optional[str] = None) -> int:
    ws = Workspace(load_config(config_path))
    cm = CaseManager(ws)
    print(ui.banner())
    try:
        while True:
            print(MENU)
            choice = input("Enter your choice: ").strip()
            if choice == "0":
                break
            elif choice == "1":
                _case_menu(cm)
            elif choice in MODULE_FOR_CHOICE:
                _run_choice(ws, cm, MODULE_FOR_CHOICE[choice])
            elif choice == "12":
                _device_lookup(ws, cm)
            elif choice == "13":
                case_id = _ask("Case id")
                for r in ws.db.list_evidence(case_id):
                    print(f"  {r['evidence_id']}  {r['source']}  {r['sha256'][:16]}…")
            elif choice == "14":
                from security_toolkit.reporting import build_report_data, Reporter
                case_id = _ask("Case id")
                case = cm.get_case(case_id)
                if not case:
                    print("Case not found."); continue
                data = build_report_data(case, cm.list_targets(case_id),
                                         ws.db.list_findings(case_id),
                                         ws.db.list_events(case_id),
                                         ws.db.list_evidence(case_id))
                out = ws.case_dir(case_id) / "reports" / f"{case_id}_report.html"
                out.parent.mkdir(parents=True, exist_ok=True)
                Reporter(data).to_html(out)
                print(ui.c(f"Report: {out}", "GREEN"))
            elif choice == "15":
                from security_toolkit.cli.main import cmd_tools
                import argparse
                cmd_tools(argparse.Namespace(config=config_path))
            elif choice == "16":
                print(f"  workspace: {ws.root}")
                print(f"  config:    {ws.config.source or '(defaults)'}")
            else:
                print("Invalid choice.")
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
    finally:
        ws.close()
    return 0
