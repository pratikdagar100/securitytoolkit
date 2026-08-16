# CyberShield Investigations Toolkit

A free, modular, cross-platform **cyber investigation & security-assessment platform**
for authorized security teams, investigators, blue teams, pentesters and students.

It behaves like a lightweight combination of **Reconnaissance + Vulnerability
Assessment + SOC Analysis + Digital Investigation + Evidence Management + Reporting**
— not a loose pile of hacking scripts. The core is responsible for orchestration,
authorization, normalization, evidence integrity, analysis and reporting; heavy
lifting is delegated to mature open-source tools (Nmap, Amass, Nuclei, YARA, …)
through pluggable adapters.

> ⚠️ **Authorized use only.** Every assessment/intrusive operation is gated by a
> case + scope + profile authorization layer that cannot be bypassed by a flag.
> Only test systems you own or are explicitly authorized to assess.

---

## Highlights

- **Unified CLI** — one `security-toolkit` command with an interactive menu *and*
  scriptable subcommands.
- **Case management** — cases, authorized targets/scope, notes, status.
- **Safety architecture** — `PASSIVE` / `ASSESSMENT` / `AUTHORIZED_LAB` profiles;
  intrusive work needs in-scope target + explicit confirmation.
- **Evidence engine + chain of custody** — SHA-256 hashing, tamper verification,
  immutable custody log.
- **Common finding & risk engine** — one schema for every module; Risk / Security /
  Confidence scores.
- **Reports** — JSON, CSV, HTML (and PDF with `reportlab`).
- **Cross-platform** — Windows / Linux / macOS (uses `pathlib`, `shutil.which`, `subprocess`).

### Modules

| Module | What it does | Class |
|---|---|---|
| `recon` | DNS, IP, reverse DNS, RDAP, TLS cert (passive) | native + optional Amass |
| `network` | host/service discovery, banners, risky-port findings | native TCP + optional Nmap |
| `web` | headers, TLS/expiry, cookies, CORS, CSP, robots, fingerprint | native |
| `sqli` | SQL injection **exposure** (safe error/differential analysis) | native |
| `xss` | reflected XSS **exposure** (reflection/context analysis) | native |
| `api` | methods, auth signalling, headers, CORS, rate-limit indicators | native |
| `availability` | latency/failure stats → NORMAL/DEGRADED/UNSTABLE/UNAVAILABLE | native |
| `logs` | mini-SIEM: brute-force, credential-stuffing, HTTP scanning | native |
| `host` | local processes, listening ports, users, config | native + optional psutil |
| `file` | hashes, entropy, strings, PE metadata, VirusTotal | native + optional pefile/VT |

Detection is always distinguished from confirmed compromise: lower-confidence
findings are labelled as indicators requiring analyst validation.

---

## Install

```bash
# From GitHub
pip install git+https://github.com/pratikdagar100/security-toolkit.git

# Or clone for development
git clone https://github.com/pratikdagar100/security-toolkit.git
cd security-toolkit
pip install -e .            # core (requests, PyYAML)
pip install -e .[full]      # + dnspython, psutil, pefile, reportlab
```

Requires Python 3.8+. Optional external tools (Nmap, Amass, Nuclei, YARA,
Metasploit, ZAP) are auto-detected on `PATH` and used when present.

---

## Quick start (the full investigation flow)

```bash
# 1. Create a case and define an AUTHORIZED target/scope
security-toolkit case create --name "Acme external review" --authorized-by "CISO"
security-toolkit case target --case CASE-2026-001 --target example.com --authorized

# 2. Passive recon (allowed in PASSIVE profile)
security-toolkit recon --case CASE-2026-001 --target example.com

# 3. Assessment-class checks (need in-scope target or --authorized)
security-toolkit web     --case CASE-2026-001 --target https://example.com --profile-auth ASSESSMENT
security-toolkit network --case CASE-2026-001 --target example.com --profile QUICK --profile-auth ASSESSMENT

# 4. Local / defensive analysis
security-toolkit logs --target ./auth.log
security-toolkit host
security-toolkit file --target ./suspicious.bin

# 5. Evidence + report
security-toolkit evidence list --case CASE-2026-001
security-toolkit report --case CASE-2026-001 --format html

# See external tool integration status
security-toolkit tools
```

Run with **no arguments** for the interactive menu:

```bash
security-toolkit
```

### Global flags

`--target` `--case` `--profile` `--profile-auth` `--authorized` `--yes`
`--timeout` `--output` `--format` `--config`

---

## Wordlists (SecLists)

The recommended source for passwords, subdomains and payload patterns is
[**SecLists**](https://github.com/danielmiessler/SecLists). Clone it and point the
config at it:

```bash
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
```

```yaml
# config.yaml
wordlists:
  seclists_path: /opt/SecLists
  subdomains: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
  common_passwords: /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
```

---

## Configuration & secrets

Generate a starter file: `security-toolkit config init`. API keys are **never**
stored in source — prefer environment variables:

```bash
export SECURITY_TOOLKIT_VIRUSTOTAL_API_KEY=...
export SECURITY_TOOLKIT_SHODAN_API_KEY=...
```

Workspace (cases, evidence, SQLite DB, logs) defaults to `~/.security_toolkit`.

---

## Development

```bash
pip install -e .[dev]
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/](docs/). Tests are network-free
and use synthetic logs / temp files — never run assessments against random public
sites in CI.

## License

MIT — see [LICENSE](LICENSE).
