# Architecture

```
                    SECURITY TOOLKIT
                           |
                    Unified CLI (cli/)
                           |
              +------------+-------------+
              |                          |
        Investigation              Assessment
       (recon, logs, host,      (network, web, api,
        file/malware)            sqli, xss, availability)
              |                          |
              +------------+-------------+
                           |
                  Module base + registry
                           |
        Authorization  ->  Target validation  ->  Risk/Finding engine
                           |
                    Evidence + Chain of custody
                           |
                    SQLite database (core/database.py)
                           |
              Report generation (json/csv/html/pdf)
```

## Core (`security_toolkit/core/`)

| File | Responsibility |
|---|---|
| `config.py` | merged config (defaults ← config.yaml ← env), secret resolution |
| `logger.py` | structured application / audit / error logs |
| `database.py` | SQLite schema + typed writers/readers |
| `models.py` | `Finding`, `Case`, `Target`, `Evidence`, `Event`, `ScanResult` |
| `risk_engine.py` | finding factory + Risk/Security/Confidence scoring |
| `target_validator.py` | classify + scope membership (IP/CIDR/domain/URL/file) |
| `authorization.py` | PASSIVE / ASSESSMENT / AUTHORIZED_LAB gate |
| `evidence.py` | hashing, evidence store, chain of custody |
| `case_manager.py` | `Workspace` + `CaseManager` |

## Data flow for one scan

1. CLI resolves a `Workspace` (config → dirs → DB → logging).
2. `AuthorizationContext` is built from the case's authorized scopes + flags.
3. The module calls `auth.authorize(...)` — denial raises before any network I/O.
4. The module produces a `ScanResult` of normalized `Finding`s.
5. Findings/events/scan are persisted; the raw result is stored as SHA-256'd
   evidence with a custody record.
6. `risk_engine.score()` aggregates; the reporter renders JSON/CSV/HTML/PDF.

## Extending

- **New module:** subclass `SecurityModule`, register in `modules/registry.py`.
- **New tool:** subclass `ToolAdapter` in `integrations/`, normalize its output.
- **Plugins:** expose an entry point in the `security_toolkit.modules` group.
```
