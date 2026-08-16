# Contributing

Thanks for helping improve the CyberShield Investigations Toolkit.

## Principles

1. **Authorized use only.** Never weaken or bypass the authorization layer
   (`security_toolkit/core/authorization.py`). Intrusive capabilities must remain
   gated behind `AUTHORIZED_LAB` + in-scope target + explicit confirmation.
2. **Detection ≠ confirmation.** Findings must carry honest severity/confidence
   and evidence. Do not fabricate vulnerabilities or claim an attack from symptoms.
3. **Normalize everything.** Every module returns a `ScanResult` of `Finding`
   objects via `risk_engine.make_finding`. External tools are wrapped by adapters
   in `integrations/` and converted to the common schema.
4. **Degrade gracefully.** Optional dependencies and external binaries must be
   optional; detect them and continue with reduced capability.
5. **Cross-platform.** Use `pathlib`, `shutil.which`, `subprocess`; no hard-coded
   paths.

## Adding a module

1. Subclass `SecurityModule` (see `modules/base.py`), set `name` / `description`
   / `operation_class`, implement `run(target, auth, **options) -> ScanResult`.
2. Call `auth.authorize(target, operation, operation_class)` first.
3. Register it in `modules/registry.py` (or ship it as a plugin via the
   `security_toolkit.modules` entry-point group).
4. Add a CLI subparser in `cli/main.py` if it needs bespoke flags.
5. Add network-free tests under `tests/`.

## Dev setup

```bash
pip install -e .[dev,full]
pytest
```

Please keep PRs focused, add tests, and include type hints and docstrings.
