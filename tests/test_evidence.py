from security_toolkit.core.evidence import sha256_bytes, file_hashes


def test_store_and_verify_roundtrip(workspace):
    case_id = "CASE-TEST-001"
    store = workspace.evidence_store(case_id)
    rec = store.store_bytes(case_id, b"hello evidence", source="unit-test",
                            description="sample blob")
    assert rec["sha256"] == sha256_bytes(b"hello evidence")
    assert store.verify(rec["evidence_id"]) is True

    # chain of custody recorded COLLECT + VERIFY
    custody = workspace.db.list_custody(case_id)
    actions = {c["action"] for c in custody}
    assert "COLLECT" in actions and "VERIFY" in actions


def test_verify_detects_tampering(workspace):
    case_id = "CASE-TEST-002"
    store = workspace.evidence_store(case_id)
    rec = store.store_json(case_id, {"k": "v"}, source="unit-test", description="json")
    # tamper
    from pathlib import Path
    Path(rec["path"]).write_text("tampered", encoding="utf-8")
    assert store.verify(rec["evidence_id"]) is False


def test_file_hashes(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    h = file_hashes(p)
    assert set(h) == {"md5", "sha1", "sha256"}
    assert h["sha256"] == sha256_bytes(b"abc")
