from audit import AuditLog


def test_chain_and_tamper(tmp_path):
    a = AuditLog(str(tmp_path / "a.jsonl"))
    a.log("x", note="hello")
    a.log("y", note="world")
    assert a.verify()
    a.path.write_text(a.path.read_text(encoding="utf-8").replace("hello", "HACK"), encoding="utf-8")
    assert not a.verify()


def test_chain_survives_restart(tmp_path):
    p = str(tmp_path / "a.jsonl")
    AuditLog(p).log("one")
    AuditLog(p).log("two")
    assert AuditLog(p).verify()
