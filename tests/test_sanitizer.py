import pytest

from models import Finding
from sanitizer import sanitize_finding

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
SECRETS = ["abc123SESSION", JWT, "hunter2", "admin@juice-sh.op", "xyzBEARER", "deadbeef" * 5, "sekret999"]


def planted():
    return Finding(
        finding_id="F1",
        title="Missing CSP header, cookie leak session=abc123SESSION",
        target="http://127.0.0.1:3000/x?token=sekret999, contact admin@juice-sh.op",
        evidence=(
            "Authorization: Bearer xyzBEARER\r\n"
            "Set-Cookie: sid=" + "deadbeef" * 5 + "\r\n"
            "password=hunter2\r\n"
            '{"jwt":"' + JWT + '"}'
        ),
        cwe_id="693",
    )


@pytest.mark.parametrize("secret", SECRETS)
def test_no_secret_survives(secret):
    f = sanitize_finding(planted())
    combined = f.title + f.target + f.evidence
    assert secret not in combined


def test_length_capped():
    f = Finding(finding_id="F1", title="x" * 5000, target="t", evidence="y")
    assert len(sanitize_finding(f).title) <= 300


def test_non_text_fields_untouched():
    f = planted()
    clean = sanitize_finding(f)
    assert clean.finding_id == f.finding_id
    assert clean.cwe_id == f.cwe_id
