import math
from dataclasses import dataclass

AV_W = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_W = {"L": 0.77, "H": 0.44}
UI_W = {"N": 0.85, "R": 0.62}
CIA_W = {"N": 0.00, "L": 0.22, "H": 0.56}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(val: float) -> float:
    int_input = round(val * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


@dataclass
class CVSSVector:
    AV: str = "N"  # N, A, L, P
    AC: str = "L"  # L, H
    PR: str = "N"  # N, L, H
    UI: str = "R"  # N, R
    S: str = "U"   # U (Unchanged), C (Changed)
    C: str = "L"   # N, L, H (Confidentiality)
    I: str = "L"   # N, L, H (Integrity)
    A: str = "N"   # N, L, H (Availability)

    @classmethod
    def from_dict(cls, d: dict, fallback_sev: str = "medium") -> "CVSSVector":
        if not isinstance(d, dict):
            return cls.default_for_severity(fallback_sev)
        av = str(d.get("AV", "N")).upper()[:1]
        ac = str(d.get("AC", "L")).upper()[:1]
        pr = str(d.get("PR", "N")).upper()[:1]
        ui = str(d.get("UI", "R")).upper()[:1]
        s = str(d.get("S", "U")).upper()[:1]
        c = str(d.get("C", "L")).upper()[:1]
        i = str(d.get("I", "L")).upper()[:1]
        a = str(d.get("A", "N")).upper()[:1]
        return cls(
            AV=av if av in AV_W else "N",
            AC=ac if ac in AC_W else "L",
            PR=pr if pr in PR_U else "N",
            UI=ui if ui in UI_W else "R",
            S=s if s in ("U", "C") else "U",
            C=c if c in CIA_W else "L",
            I=i if i in CIA_W else "L",
            A=a if a in CIA_W else "N",
        )

    @classmethod
    def default_for_severity(cls, sev: str) -> "CVSSVector":
        s = (sev or "").lower()
        if s == "critical":
            return cls("N", "L", "N", "N", "C", "H", "H", "H")
        if s == "high":
            return cls("N", "L", "N", "N", "U", "H", "H", "N")
        if s == "low":
            return cls("N", "H", "L", "R", "U", "L", "N", "N")
        return cls("N", "L", "N", "R", "U", "L", "L", "N")

    def to_string(self) -> str:
        return f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"

    def score(self) -> tuple[float, str]:
        iss = 1.0 - ((1.0 - CIA_W[self.C]) * (1.0 - CIA_W[self.I]) * (1.0 - CIA_W[self.A]))
        if self.S == "U":
            impact = 6.42 * iss
            pr_w = PR_U[self.PR]
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            pr_w = PR_C[self.PR]

        exploitability = 8.22 * AV_W[self.AV] * AC_W[self.AC] * pr_w * UI_W[self.UI]
        if impact <= 0:
            base = 0.0
        elif self.S == "U":
            base = _roundup(min(impact + exploitability, 10.0))
        else:
            base = _roundup(min(1.08 * (impact + exploitability), 10.0))

        severity = (
            "Critical" if base >= 9.0 else
            "High" if base >= 7.0 else
            "Medium" if base >= 4.0 else
            "Low" if base > 0.0 else "None"
        )
        return base, severity
