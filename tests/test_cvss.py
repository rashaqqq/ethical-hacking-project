from cvss import CVSSVector


def test_cvss_standard_vectors():
    v1 = CVSSVector("N", "L", "N", "N", "U", "H", "H", "H")
    score1, sev1 = v1.score()
    assert score1 == 9.8 and sev1 == "Critical"

    v2 = CVSSVector("N", "L", "N", "R", "C", "L", "L", "N")
    score2, sev2 = v2.score()
    assert score2 == 6.1 and sev2 == "Medium"

    v3 = CVSSVector("N", "L", "N", "N", "U", "N", "N", "N")
    score3, sev3 = v3.score()
    assert score3 == 0.0 and sev3 == "None"
