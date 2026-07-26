from app import risk_score


def test_no_findings_is_tier_nenhum():
    result = risk_score.compute({}, 0)
    assert result == {"score": 0, "tier": "Nenhum", "reason": None}


def test_score_thresholds_without_critical():
    assert risk_score.compute({"low": 5}, 0)["tier"] == "Baixo"  # score 5
    assert risk_score.compute({"medium": 5}, 0)["tier"] == "Médio"  # score 10
    assert risk_score.compute({"high": 5}, 0)["tier"] == "Alto"  # score 25


def test_wpscan_vulnerabilities_count_toward_score():
    result = risk_score.compute({}, 2)  # 2 * WPSCAN_VULN_WEIGHT (5) = 10
    assert result["score"] == 10
    assert result["tier"] == "Médio"


def test_single_critical_finding_floors_tier_at_alto():
    # score 10 sozinho seria "Médio" — 1 achado crítico não pode ficar
    # escondido atrás desse rótulo.
    result = risk_score.compute({"critical": 1}, 0)
    assert result["score"] == 10
    assert result["tier"] == "Alto"
    assert result["reason"] is not None


def test_three_or_more_criticals_floors_tier_at_critico():
    # score 30 sozinho seria "Alto" — 3+ achados críticos força "Crítico".
    result = risk_score.compute({"critical": 3}, 0)
    assert result["score"] == 30
    assert result["tier"] == "Crítico"
    assert result["reason"] is not None


def test_floor_never_downgrades_an_already_higher_score_tier():
    # score 50 (5 críticos) já é "Crítico" pela faixa — o piso não regride
    # nem duplica o motivo desnecessariamente.
    result = risk_score.compute({"critical": 5}, 0)
    assert result["tier"] == "Crítico"
