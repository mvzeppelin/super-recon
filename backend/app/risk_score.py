"""Score de risco agregado do relatório executivo (ver README "Relatório
executivo"). Heurística própria, não um padrão tipo CVSS — os pesos/faixas
abaixo são um sinal relativo pra priorizar conversa com o cliente, não uma
pontuação certificada. Módulo puro (sem I/O) de propósito: quem busca os
dados é opensearch_client.risk_summary(), aqui só a matemática, testável
sem OpenSearch de verdade."""

SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

# WPScan não grava severidade própria (ver backend/parsers/wpscan.py) — cada
# vulnerabilidade retornada já é um CVE confirmado contra a versão instalada
# (cruzado com a WPVulnDB), então entra no score como equivalente a "high",
# em vez de virar um bucket de severidade à parte.
WPSCAN_VULN_WEIGHT = 5

_TIER_ORDER = ["Nenhum", "Baixo", "Médio", "Alto", "Crítico"]

# Faixas de score (limite inferior de cada tier, em ordem crescente).
_TIER_THRESHOLDS = [(0, "Nenhum"), (1, "Baixo"), (10, "Médio"), (25, "Alto"), (50, "Crítico")]


def _tier_from_score(score: int) -> str:
    tier = _TIER_THRESHOLDS[0][1]
    for threshold, name in _TIER_THRESHOLDS:
        if score >= threshold:
            tier = name
    return tier


def compute(severity_counts: dict[str, int], wpscan_vuln_count: int) -> dict:
    score = sum(SEVERITY_WEIGHTS.get(sev, 0) * n for sev, n in severity_counts.items())
    score += wpscan_vuln_count * WPSCAN_VULN_WEIGHT

    tier = _tier_from_score(score)
    critical_count = severity_counts.get("critical", 0)
    reason = None

    # Piso: um achado crítico sozinho não pode cair pra "Médio" só porque o
    # resto do peso não empurrou o score o suficiente — um cliente lendo "1
    # achado crítico" não pode ver o nível dizer "Baixo"/"Médio" ao lado.
    if critical_count >= 3 and _TIER_ORDER.index(tier) < _TIER_ORDER.index("Crítico"):
        tier = "Crítico"
        reason = f"{critical_count} achados críticos identificados"
    elif critical_count >= 1 and _TIER_ORDER.index(tier) < _TIER_ORDER.index("Alto"):
        tier = "Alto"
        reason = f"{critical_count} achado(s) crítico(s) identificado(s)"

    return {"score": score, "tier": tier, "reason": reason}
