from unittest.mock import MagicMock, patch

from app import opensearch_client as oc


def _fake_client():
    fake = MagicMock()
    fake.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    return fake


def test_single_value_filter_becomes_terms_with_one_item():
    """Filtro de valor único (como sempre foi, ex: ?tool=nmap) continua
    funcionando igual — "terms" com lista de 1 item se comporta como "term"."""
    fake = _fake_client()
    with patch.object(oc, "client", return_value=fake):
        oc.search_findings("acme", "jobs", filters={"status": "ok"})

    body = fake.search.call_args.kwargs["body"]
    assert {"terms": {"status": ["ok"]}} in body["query"]["bool"]["filter"]


def test_list_value_filter_becomes_terms_with_multiple_items():
    """Múltiplos valores pro mesmo campo (?status=ok&status=error, a
    melhoria de multi-seleção) viram um "terms" com todos os valores —
    OpenSearch casa se o campo bater com QUALQUER um deles (semântica OR)."""
    fake = _fake_client()
    with patch.object(oc, "client", return_value=fake):
        oc.search_findings("acme", "jobs", filters={"status": ["ok", "error"]})

    body = fake.search.call_args.kwargs["body"]
    assert {"terms": {"status": ["ok", "error"]}} in body["query"]["bool"]["filter"]


def test_no_filters_matches_everything():
    fake = _fake_client()
    with patch.object(oc, "client", return_value=fake):
        oc.search_findings("acme", "jobs")

    body = fake.search.call_args.kwargs["body"]
    assert body["query"] == {"match_all": {}}
