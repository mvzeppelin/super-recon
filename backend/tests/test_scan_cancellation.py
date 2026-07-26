from unittest.mock import patch

from app import tasks

CLIENT = "teste"
SCAN_ID = "scan-001"


def _job_ctx():
    return {"client": CLIENT, "scan_id": SCAN_ID, "gobuster_wordlist": "common", "gobuster_custom_wordlist_id": None}


def test_scan_cancelled_checks_opensearch_flag():
    with patch.object(tasks.opensearch_client, "is_scan_cancelled", return_value=True) as mock_check:
        assert tasks._scan_cancelled(_job_ctx()) is True
    mock_check.assert_called_once_with(CLIENT, SCAN_ID)


def _assert_no_dispatch(*mocks):
    for m in mocks:
        m.assert_not_called()


def test_phase2_domain_task_skips_when_cancelled():
    with (
        patch.object(tasks, "_scan_cancelled", return_value=True),
        patch.object(tasks.opensearch_client, "query_subdomains") as mock_query,
        patch.object(tasks, "chord") as mock_chord,
    ):
        result = tasks.phase2_domain_task(None, _job_ctx(), "example.com")

    assert result == {"domain": "example.com", "status": "cancelled"}
    _assert_no_dispatch(mock_query, mock_chord)


def test_phase2_ip_task_skips_when_cancelled():
    with (
        patch.object(tasks, "_scan_cancelled", return_value=True),
        patch.object(tasks.opensearch_client, "query_masscan_ports") as mock_query,
        patch.object(tasks, "chord") as mock_chord,
    ):
        result = tasks.phase2_ip_task(None, _job_ctx(), "1.2.3.4")

    assert result == {"ip": "1.2.3.4", "status": "cancelled"}
    _assert_no_dispatch(mock_query, mock_chord)


def test_phase4_dispatch_task_skips_when_cancelled():
    with (
        patch.object(tasks, "_scan_cancelled", return_value=True),
        patch.object(tasks, "_dispatch_subdomain_ip_recon") as mock_subdomain_ip,
        patch.object(tasks.opensearch_client, "query_alive_urls") as mock_urls,
    ):
        result = tasks.phase4_dispatch_task(None, _job_ctx(), "example.com")

    assert result == {"target": "example.com", "status": "cancelled"}
    _assert_no_dispatch(mock_subdomain_ip, mock_urls)


def test_subdomain_ip_recon_task_skips_when_cancelled():
    """Este é o caso real que motivou o fix: o masscan de um IP de
    subdomínio pode terminar (com sucesso ou erro) DEPOIS do usuário
    cancelar o scan — sem essa checagem, o callback ainda disparava o nmap
    seguinte, dando a impressão de que "cancelar tudo" não funcionava."""
    with (
        patch.object(tasks, "_scan_cancelled", return_value=True),
        patch.object(tasks.opensearch_client, "query_masscan_ports") as mock_ports,
        patch.object(tasks.run_tool_task, "delay") as mock_delay,
    ):
        result = tasks.subdomain_ip_recon_task(None, _job_ctx(), "1.2.3.4")

    assert result == {"ip": "1.2.3.4", "status": "cancelled"}
    _assert_no_dispatch(mock_ports, mock_delay)


def test_phase2_domain_task_proceeds_when_not_cancelled():
    with (
        patch.object(tasks, "_scan_cancelled", return_value=False),
        patch.object(tasks.opensearch_client, "query_subdomains", return_value=[]),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks.util, "resolve_ip", return_value=None),
        patch.object(tasks, "chord", return_value=lambda callback: None) as mock_chord,
    ):
        result = tasks.phase2_domain_task(None, _job_ctx(), "example.com")

    assert result.get("status") != "cancelled"
    mock_chord.assert_called_once()
