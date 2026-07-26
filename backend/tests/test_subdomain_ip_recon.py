from unittest.mock import patch

from app import tasks


def test_is_scannable_ip_accepts_public_address():
    assert tasks._is_scannable_ip("44.228.249.3") is True


def test_is_scannable_ip_rejects_loopback():
    # Achado na prática com vulnweb.com: um subdomínio ("localhost.vulnweb.com")
    # resolve de propósito para 127.0.0.1.
    assert tasks._is_scannable_ip("127.0.0.1") is False


def test_is_scannable_ip_rejects_private_range():
    assert tasks._is_scannable_ip("10.0.0.5") is False
    assert tasks._is_scannable_ip("192.168.1.1") is False


def test_is_scannable_ip_rejects_link_local():
    assert tasks._is_scannable_ip("169.254.1.1") is False


def test_is_scannable_ip_rejects_malformed():
    assert tasks._is_scannable_ip("not-an-ip") is False


def _job_ctx():
    return {"client": "acme", "scan_id": "scan-001"}


def test_dispatch_excludes_root_ip_and_private_ips():
    # Dados reais vistos rodando contra vulnweb.com: 3 IPs públicos (um deles
    # o do domínio raiz) + 1 subdomínio-armadilha resolvendo pra loopback.
    with (
        patch.object(tasks.opensearch_client, "query_dnsx_ips", return_value={
            "44.228.249.3", "44.238.29.244", "18.215.71.186", "127.0.0.1",
        }),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks.util, "resolve_ip", return_value="44.228.249.3"),
        patch.object(tasks, "chord", return_value=lambda callback: None),
        patch.object(tasks.subdomain_ip_recon_task, "s") as mock_callback_sig,
    ):
        tasks._dispatch_subdomain_ip_recon(_job_ctx(), "vulnweb.com")

    dispatched_ips = {call.args[1] for call in mock_callback_sig.call_args_list}
    assert dispatched_ips == {"44.238.29.244", "18.215.71.186"}


def test_dispatch_is_noop_when_no_dnsx_ips():
    with (
        patch.object(tasks.opensearch_client, "query_dnsx_ips", return_value=set()),
        patch.object(tasks, "chord") as mock_chord,
    ):
        tasks._dispatch_subdomain_ip_recon(_job_ctx(), "vulnweb.com")

    mock_chord.assert_not_called()


def test_dispatch_skips_resolve_ip_for_ip_target():
    """Alvo IP puro não roda dnsx (query_dnsx_ips já devolve vazio) — não
    deveria nem tentar resolver o "domínio" via DNS nesse caso."""
    with (
        patch.object(tasks.opensearch_client, "query_dnsx_ips", return_value=set()),
        patch.object(tasks.util, "resolve_ip") as mock_resolve,
    ):
        tasks._dispatch_subdomain_ip_recon(_job_ctx(), "1.2.3.4")

    mock_resolve.assert_not_called()


def test_dispatch_includes_shodan_when_configured():
    with (
        patch.object(tasks.opensearch_client, "query_dnsx_ips", return_value={"44.238.29.244"}),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks.util, "resolve_ip", return_value="9.9.9.9"),
        patch.object(tasks, "chord", return_value=lambda callback: None),
        patch.object(tasks.subdomain_ip_recon_task, "s"),
        patch.object(tasks.config, "SHODAN_API_KEY", "fake-key"),
        patch.object(tasks.run_shodan_task, "s") as mock_shodan_sig,
    ):
        tasks._dispatch_subdomain_ip_recon(_job_ctx(), "example.com")

    mock_shodan_sig.assert_called_once()
    assert mock_shodan_sig.call_args.args[1] == "44.238.29.244"


def test_dispatch_skips_shodan_when_not_configured():
    with (
        patch.object(tasks.opensearch_client, "query_dnsx_ips", return_value={"44.238.29.244"}),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks.util, "resolve_ip", return_value="9.9.9.9"),
        patch.object(tasks, "chord", return_value=lambda callback: None),
        patch.object(tasks.subdomain_ip_recon_task, "s"),
        patch.object(tasks.config, "SHODAN_API_KEY", ""),
        patch.object(tasks.run_shodan_task, "s") as mock_shodan_sig,
    ):
        tasks._dispatch_subdomain_ip_recon(_job_ctx(), "example.com")

    mock_shodan_sig.assert_not_called()


def test_dispatch_includes_censys_when_configured():
    with (
        patch.object(tasks.opensearch_client, "query_dnsx_ips", return_value={"44.238.29.244"}),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks.util, "resolve_ip", return_value="9.9.9.9"),
        patch.object(tasks, "chord", return_value=lambda callback: None),
        patch.object(tasks.subdomain_ip_recon_task, "s"),
        patch.object(tasks.config, "CENSYS_API_KEY", "fake-key"),
        patch.object(tasks.run_censys_task, "s") as mock_censys_sig,
    ):
        tasks._dispatch_subdomain_ip_recon(_job_ctx(), "example.com")

    mock_censys_sig.assert_called_once()
    assert mock_censys_sig.call_args.args[1] == "44.238.29.244"


def test_dispatch_skips_censys_when_not_configured():
    with (
        patch.object(tasks.opensearch_client, "query_dnsx_ips", return_value={"44.238.29.244"}),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks.util, "resolve_ip", return_value="9.9.9.9"),
        patch.object(tasks, "chord", return_value=lambda callback: None),
        patch.object(tasks.subdomain_ip_recon_task, "s"),
        patch.object(tasks.config, "CENSYS_API_KEY", ""),
        patch.object(tasks.run_censys_task, "s") as mock_censys_sig,
    ):
        tasks._dispatch_subdomain_ip_recon(_job_ctx(), "example.com")

    mock_censys_sig.assert_not_called()
