from unittest.mock import patch

from app import config, tasks

CLIENT = "teste"
SCAN_ID = "scan-001"


def _job_ctx(enabled_tools):
    return {
        "client": CLIENT, "scan_id": SCAN_ID, "gobuster_wordlist": "common",
        "gobuster_custom_wordlist_id": None, "enabled_tools": enabled_tools,
    }


# nikto/gowitness têm task Celery própria (o nome da ferramenta não é um
# argumento posicional como em run_tool_task) — extrai o nome real a partir
# da task registrada em cada caso.
_TASK_NAME_TO_TOOL = {"recon.run_nikto": "nikto", "recon.run_gowitness": "gowitness"}


def _tool_name(sig):
    return _TASK_NAME_TO_TOOL.get(sig.task, sig.args[1] if sig.task == "recon.run_tool" else sig.task)


def _dispatch(enabled_tools, urls=("http://a.example.com",)):
    """Roda phase4_dispatch_task e devolve o nome das ferramentas cujas
    signatures foram passadas pro group(...).apply_async() real — sem tocar
    Celery/broker/OpenSearch de verdade (mesmo padrão do antigo
    test_phase4_stagger.py)."""
    captured = {}

    def fake_group(sigs):
        captured["sigs"] = list(sigs)
        return type("FakeGroupResult", (), {"apply_async": lambda self: None})()

    with (
        patch.object(tasks, "_scan_cancelled", return_value=False),
        patch.object(tasks, "_dispatch_subdomain_ip_recon"),
        patch.object(tasks.opensearch_client, "query_alive_urls", return_value=list(urls)),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks, "group", side_effect=fake_group),
    ):
        tasks.phase4_dispatch_task(None, _job_ctx(enabled_tools), "example.com")

    return {_tool_name(sig) for sig in captured.get("sigs", [])}


def test_explicit_enabled_tools_gates_dispatch(monkeypatch):
    # Ligado no config, mas fora do checklist do scan -> não dispara.
    monkeypatch.setattr(config, "DALFOX_ENABLED", True)
    dispatched = _dispatch(["gobuster", "dalfox"])
    assert dispatched == {"gobuster", "dalfox"}


def test_opt_in_tool_off_in_config_still_runs_if_in_checklist(monkeypatch):
    monkeypatch.setattr(config, "KITERUNNER_ENABLED", False)
    dispatched = _dispatch(["kiterunner"])
    assert dispatched == {"kiterunner"}


def test_empty_enabled_tools_dispatches_nothing_from_phase4():
    dispatched = _dispatch([])
    assert dispatched == set()


def test_default_five_tools_when_enabled_tools_missing_from_job_ctx():
    # job_ctx sem "enabled_tools" (compat com formato antigo) cai no
    # fallback de _resolved_enabled_tools -> PHASE4_DEFAULT_TOOLS.
    captured = {}

    def fake_group(sigs):
        captured["sigs"] = list(sigs)
        return type("FakeGroupResult", (), {"apply_async": lambda self: None})()

    job_ctx = {"client": CLIENT, "scan_id": SCAN_ID, "gobuster_wordlist": "common", "gobuster_custom_wordlist_id": None}
    with (
        patch.object(tasks, "_scan_cancelled", return_value=False),
        patch.object(tasks, "_dispatch_subdomain_ip_recon"),
        patch.object(tasks.opensearch_client, "query_alive_urls", return_value=["http://a.example.com"]),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks, "group", side_effect=fake_group),
    ):
        tasks.phase4_dispatch_task(None, job_ctx, "example.com")

    dispatched = {_tool_name(sig) for sig in captured["sigs"]}
    assert dispatched == set(config.PHASE4_DEFAULT_TOOLS)
