from unittest.mock import patch

from app import tasks

CLIENT = "teste"
SCAN_ID = "scan-001"

_RAW_JSONL = (
    '{"url": "https://example.com", "final_url": "https://example.com/", '
    '"response_code": 200, "title": "Example Domain", "failed": false}'
)


def _job_ctx():
    return {"client": CLIENT, "scan_id": SCAN_ID}


def _fake_docker_run_with_screenshot(_cmd, **kwargs):
    """Simula docker_runner.run(): chama on_finished (como o real faz antes
    de limpar o diretório de troca) e devolve o JSONL como raw output."""
    if kwargs.get("on_finished"):
        kwargs["on_finished"]("/fake/local_dir")
    return _RAW_JSONL


def test_run_gowitness_task_attaches_screenshot_id():
    with (
        patch.object(tasks, "_pick_core", return_value=0),
        patch.object(tasks.docker_runner, "run", side_effect=_fake_docker_run_with_screenshot),
        patch.object(tasks.os, "listdir", return_value=["https---example.com.jpeg"]),
        patch.object(tasks.os.path, "isdir", return_value=True),
        patch.object(tasks.screenshots_mod, "persist", return_value="deadbeef" * 4) as mock_persist,
        patch.object(tasks.opensearch_client, "record_job") as mock_record,
        patch.object(tasks.opensearch_client, "bulk_index", return_value=1) as mock_bulk,
        patch.object(tasks.notifications, "notify_findings"),
    ):
        result = tasks.run_gowitness_task(_job_ctx(), "https://example.com", job_id="job-1")

    assert result == {"tool": "gowitness", "target": "https://example.com", "count": 1, "status": "ok"}
    mock_persist.assert_called_once_with(CLIENT, "/fake/local_dir/screenshots/https---example.com.jpeg")
    indexed_docs = mock_bulk.call_args.args[1]
    assert indexed_docs[0]["screenshot_id"] == "deadbeef" * 4
    final_call = mock_record.call_args_list[-1]
    assert final_call.kwargs["status"] == "ok"


def test_run_gowitness_task_without_screenshot_dir_indexes_without_screenshot_id():
    """Falha antes de conseguir tirar o screenshot (ex: alvo fora do ar) —
    ainda indexa o achado (failed=true), só sem screenshot_id."""
    with (
        patch.object(tasks, "_pick_core", return_value=0),
        patch.object(tasks.docker_runner, "run", side_effect=_fake_docker_run_with_screenshot),
        patch.object(tasks.os.path, "isdir", return_value=False),
        patch.object(tasks.screenshots_mod, "persist") as mock_persist,
        patch.object(tasks.opensearch_client, "record_job"),
        patch.object(tasks.opensearch_client, "bulk_index", return_value=1) as mock_bulk,
        patch.object(tasks.notifications, "notify_findings"),
    ):
        tasks.run_gowitness_task(_job_ctx(), "https://example.com", job_id="job-2")

    mock_persist.assert_not_called()
    indexed_docs = mock_bulk.call_args.args[1]
    assert "screenshot_id" not in indexed_docs[0]
