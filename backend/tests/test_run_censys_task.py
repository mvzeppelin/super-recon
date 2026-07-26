from unittest.mock import patch

from app import tasks

CLIENT = "teste"
SCAN_ID = "scan-001"


def _job_ctx():
    return {"client": CLIENT, "scan_id": SCAN_ID}


def test_run_censys_task_indexes_real_data():
    raw = '{"result": {"resource": {"ip": "1.2.3.4", "services": [{"port": 80, "protocol": "HTTP"}]}}}'
    with (
        patch.object(tasks.censys_client, "lookup", return_value=raw),
        patch.object(tasks.opensearch_client, "record_job") as mock_record,
        patch.object(tasks.opensearch_client, "bulk_index", return_value=1) as mock_bulk,
        patch.object(tasks.notifications, "notify_findings") as mock_notify,
    ):
        result = tasks.run_censys_task(_job_ctx(), "1.2.3.4", job_id="job-1")

    assert result == {"tool": "censys", "target": "1.2.3.4", "count": 1, "status": "ok"}
    mock_bulk.assert_called_once()
    mock_notify.assert_called_once()
    assert mock_record.call_args_list[-1].kwargs["status"] == "ok"


def test_run_censys_task_no_services_is_ok_with_zero_docs():
    """"services": [] (comum — Censys não achou porta aberta nesse IP) não é
    erro, é achado zero — igual ao nmap sem portas."""
    raw = '{"result": {"resource": {"ip": "1.2.3.4", "services": []}}}'
    with (
        patch.object(tasks.censys_client, "lookup", return_value=raw),
        patch.object(tasks.opensearch_client, "record_job") as mock_record,
        patch.object(tasks.opensearch_client, "bulk_index", return_value=0),
        patch.object(tasks.notifications, "notify_findings"),
    ):
        result = tasks.run_censys_task(_job_ctx(), "1.2.3.4", job_id="job-2")

    assert result == {"tool": "censys", "target": "1.2.3.4", "count": 0, "status": "ok"}
    assert mock_record.call_args_list[-1].kwargs["status"] == "ok"


def test_run_censys_task_http_error_is_recorded_as_error():
    """Visto na prática: essa API pode responder 429 (rate limit) sob
    chamadas concorrentes — precisa virar status=error, não quebrar o
    pipeline nem ser tratado como "sem achado"."""
    with (
        patch.object(tasks.censys_client, "lookup", side_effect=RuntimeError("429 Too Many Requests")),
        patch.object(tasks.opensearch_client, "record_job") as mock_record,
    ):
        result = tasks.run_censys_task(_job_ctx(), "1.2.3.4", job_id="job-3")

    assert result["status"] == "error"
    assert "429" in result["error"]
    assert mock_record.call_args_list[-1].kwargs["status"] == "error"
