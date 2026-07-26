from unittest.mock import patch

from app import shodan_client, tasks

CLIENT = "teste"
SCAN_ID = "scan-001"


def _job_ctx():
    return {"client": CLIENT, "scan_id": SCAN_ID}


def test_run_shodan_task_indexes_real_data():
    raw = '{"ip_str": "1.2.3.4", "org": "Acme", "data": [{"port": 80, "transport": "tcp"}]}'
    with (
        patch.object(tasks.shodan_client, "lookup", return_value=raw),
        patch.object(tasks.opensearch_client, "record_job") as mock_record,
        patch.object(tasks.opensearch_client, "bulk_index", return_value=1) as mock_bulk,
        patch.object(tasks.notifications, "notify_findings") as mock_notify,
    ):
        result = tasks.run_shodan_task(_job_ctx(), "1.2.3.4", job_id="job-1")

    assert result == {"tool": "shodan", "target": "1.2.3.4", "count": 1, "status": "ok"}
    mock_bulk.assert_called_once()
    mock_notify.assert_called_once()
    final_call = mock_record.call_args_list[-1]
    assert final_call.kwargs["status"] == "ok"
    assert final_call.kwargs["doc_count"] == 1


def test_run_shodan_task_not_found_is_ok_with_zero_docs():
    """404 (Shodan não tem o IP indexado) não é erro — é achado zero."""
    with (
        patch.object(tasks.shodan_client, "lookup", side_effect=shodan_client.NotFoundError("1.2.3.4")),
        patch.object(tasks.opensearch_client, "record_job") as mock_record,
    ):
        result = tasks.run_shodan_task(_job_ctx(), "1.2.3.4", job_id="job-2")

    assert result == {"tool": "shodan", "target": "1.2.3.4", "count": 0, "status": "ok"}
    final_call = mock_record.call_args_list[-1]
    assert final_call.kwargs["status"] == "ok"
    assert final_call.kwargs["doc_count"] == 0


def test_run_shodan_task_plan_required_is_error_not_ok():
    """403 "Requires membership or higher" (Shodan TEM dado, plano não dá
    acesso) precisa ficar como status=error — não pode parecer achado
    limpo/zero, senão passa a impressão enganosa de "verificamos e não
    tinha nada"."""
    with (
        patch.object(
            tasks.shodan_client, "lookup",
            side_effect=shodan_client.PlanRequiredError('{"error": "Requires membership or higher to access"}'),
        ),
        patch.object(tasks.opensearch_client, "record_job") as mock_record,
    ):
        result = tasks.run_shodan_task(_job_ctx(), "1.2.3.4", job_id="job-3")

    assert result["status"] == "error"
    assert "membership" in result["error"]
    final_call = mock_record.call_args_list[-1]
    assert final_call.kwargs["status"] == "error"
