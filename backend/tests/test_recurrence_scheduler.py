from unittest.mock import patch

from app import recurrence_scheduler


def _sched(**overrides):
    base = {
        "schedule_id": "sched-1",
        "client": "acme",
        "targets": ["acme.com"],
        "gobuster_wordlist": "common",
        "gobuster_custom_wordlist_id": None,
        "enabled": True,
        "periodicity": "daily",
        "run_time": "14:00",
        "weekday": None,
        "day_of_month": None,
    }
    base.update(overrides)
    return base


def test_run_due_schedules_triggers_each_due_schedule_and_reschedules():
    due = [_sched(schedule_id="sched-1"), _sched(schedule_id="sched-2", client="other")]
    with (
        patch.object(recurrence_scheduler.opensearch_client, "list_due_recurring_scans", return_value=due) as mock_list,
        patch.object(recurrence_scheduler.opensearch_client, "record_scan") as mock_record_scan,
        patch.object(recurrence_scheduler.opensearch_client, "update_recurring_scan_after_run") as mock_update,
        patch.object(recurrence_scheduler.tasks.orchestrate_scan_task, "delay") as mock_delay,
    ):
        count = recurrence_scheduler.run_due_schedules()

    assert count == 2
    mock_list.assert_called_once()
    assert mock_record_scan.call_count == 2
    assert mock_delay.call_count == 2
    assert mock_update.call_count == 2

    first_record_call = mock_record_scan.call_args_list[0]
    assert first_record_call.args[0] == "acme"
    assert first_record_call.args[2] == ["acme.com"]
    assert first_record_call.kwargs["triggered_by"] == "recurrence"
    assert first_record_call.kwargs["schedule_id"] == "sched-1"

    first_update_call = mock_update.call_args_list[0]
    assert first_update_call.args[0] == "acme"
    assert first_update_call.args[1] == "sched-1"
    assert "next_run_at" in first_update_call.kwargs


def test_run_due_schedules_skips_nothing_but_isolates_failures():
    """Uma falha ao disparar um alvo não impede os outros de rodar."""
    due = [_sched(schedule_id="sched-broken"), _sched(schedule_id="sched-ok")]
    with (
        patch.object(recurrence_scheduler.opensearch_client, "list_due_recurring_scans", return_value=due),
        patch.object(
            recurrence_scheduler.opensearch_client, "record_scan",
            side_effect=[RuntimeError("falhou"), None],
        ),
        patch.object(recurrence_scheduler.opensearch_client, "update_recurring_scan_after_run") as mock_update,
        patch.object(recurrence_scheduler.tasks.orchestrate_scan_task, "delay") as mock_delay,
    ):
        count = recurrence_scheduler.run_due_schedules()

    assert count == 2  # devolve quantos estavam devidos, não quantos tiveram sucesso
    assert mock_delay.call_count == 1  # só o segundo chegou a disparar
    assert mock_update.call_count == 1


def test_run_due_schedules_with_nothing_due_does_nothing():
    with (
        patch.object(recurrence_scheduler.opensearch_client, "list_due_recurring_scans", return_value=[]),
        patch.object(recurrence_scheduler.opensearch_client, "record_scan") as mock_record_scan,
        patch.object(recurrence_scheduler.tasks.orchestrate_scan_task, "delay") as mock_delay,
    ):
        count = recurrence_scheduler.run_due_schedules()

    assert count == 0
    mock_record_scan.assert_not_called()
    mock_delay.assert_not_called()
