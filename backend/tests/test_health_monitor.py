from unittest.mock import patch

from app import health_monitor


def _set_checks(problems: list[str | None]):
    """Substitui os 4 checks reais por stubs que devolvem, em ordem, os
    valores de `problems` (None = check OK, str = problema)."""
    return patch.object(health_monitor, "_CHECKS", tuple((lambda p=p: p) for p in problems))


def test_check_health_collects_only_actual_problems():
    with _set_checks([None, "worker down", None, "fila represada"]):
        assert health_monitor.check_health() == ["worker down", "fila represada"]


def test_check_health_all_ok_returns_empty_list():
    with _set_checks([None, None, None, None]):
        assert health_monitor.check_health() == []


def test_run_check_and_notify_alerts_on_first_problem():
    health_monitor._last_problems = None
    with _set_checks(["opensearch vermelho", None, None, None]):
        with patch.object(health_monitor.notifications, "notify_health") as notify:
            problems = health_monitor.run_check_and_notify()
    assert problems == ["opensearch vermelho"]
    notify.assert_called_once_with(["opensearch vermelho"])


def test_run_check_and_notify_does_not_repeat_same_problem():
    health_monitor._last_problems = ["opensearch vermelho"]
    with _set_checks(["opensearch vermelho", None, None, None]):
        with patch.object(health_monitor.notifications, "notify_health") as notify:
            health_monitor.run_check_and_notify()
    notify.assert_not_called()


def test_run_check_and_notify_alerts_on_recovery():
    health_monitor._last_problems = ["opensearch vermelho"]
    with _set_checks([None, None, None, None]):
        with patch.object(health_monitor.notifications, "notify_health") as notify:
            problems = health_monitor.run_check_and_notify()
    assert problems == []
    notify.assert_called_once_with([])


def test_run_check_and_notify_skips_notify_when_starting_healthy():
    health_monitor._last_problems = None
    with _set_checks([None, None, None, None]):
        with patch.object(health_monitor.notifications, "notify_health") as notify:
            health_monitor.run_check_and_notify()
    notify.assert_not_called()


def test_run_check_and_notify_alerts_on_changed_problem_set():
    health_monitor._last_problems = ["fila represada"]
    with _set_checks(["worker down", None, None, None]):
        with patch.object(health_monitor.notifications, "notify_health") as notify:
            problems = health_monitor.run_check_and_notify()
    assert problems == ["worker down"]
    notify.assert_called_once_with(["worker down"])
