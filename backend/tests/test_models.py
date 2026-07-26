import pytest
from pydantic import ValidationError

from app.models import RecurringScanRequest, ScanRequest


def test_disabled_schedule_needs_no_periodicity():
    req = RecurringScanRequest(targets=["acme.com"], enabled=False)
    assert req.enabled is False
    assert req.periodicity is None


def test_enabled_daily_is_valid():
    req = RecurringScanRequest(targets=["acme.com"], enabled=True, periodicity="daily", run_time="14:00")
    assert req.periodicity == "daily"


def test_enabled_without_periodicity_fails():
    with pytest.raises(ValidationError, match="periodicity"):
        RecurringScanRequest(targets=["acme.com"], enabled=True, run_time="14:00")


def test_enabled_with_invalid_run_time_fails():
    with pytest.raises(ValidationError, match="run_time"):
        RecurringScanRequest(targets=["acme.com"], enabled=True, periodicity="daily", run_time="25:00")


def test_enabled_weekly_without_weekday_fails():
    with pytest.raises(ValidationError, match="weekday"):
        RecurringScanRequest(targets=["acme.com"], enabled=True, periodicity="weekly", run_time="14:00")


def test_enabled_weekly_with_weekday_is_valid():
    req = RecurringScanRequest(targets=["acme.com"], enabled=True, periodicity="weekly", run_time="14:00", weekday=0)
    assert req.weekday == 0


def test_enabled_monthly_without_day_of_month_fails():
    with pytest.raises(ValidationError, match="day_of_month"):
        RecurringScanRequest(targets=["acme.com"], enabled=True, periodicity="monthly", run_time="14:00")


def test_enabled_monthly_with_out_of_range_day_fails():
    with pytest.raises(ValidationError, match="day_of_month"):
        RecurringScanRequest(
            targets=["acme.com"], enabled=True, periodicity="monthly", run_time="14:00", day_of_month=32,
        )


def test_custom_wordlist_without_id_fails():
    with pytest.raises(ValidationError, match="gobuster_custom_wordlist_id"):
        RecurringScanRequest(targets=["acme.com"], gobuster_wordlist="custom")


# ---- enabled_tools (Perfis de scan por execução) ----


def test_scan_request_enabled_tools_omitted_is_none():
    req = ScanRequest(client="acme", targets=["acme.com"])
    assert req.enabled_tools is None


def test_scan_request_enabled_tools_valid_list():
    req = ScanRequest(client="acme", targets=["acme.com"], enabled_tools=["gobuster", "dalfox"])
    assert req.enabled_tools == ["gobuster", "dalfox"]


def test_scan_request_enabled_tools_unknown_tool_fails():
    with pytest.raises(ValidationError, match="enabled_tools"):
        ScanRequest(client="acme", targets=["acme.com"], enabled_tools=["gobuster", "sqlmap"])


def test_scan_request_enabled_tools_empty_list_is_valid():
    # Lista vazia é válida (desliga toda a Fase 4 nesse scan) — diferente de
    # None, que significa "usa o default".
    req = ScanRequest(client="acme", targets=["acme.com"], enabled_tools=[])
    assert req.enabled_tools == []


def test_recurring_scan_request_enabled_tools_unknown_tool_fails():
    # Validado mesmo com enabled=False (alvo salvo sem recorrência ativa) —
    # a checagem de enabled_tools não pode ficar atrás do "if not enabled".
    with pytest.raises(ValidationError, match="enabled_tools"):
        RecurringScanRequest(targets=["acme.com"], enabled=False, enabled_tools=["nuclei", "sqlmap"])
