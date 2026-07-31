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


# ---- client (charset — evita IDOR/wildcard via path/query em main.py) ----


def test_scan_request_client_accepts_charset():
    req = ScanRequest(client="acme-Corp_1", targets=["acme.com"])
    assert req.client == "acme-Corp_1"


def test_scan_request_client_rejects_wildcard():
    with pytest.raises(ValidationError, match="client"):
        ScanRequest(client="*", targets=["acme.com"])


def test_scan_request_client_rejects_path_traversal():
    with pytest.raises(ValidationError, match="client"):
        ScanRequest(client="../../etc", targets=["acme.com"])


def test_scan_request_client_rejects_slash():
    with pytest.raises(ValidationError, match="client"):
        ScanRequest(client="acme/other", targets=["acme.com"])


# ---- targets (hostname/IP/CIDR — evita CWE-88 argument injection em commands.py) ----


def test_scan_request_targets_accepts_hostname():
    req = ScanRequest(client="acme", targets=["acme.com"])
    assert req.targets == ["acme.com"]


def test_scan_request_targets_accepts_ip():
    req = ScanRequest(client="acme", targets=["8.8.8.8"])
    assert req.targets == ["8.8.8.8"]


def test_scan_request_targets_accepts_cidr():
    req = ScanRequest(client="acme", targets=["8.8.8.0/24"])
    assert req.targets == ["8.8.8.0/24"]


def test_scan_request_targets_rejects_flag_like_value():
    # Um valor começando com "-" nunca deve chegar em commands.build() —
    # rejeitado aqui, na borda, antes de virar argumento de linha de comando.
    with pytest.raises(ValidationError, match="alvo"):
        ScanRequest(client="acme", targets=["--script=evil"])


def test_scan_request_targets_rejects_shell_metacharacters():
    with pytest.raises(ValidationError, match="alvo"):
        ScanRequest(client="acme", targets=["acme.com; rm -rf /"])


def test_recurring_scan_request_targets_rejects_invalid():
    with pytest.raises(ValidationError, match="alvo"):
        RecurringScanRequest(targets=["--evil"], enabled=False)
