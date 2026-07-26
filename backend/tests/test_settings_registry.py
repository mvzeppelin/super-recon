from app import config, settings_registry


def test_defaults_match_current_config_value():
    assert settings_registry.default_value("NUCLEI_TIMEOUT") == config.NUCLEI_TIMEOUT
    assert settings_registry.default_value("SESSION_TTL_DAYS") == config.SESSION_TTL_DAYS


def test_validate_int_accepts_good_value():
    assert settings_registry.validate("NUCLEI_TIMEOUT", 600) == 600


def test_validate_int_rejects_non_int():
    try:
        settings_registry.validate("NUCLEI_TIMEOUT", "600")
        assert False, "devia ter levantado ValueError"
    except ValueError:
        pass


def test_validate_int_rejects_bool_even_though_bool_is_a_python_int():
    try:
        settings_registry.validate("NUCLEI_TIMEOUT", True)
        assert False, "devia ter levantado ValueError"
    except ValueError:
        pass


def test_validate_int_rejects_below_min():
    try:
        settings_registry.validate("NUCLEI_TIMEOUT", 0)
        assert False, "devia ter levantado ValueError (min=1)"
    except ValueError:
        pass


def test_validate_int_allows_zero_or_negative_when_no_min_declared():
    # HEALTH_CHECK_INTERVAL_SECONDS não tem "min" no registro de propósito
    # — <= 0 desliga o monitor, é um valor válido.
    assert settings_registry.validate("HEALTH_CHECK_INTERVAL_SECONDS", -1) == -1


def test_validate_bool():
    assert settings_registry.validate("GOWITNESS_ENABLED", True) is True
    try:
        settings_registry.validate("GOWITNESS_ENABLED", "true")
        assert False, "devia ter levantado ValueError"
    except ValueError:
        pass


def test_validate_csv_set_lowercases_and_dedupes_via_set():
    result = settings_registry.validate("NOTIFY_SEVERITIES", ["Critical", "high", " critical "])
    assert result == {"critical", "high"}


def test_apply_overrides_updates_config_module(monkeypatch):
    monkeypatch.setattr(config, "NUCLEI_TIMEOUT", 300)
    settings_registry.apply_overrides({"NUCLEI_TIMEOUT": 900})
    assert config.NUCLEI_TIMEOUT == 900


def test_apply_overrides_ignores_unknown_keys(monkeypatch):
    # não deve levantar, só ignora — quem valida a chave em si é a rota
    # (main.py), não apply_overrides.
    settings_registry.apply_overrides({"NOT_A_REAL_SETTING": 1})


def test_effective_view_marks_overridden(monkeypatch):
    monkeypatch.setattr(config, "NUCLEI_TIMEOUT", 300)
    view = settings_registry.effective_view({})
    entry = next(e for e in view if e["key"] == "NUCLEI_TIMEOUT")
    assert entry["overridden"] is False
    assert entry["value"] == 300

    view_overridden = settings_registry.effective_view({"NUCLEI_TIMEOUT": 900})
    entry = next(e for e in view_overridden if e["key"] == "NUCLEI_TIMEOUT")
    assert entry["overridden"] is True


def test_effective_view_never_leaks_secret_value(monkeypatch):
    monkeypatch.setattr(config, "SHODAN_API_KEY", "super-secret-value")
    view = settings_registry.effective_view({})
    entry = next(e for e in view if e["key"] == "SHODAN_API_KEY")
    assert "value" not in entry
    assert "default" not in entry
    assert entry["is_set"] is True
    assert "super-secret-value" not in str(entry)
