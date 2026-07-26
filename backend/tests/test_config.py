from app import config


def test_resolve_enabled_tools_none_uses_default_without_opt_in(monkeypatch):
    monkeypatch.setattr(config, "DALFOX_ENABLED", False)
    monkeypatch.setattr(config, "GOWITNESS_ENABLED", False)
    monkeypatch.setattr(config, "KITERUNNER_ENABLED", False)
    assert config.resolve_enabled_tools(None) == config.PHASE4_DEFAULT_TOOLS


def test_resolve_enabled_tools_none_includes_opt_in_when_enabled(monkeypatch):
    monkeypatch.setattr(config, "DALFOX_ENABLED", True)
    monkeypatch.setattr(config, "GOWITNESS_ENABLED", False)
    monkeypatch.setattr(config, "KITERUNNER_ENABLED", True)
    resolved = config.resolve_enabled_tools(None)
    assert resolved == [*config.PHASE4_DEFAULT_TOOLS, "dalfox", "kiterunner"]


def test_resolve_enabled_tools_explicit_list_ignores_env_flags(monkeypatch):
    # Lista explícita manda, mesmo que contradiga os *_ENABLED do .env — é
    # exatamente o ponto de "Perfis de scan por execução".
    monkeypatch.setattr(config, "DALFOX_ENABLED", False)
    assert config.resolve_enabled_tools(["dalfox"]) == ["dalfox"]


def test_resolve_enabled_tools_explicit_empty_list_disables_everything(monkeypatch):
    monkeypatch.setattr(config, "DALFOX_ENABLED", True)
    assert config.resolve_enabled_tools([]) == []
