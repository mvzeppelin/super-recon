from app import commands, config


def test_wpscan_without_api_token(monkeypatch):
    monkeypatch.setattr(config, "WPSCAN_API_TOKEN", "")
    spec = commands.build("wpscan", "http://acme.com")
    assert "--api-token" not in spec["cmd"]
    assert spec["cmd"][:3] == ["wpscan", "--url", "http://acme.com"]
    assert spec["output_file"] == "result.json"


def test_wpscan_with_api_token(monkeypatch):
    monkeypatch.setattr(config, "WPSCAN_API_TOKEN", "test-token-123")
    spec = commands.build("wpscan", "http://acme.com")
    assert "--api-token" in spec["cmd"]
    idx = spec["cmd"].index("--api-token")
    assert spec["cmd"][idx + 1] == "test-token-123"


def test_wpscan_uses_vulnerable_only_profile(monkeypatch):
    monkeypatch.setattr(config, "WPSCAN_API_TOKEN", "")
    spec = commands.build("wpscan", "http://acme.com")
    idx = spec["cmd"].index("-e")
    assert spec["cmd"][idx + 1] == "vp,vt,u"
