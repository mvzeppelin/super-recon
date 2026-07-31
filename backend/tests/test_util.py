from unittest.mock import patch

from app import util


def test_is_ip_or_cidr_accepts_ip():
    assert util.is_ip_or_cidr("8.8.8.8") is True


def test_is_ip_or_cidr_accepts_cidr():
    assert util.is_ip_or_cidr("8.8.8.0/24") is True


def test_is_ip_or_cidr_rejects_hostname():
    assert util.is_ip_or_cidr("acme.com") is False


# ---- is_safe_webhook_url (defesa contra SSRF — settings_registry.py e notifications.py) ----


def test_is_safe_webhook_url_accepts_public_host():
    with patch.object(util.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.8.8", 0))]):
        assert util.is_safe_webhook_url("https://example.com/hook") is True


def test_is_safe_webhook_url_rejects_loopback():
    with patch.object(util.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 0))]):
        assert util.is_safe_webhook_url("http://localhost/hook") is False


def test_is_safe_webhook_url_rejects_private_range():
    with patch.object(util.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 0))]):
        assert util.is_safe_webhook_url("http://internal.example.com/hook") is False


def test_is_safe_webhook_url_rejects_cloud_metadata_address():
    with patch.object(util.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("169.254.169.254", 0))]):
        assert util.is_safe_webhook_url("http://metadata.example.com/hook") is False


def test_is_safe_webhook_url_rejects_when_any_resolved_address_is_private():
    # DNS malicioso/rebinding devolvendo um IP público primeiro e um interno
    # depois — não basta checar só o primeiro resultado de getaddrinfo.
    with patch.object(
        util.socket, "getaddrinfo",
        return_value=[(2, 1, 6, "", ("8.8.8.8", 0)), (2, 1, 6, "", ("10.0.0.5", 0))],
    ):
        assert util.is_safe_webhook_url("http://mixed.example.com/hook") is False


def test_is_safe_webhook_url_rejects_non_http_scheme():
    assert util.is_safe_webhook_url("ftp://example.com/hook") is False


def test_is_safe_webhook_url_rejects_unresolvable_host():
    with patch.object(util.socket, "getaddrinfo", side_effect=OSError):
        assert util.is_safe_webhook_url("http://does-not-resolve.invalid/hook") is False
