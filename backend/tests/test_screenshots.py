import os

import pytest

from app import config, screenshots


def test_persist_moves_file_and_returns_opaque_id(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    source = tmp_path / "source.jpeg"
    source.write_bytes(b"fake-jpeg-bytes")

    screenshot_id = screenshots.persist("acme", str(source))

    assert screenshot_id is not None
    assert not source.exists()  # movido, não copiado
    dest = tmp_path / "acme" / f"{screenshot_id}.jpeg"
    assert dest.read_bytes() == b"fake-jpeg-bytes"


def test_persist_returns_none_when_source_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    assert screenshots.persist("acme", str(tmp_path / "does-not-exist.jpeg")) is None


def test_resolve_finds_persisted_file(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    source = tmp_path / "source.jpeg"
    source.write_bytes(b"fake-jpeg-bytes")
    screenshot_id = screenshots.persist("acme", str(source))

    resolved = screenshots.resolve("acme", screenshot_id)
    assert resolved == os.path.join(str(tmp_path), "acme", f"{screenshot_id}.jpeg")


def test_resolve_rejects_non_hex_id_path_traversal(tmp_path, monkeypatch):
    # Tentativa de escapar do diretório do cliente via id malicioso — nunca
    # deve virar um path válido, mesmo que o arquivo alvo exista de verdade.
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    assert screenshots.resolve("acme", "../../etc/passwd") is None
    assert screenshots.resolve("acme", "not-a-valid-hex-id") is None
    assert screenshots.resolve("acme", "") is None


def test_resolve_returns_none_for_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    assert screenshots.resolve("acme", "a" * 32) is None


def test_resolve_is_scoped_to_client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    source = tmp_path / "source.jpeg"
    source.write_bytes(b"fake-jpeg-bytes")
    screenshot_id = screenshots.persist("acme", str(source))

    assert screenshots.resolve("other-client", screenshot_id) is None
    assert screenshots.resolve("acme", screenshot_id) is not None


def test_delete_client_screenshots_removes_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    source = tmp_path / "source.jpeg"
    source.write_bytes(b"fake-jpeg-bytes")
    screenshots.persist("acme", str(source))

    screenshots.delete_client_screenshots("acme")
    assert not (tmp_path / "acme").exists()


def test_delete_client_screenshots_is_noop_when_nothing_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    screenshots.delete_client_screenshots("never-existed")  # não deve levantar exceção


# ---- client_name (defesa em profundidade contra path traversal — este
# módulo nunca deve confiar cegamente em quem chamou já ter validado) ----


def test_persist_raises_for_invalid_client_name_when_source_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    source = tmp_path / "source.jpeg"
    source.write_bytes(b"fake-jpeg-bytes")

    with pytest.raises(ValueError, match="cliente inválido"):
        screenshots.persist("../../etc", str(source))


def test_resolve_rejects_path_traversal_client_name(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    assert screenshots.resolve("../../etc", "a" * 32) is None


def test_delete_client_screenshots_rejects_invalid_client_name(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOTS_DIR", str(tmp_path))
    with pytest.raises(ValueError, match="cliente inválido"):
        screenshots.delete_client_screenshots("../../etc")
