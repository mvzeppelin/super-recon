import os
from unittest.mock import MagicMock

import docker
import pytest
import requests

from app import config, docker_runner


@pytest.fixture(autouse=True)
def _fast_poll():
    """Encurta o intervalo entre tentativas pra esses testes não gastarem
    os 5s reais por retry — comportamento é o mesmo, só mais rápido de
    rodar."""
    original = docker_runner._WAIT_POLL_SECONDS
    docker_runner._WAIT_POLL_SECONDS = 0.01
    yield
    docker_runner._WAIT_POLL_SECONDS = original


def _container(statuses):
    """Container fake cujo .reload() avança por uma sequência de "estados":
    cada item é uma exceção pra levantar, ou uma string de status pra
    deixar setada após a chamada."""
    c = MagicMock()
    c.short_id = "abc123"
    it = iter(statuses)

    def reload():
        step = next(it)
        if isinstance(step, Exception):
            raise step
        c.status = step

    c.reload.side_effect = reload
    return c


def test_wait_for_exit_returns_once_status_is_exited():
    c = _container(["running", "running", "exited"])
    docker_runner._wait_for_exit(c, timeout=10)
    assert c.reload.call_count == 3


def test_wait_for_exit_retries_transient_read_timeout():
    """O caso real que motivou o fix: um soluço passageiro do daemon
    (Read timed out) não deve derrubar a espera — só tenta de novo."""
    c = _container([
        requests.exceptions.ReadTimeout("Read timed out"),
        requests.exceptions.ConnectionError("connection reset"),
        "exited",
    ])
    docker_runner._wait_for_exit(c, timeout=10)
    assert c.reload.call_count == 3


def test_wait_for_exit_returns_when_container_removed_concurrently():
    """Cancelamento (stop_container de fora) remove o container — a espera
    deve encerrar normalmente, não estourar erro."""
    c = _container([docker.errors.NotFound("no such container")])
    docker_runner._wait_for_exit(c, timeout=10)
    assert c.reload.call_count == 1


def test_wait_for_exit_raises_after_real_timeout():
    """Container que genuinamente nunca termina estoura o timeout — vira um
    TimeoutError com mensagem clara, não mais o "Read timed out" confuso."""
    c = MagicMock()
    c.short_id = "abc123"
    c.status = "running"  # nunca muda

    with pytest.raises(TimeoutError, match="não terminou em"):
        docker_runner._wait_for_exit(c, timeout=0.05)


def _fake_client(container):
    client = MagicMock()
    client.containers.run.return_value = container
    return client


def test_retry_on_daemon_hiccup_retries_then_succeeds():
    """O caso real que motivou o fix: criar o container (containers.run) ou
    buscar os logs (container.logs) não tinham nenhum retry — um soluço
    passageiro do daemon derrubava o job inteiro em vez de só tentar de
    novo, como _wait_for_exit já fazia pra checagem de status."""
    calls = iter([
        requests.exceptions.ReadTimeout("Read timed out"),
        requests.exceptions.ConnectionError("connection reset"),
        "ok",
    ])

    def fn():
        step = next(calls)
        if isinstance(step, Exception):
            raise step
        return step

    result = docker_runner._retry_on_daemon_hiccup(fn, timeout=10, action="testar")
    assert result == "ok"


def test_retry_on_daemon_hiccup_raises_timeout_error_after_deadline():
    def always_fails():
        raise requests.exceptions.ReadTimeout("Read timed out")

    with pytest.raises(TimeoutError, match="criar o container"):
        docker_runner._retry_on_daemon_hiccup(always_fails, timeout=0.05, action="criar o container")


def test_run_retries_container_creation_on_transient_daemon_hiccup(monkeypatch):
    container = MagicMock()
    container.short_id = "abc123"
    container.logs.return_value = b""

    client = MagicMock()
    client.containers.run.side_effect = [
        requests.exceptions.ReadTimeout("Read timed out"),
        container,
    ]
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: client)
    monkeypatch.setattr(docker_runner, "_wait_for_exit", lambda *_a, **_kw: None)

    result = docker_runner.run(["dalfox", "url", "http://acme.com"], timeout=10)

    assert result == ""
    assert client.containers.run.call_count == 2


def test_run_raises_when_container_creation_never_succeeds(monkeypatch):
    client = MagicMock()
    client.containers.run.side_effect = requests.exceptions.ReadTimeout("Read timed out")
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: client)

    with pytest.raises(TimeoutError, match="criar o container"):
        docker_runner.run(["dalfox", "url", "http://acme.com"], timeout=0.05)


def test_run_retries_logs_on_transient_daemon_hiccup(monkeypatch):
    container = MagicMock()
    container.short_id = "abc123"
    container.logs.side_effect = [
        requests.exceptions.ConnectionError("connection reset"),
        b"saida real",
    ]
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: _fake_client(container))
    monkeypatch.setattr(docker_runner, "_wait_for_exit", lambda *_a, **_kw: None)

    result = docker_runner.run(["dalfox", "url", "http://acme.com"], timeout=10)

    assert result == "saida real"
    assert container.logs.call_count == 2


def test_run_recovers_when_container_vanishes_before_logs(tmp_path, monkeypatch):
    """Visto na prática sob carga pesada (dois scans em paralelo): o
    container termina normalmente (_wait_for_exit não reclama), mas some
    antes do container.logs() ser chamado — o daemon estava sobrecarregado
    demais até pra manter o rastro dele. Antes desse fix isso derrubava o
    job inteiro com "404 No such container"; agora aproveita o output_file
    já escrito em vez de perder o resultado todo."""
    monkeypatch.setattr(config, "EXCHANGE_DIR", str(tmp_path))
    container = MagicMock()
    container.short_id = "abc123"
    container.logs.side_effect = docker.errors.NotFound("no such container")
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: _fake_client(container))

    def fake_wait(_container, _timeout):
        exchange_dir = next(tmp_path.iterdir())
        (exchange_dir / "result.json").write_text('{"achou": true}')

    monkeypatch.setattr(docker_runner, "_wait_for_exit", fake_wait)

    result = docker_runner.run(["dalfox", "url", "http://acme.com"], output_file="result.json", timeout=10)

    assert result == '{"achou": true}'


def test_run_ignores_transient_error_removing_container(monkeypatch):
    """Limpeza (finally) não deve derrubar um resultado que já tinha sido
    obtido com sucesso, só porque o daemon soneca bem na hora do remove()."""
    container = MagicMock()
    container.short_id = "abc123"
    container.logs.return_value = b"saida real"
    container.remove.side_effect = requests.exceptions.ReadTimeout("Read timed out")
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: _fake_client(container))
    monkeypatch.setattr(docker_runner, "_wait_for_exit", lambda *_a, **_kw: None)

    result = docker_runner.run(["dalfox", "url", "http://acme.com"], timeout=10)

    assert result == "saida real"


def test_run_returns_partial_output_when_timeout_hits_after_partial_write(tmp_path, monkeypatch):
    """O caso que motivou o teto de registros do wayback: o timeout do
    container estoura, mas o que já tinha sido escrito no output_file (por
    página, ver wayback_fetch.py) não pode se perder."""
    monkeypatch.setattr(config, "EXCHANGE_DIR", str(tmp_path))
    container = MagicMock()
    container.short_id = "abc123"
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: _fake_client(container))

    def fake_wait(_container, _timeout):
        exchange_dir = next(tmp_path.iterdir())
        (exchange_dir / "urls.txt").write_text("http://a.com/1\nhttp://a.com/2\n")
        raise TimeoutError("container não terminou em 5s")

    monkeypatch.setattr(docker_runner, "_wait_for_exit", fake_wait)

    result = docker_runner.run(["bash", "-c", "..."], output_file="urls.txt", timeout=5)

    assert result == "http://a.com/1\nhttp://a.com/2\n"
    container.remove.assert_called_once_with(force=True)


def test_run_raises_on_timeout_without_output_file(monkeypatch):
    container = MagicMock()
    container.short_id = "abc123"
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: _fake_client(container))
    monkeypatch.setattr(
        docker_runner, "_wait_for_exit",
        lambda *_a, **_kw: (_ for _ in ()).throw(TimeoutError("container não terminou em 5s")),
    )

    with pytest.raises(TimeoutError):
        docker_runner.run(["assetfinder", "-subs-only", "acme.com"], timeout=5)


def test_run_raises_on_timeout_when_output_file_was_never_written(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EXCHANGE_DIR", str(tmp_path))
    container = MagicMock()
    container.short_id = "abc123"
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: _fake_client(container))
    monkeypatch.setattr(
        docker_runner, "_wait_for_exit",
        lambda *_a, **_kw: (_ for _ in ()).throw(TimeoutError("container não terminou em 5s")),
    )

    with pytest.raises(TimeoutError):
        docker_runner.run(["bash", "-c", "..."], output_file="urls.txt", timeout=5)


def test_run_calls_on_finished_with_local_dir_before_cleanup(tmp_path, monkeypatch):
    # Caso do gowitness: precisa mover um arquivo do diretório de troca (o
    # screenshot) pra um lugar persistente antes dele ser apagado.
    monkeypatch.setattr(config, "EXCHANGE_DIR", str(tmp_path))
    container = MagicMock()
    container.short_id = "abc123"
    container.logs.return_value = b""
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: _fake_client(container))

    def fake_wait(_container, _timeout):
        exchange_dir = next(tmp_path.iterdir())
        (exchange_dir / "result.json").write_text("{}")

    monkeypatch.setattr(docker_runner, "_wait_for_exit", fake_wait)

    seen_dirs = []

    def on_finished(local_dir):
        seen_dirs.append(local_dir)
        assert os.path.exists(os.path.join(local_dir, "result.json"))  # ainda não apagado

    docker_runner.run(["bash", "-c", "..."], output_file="result.json", on_finished=on_finished)

    assert len(seen_dirs) == 1
    assert not os.path.exists(seen_dirs[0])  # apagado depois do callback


def test_run_isolates_on_finished_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "EXCHANGE_DIR", str(tmp_path))
    container = MagicMock()
    container.short_id = "abc123"
    container.logs.return_value = b""
    monkeypatch.setattr(docker_runner, "_docker_client", lambda: _fake_client(container))
    monkeypatch.setattr(docker_runner, "_wait_for_exit", lambda *_a, **_kw: None)

    def broken_on_finished(_local_dir):
        raise RuntimeError("boom")

    # Não deve propagar — mesmo tratamento de on_started.
    result = docker_runner.run(["bash", "-c", "..."], output_file="result.json", on_finished=broken_on_finished)
    assert result == ""
