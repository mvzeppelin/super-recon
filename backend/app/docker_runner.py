import logging
import os
import shutil
import time
import uuid

import docker
import requests

from . import config

logger = logging.getLogger(__name__)

_client = None

# Timeout curto por chamada HTTP ao daemon (docker.sock) — não é a mesma
# coisa que o timeout por ferramenta (quanto tempo o recon pode rodar);
# esse aqui é só "quanto tempo aceitável pro daemon responder uma pergunta
# rápida tipo 'esse container já terminou?'". Sem isso, o cliente docker usa
# o default de 60s por chamada — alto demais pra um polling que já tenta de
# novo sozinho em caso de soneca do daemon (ver _wait_for_exit).
_DOCKER_CLIENT_TIMEOUT = 20


def _docker_client():
    global _client
    if _client is None:
        _client = docker.from_env(timeout=_DOCKER_CLIENT_TIMEOUT)
    return _client


# Intervalo entre tentativas de checar se o container terminou.
_WAIT_POLL_SECONDS = 5

# Teto pra buscar os logs de um container que já terminou (ver _wait_for_exit)
# — não precisa ser o timeout inteiro da ferramenta, é só uma leitura rápida
# de algo que já existe; generoso o bastante pro daemon lento sob carga.
_LOGS_TIMEOUT_SECONDS = 30


def _retry_on_daemon_hiccup(fn, *, timeout: int, action: str):
    """Executa `fn()` retentando em caso de soneca transitória do daemon do
    Docker (mesmo padrão de _wait_for_exit, mas genérico o bastante pra
    qualquer chamada pontual — antes disso, só a checagem de status tinha
    esse retry; a criação do container e a leitura de logs não tinham
    nenhuma proteção, e ficavam presas pra sempre (criação) ou explodiam
    (logs) quando o daemon ficava lento sob muitos containers em paralelo,
    visto na prática com vários scans simultâneos)."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return fn()
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"daemon do Docker não respondeu a tempo ao tentar {action}") from exc
            logger.warning(
                "timeout tentando %s (daemon lento?) — tentando de novo: %s", action, exc,
            )
            time.sleep(min(_WAIT_POLL_SECONDS, remaining))


def _wait_for_exit(container, timeout: int) -> None:
    """Espera o container terminar, via polling — não uma única chamada
    HTTP bloqueada (container.wait(timeout=N) usa o socket do docker.sock
    com N como timeout de LEITURA dessa chamada específica).

    Visto na prática: mesmo com timeouts generosos (300-600s) configurados
    por ferramenta, o erro "UnixHTTPConnectionPool ... Read timed out"
    continuava acontecendo em várias ferramentas diferentes — sinal de que
    o gargalo não é a ferramenta demorar mais que o timeout, é o daemon do
    Docker demorando pra responder (host sobrecarregado com muitos
    containers em paralelo), o que derruba a chamada única de wait() à toa
    mesmo que o container estivesse prestes a terminar normalmente.

    Aqui, cada tentativa de checar o status tem seu próprio teto curto
    (_DOCKER_CLIENT_TIMEOUT, no cliente docker); se uma tentativa falhar por
    timeout/conexão, é só uma soneca transitória do daemon — tenta de novo
    no próximo ciclo, em vez de derrubar o job inteiro. O `timeout` (por
    ferramenta, configurável via .env) vira um prazo de parede — soma de
    todas as tentativas — não o timeout de uma chamada HTTP só."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            container.reload()
        except docker.errors.NotFound:
            return  # removido por fora (cancelamento concorrente) — nada mais a esperar
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as exc:
            logger.warning(
                "timeout consultando status do container %s (daemon lento?) — tentando de novo: %s",
                container.short_id, exc,
            )
        else:
            if container.status in ("exited", "dead"):
                return

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"container não terminou em {timeout}s")
        time.sleep(min(_WAIT_POLL_SECONDS, remaining))


def _read_output_file(local_dir: str | None, output_file: str) -> str | None:
    if not local_dir:
        return None
    path = os.path.join(local_dir, output_file)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def run(
    cmd: list[str],
    *,
    cpuset: int | None = None,
    cap_add: list[str] | None = None,
    output_file: str | None = None,
    extra_ro_mounts: dict[str, str] | None = None,
    timeout: int = 300,
    on_started: "callable | None" = None,
    on_finished: "callable | None" = None,
) -> str:
    """Executa `cmd` em um container efêmero da imagem kali-tools.

    Por padrão captura e devolve o stdout/stderr do container. Se `output_file`
    for informado, monta um diretório de troca (bind mount) em /data dentro do
    container, e devolve o conteúdo de `output_file` após a execução —
    necessário para ferramentas que não sabem escrever a saída em stdout
    (nikto).

    `extra_ro_mounts` (host_path -> container_path) monta arquivos adicionais
    somente-leitura — usado para a wordlist customizada do gobuster (ver
    wordlists.py); read-only porque a ferramenta só precisa ler o arquivo,
    nunca escrever nele.

    `on_started(container_id)`, se informado, é chamado assim que o container
    sobe — usado para gravar o container_id no job e permitir cancelamento
    (ver stop_container()).

    `on_finished(local_dir)`, se informado, é chamado com o diretório de troca
    (mesmo de output_file) logo antes dele ser apagado — dá à chamadora a
    chance de salvar algo além do texto de output_file (ex: o screenshot do
    gowitness, que é um arquivo binário à parte; ver screenshots.py).
    """
    volumes = None
    exchange_id = None
    local_dir = None

    if output_file:
        exchange_id = uuid.uuid4().hex
        host_dir = f"{config.HOST_EXCHANGE_DIR}/{exchange_id}"
        local_dir = f"{config.EXCHANGE_DIR}/{exchange_id}"
        os.makedirs(local_dir, exist_ok=True)
        volumes = {host_dir: {"bind": "/data", "mode": "rw"}}

    if extra_ro_mounts:
        volumes = volumes or {}
        for host_path, container_path in extra_ro_mounts.items():
            volumes[host_path] = {"bind": container_path, "mode": "ro"}

    container = _retry_on_daemon_hiccup(
        lambda: _docker_client().containers.run(
            config.KALI_IMAGE,
            cmd,
            detach=True,
            cpuset_cpus=str(cpuset) if cpuset is not None else None,
            cap_add=cap_add or [],
            volumes=volumes,
            working_dir="/data" if output_file else None,
        ),
        timeout=timeout,
        action="criar o container",
    )

    if on_started:
        try:
            on_started(container.id)
        except Exception:
            logger.exception("on_started callback falhou para o container %s", container.id)

    try:
        # Ferramentas de recon costumam sair com código != 0 mesmo sem falha
        # real (ex: nikto retorna != 0 quando não encontra nada), por isso
        # não tratamos exit code como erro — só como informação de log.
        # Um cancelamento (stop_container chamado de fora) também faz a
        # espera retornar aqui normalmente (container removido).
        try:
            _wait_for_exit(container, timeout)
        except TimeoutError:
            # Ferramentas que escrevem output_file incrementalmente (ver
            # wayback_fetch.py) já têm o que foi produzido até aqui no bind
            # mount, mesmo com o container prestes a ser morto à força no
            # finally — devolve esse parcial em vez de descartar tudo.
            partial = _read_output_file(local_dir, output_file) if output_file else None
            if partial and partial.strip():
                logger.warning(
                    "container %s não terminou em %ss — devolvendo resultado parcial (%d bytes) do arquivo de saída",
                    container.short_id, timeout, len(partial),
                )
                return partial
            raise
        try:
            logs = _retry_on_daemon_hiccup(
                lambda: container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace"),
                timeout=_LOGS_TIMEOUT_SECONDS,
                action="buscar os logs do container",
            )
        except docker.errors.NotFound:
            # Container já tinha sumido entre o fim do _wait_for_exit e essa
            # leitura (visto na prática sob carga pesada: o daemon fica tão
            # sobrecarregado que perde o rastro do container mesmo ele tendo
            # terminado normalmente) — mesmo espírito do timeout acima:
            # aproveita o que já foi escrito no output_file em vez de
            # derrubar o job inteiro por causa só dos logs de stdout/stderr.
            logger.warning(
                "container %s sumiu antes de buscar os logs (daemon sobrecarregado?)", container.short_id,
            )
            logs = ""

        if output_file:
            return _read_output_file(local_dir, output_file) or ""
        return logs
    finally:
        if on_finished and local_dir:
            try:
                on_finished(local_dir)
            except Exception:
                logger.exception("on_finished callback falhou para o container %s", container.id)
        try:
            container.remove(force=True)
        except docker.errors.NotFound:
            pass  # já removido por stop_container() (cancelamento concorrente)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            # Daemon sobrecarregado bem na hora da limpeza — best-effort, não
            # vale a pena um retry aqui (é só remoção de um container que já
            # terminou; se falhar, fica pra próxima faxina/GC do Docker).
            logger.warning("timeout removendo o container %s (daemon lento?) — deixando pra depois", container.short_id)
        if local_dir:
            shutil.rmtree(local_dir, ignore_errors=True)


def stop_container(container_id: str) -> bool:
    """Para e remove um container do Kali em execução — usado ao cancelar um
    job. Retorna False se o container já não existir mais (ex: já tinha
    terminado sozinho)."""
    try:
        container = _docker_client().containers.get(container_id)
    except docker.errors.NotFound:
        return False
    try:
        container.stop(timeout=5)
    except docker.errors.APIError:
        pass
    try:
        container.remove(force=True)
    except docker.errors.NotFound:
        pass
    return True
