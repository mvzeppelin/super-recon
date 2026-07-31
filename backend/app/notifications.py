import logging

import requests

from . import config, util

logger = logging.getLogger(__name__)

_SLACK_API_URL = "https://slack.com/api/chat.postMessage"
_MAX_LISTED_FINDINGS = 10
_HTTP_TIMEOUT = 10


def _build_message(client_name: str, tool: str, target: str, docs: list[dict]) -> str:
    count = len(docs)
    header = f"🔴 *{count} achado(s) crítico(s)* — `{tool}` em `{target}` (cliente `{client_name}`)"

    lines = [header]
    for doc in docs[:_MAX_LISTED_FINDINGS]:
        label = doc.get("template_id") or doc.get("name") or "?"
        where = doc.get("matched_at") or doc.get("host") or ""
        lines.append(f"• {label} — {where}" if where else f"• {label}")
    if count > _MAX_LISTED_FINDINGS:
        lines.append(f"… e mais {count - _MAX_LISTED_FINDINGS}.")

    if config.PUBLIC_BASE_URL:
        lines.append(f"<{config.PUBLIC_BASE_URL}/clients/{client_name}/{tool}|Ver no dashboard>")

    return "\n".join(lines)


def _send_slack(message: str) -> None:
    resp = requests.post(
        _SLACK_API_URL,
        headers={"Authorization": f"Bearer {config.SLACK_BOT_TOKEN}"},
        json={"channel": config.SLACK_CHANNEL, "text": message},
        timeout=_HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    body = resp.json()
    if not body.get("ok"):
        # Slack responde 200 OK mesmo em erro de aplicação (token inválido,
        # bot não está no canal etc.) — o motivo real vem em body["error"].
        logger.error("Slack recusou a notificação: %s", body.get("error"))


def _send_webhook(payload: dict) -> None:
    # Revalida a cada disparo, não só quando a URL foi salva (ver
    # settings_registry.py) — defesa contra TOCTOU: o hostname podia
    # resolver pra um IP público na hora de salvar e pra um IP interno
    # depois (DNS que o admin não controla), ver util.is_safe_webhook_url.
    if not util.is_safe_webhook_url(config.NOTIFY_WEBHOOK_URL):
        logger.error(
            "NOTIFY_WEBHOOK_URL não passa mais na checagem de segurança (SSRF) — notificação não enviada. "
            "Revise o valor na tela Configurações."
        )
        return
    resp = requests.post(config.NOTIFY_WEBHOOK_URL, json=payload, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()


def notify_findings(client_name: str, tool: str, target: str, docs: list[dict]) -> None:
    """Notifica (Slack e/ou webhook genérico — o que estiver configurado)
    quando algum achado recém-indexado tem severidade em NOTIFY_SEVERITIES.
    Uma mensagem por execução de ferramenta, não uma por achado — senão uma
    ferramenta que acha vários de uma vez inundaria o canal. Chamado de
    dentro do pipeline síncrono (_run_and_index em tasks.py); qualquer falha
    aqui é só logada, nunca derruba o job de recon em si."""
    if not (config.SLACK_BOT_TOKEN and config.SLACK_CHANNEL) and not config.NOTIFY_WEBHOOK_URL:
        return

    qualifying = [d for d in docs if str(d.get("severity") or "").lower() in config.NOTIFY_SEVERITIES]
    if not qualifying:
        return

    message = _build_message(client_name, tool, target, qualifying)

    if config.SLACK_BOT_TOKEN and config.SLACK_CHANNEL:
        try:
            _send_slack(message)
        except Exception:
            logger.exception("falha ao notificar Slack (cliente=%s, tool=%s)", client_name, tool)

    if config.NOTIFY_WEBHOOK_URL:
        try:
            _send_webhook(
                {"text": message, "client": client_name, "tool": tool, "target": target, "findings": qualifying}
            )
        except Exception:
            logger.exception("falha ao notificar webhook (cliente=%s, tool=%s)", client_name, tool)


def notify_health(problems: list[str]) -> None:
    """Chamado pelo monitor de saúde da plataforma (health_monitor.py) só na
    transição de estado (bom->ruim ou ruim->bom) — nunca a cada checagem,
    senão um problema persistente (ex: cluster amarelo por horas) inundaria
    o canal. `problems` vazio = recuperação (estava ruim, voltou ao normal).
    Reaproveita o mesmo Slack/webhook de achado crítico; qualquer falha aqui
    é só logada."""
    if not (config.SLACK_BOT_TOKEN and config.SLACK_CHANNEL) and not config.NOTIFY_WEBHOOK_URL:
        return

    if problems:
        message = "\n".join(["🔴 *Problema(s) detectado(s) na plataforma:*", *(f"• {p}" for p in problems)])
    else:
        message = "🟢 *Plataforma voltou ao normal* — todos os checks de saúde passando."
    if config.PUBLIC_BASE_URL:
        message += f"\n<{config.PUBLIC_BASE_URL}|Ver dashboard>"

    if config.SLACK_BOT_TOKEN and config.SLACK_CHANNEL:
        try:
            _send_slack(message)
        except Exception:
            logger.exception("falha ao notificar Slack (health)")

    if config.NOTIFY_WEBHOOK_URL:
        try:
            _send_webhook({"text": message, "type": "health", "problems": problems})
        except Exception:
            logger.exception("falha ao notificar webhook (health)")
