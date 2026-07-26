import csv
import io
import json
import zipfile
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from . import opensearch_client

# Mesmo teto pragmático já usado nas outras queries "traga tudo" do projeto
# (query_subdomains, query_alive_urls etc.) — sem scroll/PIT por enquanto.
MAX_ROWS = 10000

MAX_PDF_ROWS_PER_INDEX = 500
MAX_PDF_COLUMNS = 6
MAX_CELL_CHARS = 60

# Campos redundantes com o contexto já mostrado no relatório (cliente/scan já
# está no cabeçalho da seção) — não valem uma coluna própria no PDF.
PDF_EXCLUDE_FIELDS = {"client", "scan_id", "_id"}
PDF_PRIORITY_FIELDS = ["tool", "target", "@timestamp"]

# Colunas curadas por índice — sem isso, a seleção automática (alfabética)
# pode deixar de fora o campo mais importante da ferramenta (ex: "severity"
# do nuclei) só porque outro campo menos útil vem antes no alfabeto. Um
# sufixo sem entrada aqui cai no fallback automático (columns genéricas) —
# ferramenta nova continua funcionando, só sem essa curadoria.
PDF_PREFERRED_COLUMNS = {
    "subdomains": ["subdomain", "domain", "tool"],
    "httpx": ["url", "status_code", "alive", "tool"],
    "dns": ["subdomain", "ips", "resolved"],
    "wayback": ["url", "has_params", "tool"],
    "katana": ["url", "domain"],
    "harvester": ["type", "value"],
    "rdap-domain": ["domain", "handle", "registrant", "nameservers"],
    "rdap-network": ["handle", "start_address", "end_address", "cidr", "org"],
    "masscan": ["ip", "port", "proto", "state"],
    "nmap": ["ip", "hostname", "port", "service", "product", "version"],
    "nikto": ["host", "uri", "description"],
    "nuclei": ["severity", "template_id", "host", "matched_at", "cve"],
    "gobuster": ["url", "path", "status_code", "size"],
    "jobs": ["tool", "target", "status", "doc_count", "error"],
    "scans": ["targets", "gobuster_wordlist", "@timestamp"],
    "wordlists": ["filename", "line_count", "size_bytes", "@timestamp"],
}


# Campos que variam entre "duplicatas" do mesmo achado — qual tool achou,
# em qual scan, e quando. Duas ferramentas achando o mesmo subdomínio (soma
# positiva) ou o mesmo scan rodado de novo em outro dia são exatamente os
# dois casos que geram essas repetições no dia a dia; o resto do documento
# sendo idêntico é o que define "é o mesmo achado".
DEDUP_IGNORE_FIELDS = {"client", "scan_id", "tool", "@timestamp", "_id", "first_seen"}


def dedup_key(doc: dict) -> tuple:
    def normalize(v):
        return json.dumps(v, sort_keys=True, ensure_ascii=False) if isinstance(v, (list, dict)) else v

    return tuple(sorted((k, normalize(v)) for k, v in doc.items() if k not in DEDUP_IGNORE_FIELDS))


def _dedupe(docs: list[dict]) -> list[dict]:
    """Uma linha por achado distinto, em vez de uma por (achado, tool, scan).
    Não descarta a informação de quais ferramentas concordam — junta em
    "tool" (lista) e conta as repetições em "_dedup_count", já que isso é um
    sinal útil (um achado confirmado por 3 ferramentas/scans é mais forte que
    um confirmado por 1)."""
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []
    for doc in docs:
        key = dedup_key(doc)
        if key not in groups:
            groups[key] = dict(doc)
            groups[key]["_dedup_count"] = 0
            order.append(key)
        group = groups[key]
        group["_dedup_count"] += 1
        tool = doc.get("tool")
        if tool:
            existing = group.get("tool")
            tools = set(existing) if isinstance(existing, list) else ({existing} if existing else set())
            tools.add(tool)
            group["tool"] = sorted(tools)
    return [groups[k] for k in order]


def _fetch_all(
    client_name: str, suffix: str, *, q: str | None = None, filters: dict | None = None, unique: bool = False,
) -> list[dict]:
    result = opensearch_client.search_findings(client_name, suffix, q=q, filters=filters, size=MAX_ROWS)
    items = result["items"]
    return _dedupe(items) if unique else items


def _format_scan_label(scan: dict) -> str:
    """scan_id é um hex opaco — troca por algo legível (data + alvos
    originais) no relatório, já que é exatamente essa identidade "por data de
    execução" que dá sentido a filtrar/exportar por um scan específico."""
    raw_ts = scan.get("@timestamp", "")
    try:
        when = datetime.fromisoformat(raw_ts).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        when = raw_ts
    targets = ", ".join(scan.get("targets", []))
    return f"{when} — {targets}" if targets else when


def _describe_filters(client_name: str, q: str | None, filters: dict | None, unique: bool = False) -> str | None:
    """Texto tipo 'severity=critical, q=login' para deixar registrado no
    relatório qual recorte gerou aqueles achados — sem isso, um PDF filtrado
    fica indistinguível de um completo."""
    parts = []
    for k, v in (filters or {}).items():
        # v pode ser string (valor único, como sempre foi) ou lista (múltiplos
        # valores pro mesmo campo, ex: vários status selecionados de uma vez).
        values = v if isinstance(v, list) else [v]
        if k == "scan_id":
            labels = [(_format_scan_label(s) if (s := opensearch_client.get_scan(client_name, sid)) else sid) for sid in values]
            parts.append(f"scan={' ou '.join(labels)}")
        else:
            parts.append(f"{k}={' ou '.join(values)}")
    if q:
        parts.insert(0, f"q={q}")
    if unique:
        parts.append("únicos (agrupado por achado, ver _dedup_count)")
    return ", ".join(parts) if parts else None


def _client_suffixes(client_name: str) -> list[str]:
    return [i["suffix"] for i in opensearch_client.list_client_indices(client_name)]


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------

def export_json(
    client_name: str, suffix: str | None = None, *,
    q: str | None = None, filters: dict | None = None, unique: bool = False,
) -> bytes:
    if suffix:
        # filtros/únicos só fazem sentido num índice só — no nível de
        # cliente, cada índice tem seu próprio schema de campos.
        data = _fetch_all(client_name, suffix, q=q, filters=filters, unique=unique)
    else:
        data = {s: _fetch_all(client_name, s) for s in _client_suffixes(client_name)}
    return json.dumps(data, indent=2, ensure_ascii=False, default=str).encode("utf-8")


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------

def _docs_to_csv(docs: list[dict]) -> bytes:
    if not docs:
        return b""
    fieldnames: list[str] = []
    seen = set()
    for doc in docs:
        for key in doc.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for doc in docs:
        row = {
            k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v)
            for k, v in doc.items()
        }
        writer.writerow(row)
    return buf.getvalue().encode("utf-8")


def export_csv(
    client_name: str, suffix: str | None = None, *,
    q: str | None = None, filters: dict | None = None, unique: bool = False,
) -> tuple[bytes, str]:
    """Retorna (conteudo, content_type). Um índice só -> CSV puro. Nível de
    cliente (múltiplos índices, schemas diferentes) -> ZIP com um CSV por
    índice, já que CSV não representa mais de uma tabela por arquivo."""
    if suffix:
        return _docs_to_csv(_fetch_all(client_name, suffix, q=q, filters=filters, unique=unique)), "text/csv"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for s in _client_suffixes(client_name):
            zf.writestr(f"{s}.csv", _docs_to_csv(_fetch_all(client_name, s)))
    return buf.getvalue(), "application/zip"


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------

def _pdf_columns(suffix: str, docs: list[dict]) -> list[str]:
    seen = set()
    keys: list[str] = []
    for doc in docs:
        for key in doc.keys():
            if key in PDF_EXCLUDE_FIELDS or key in seen:
                continue
            seen.add(key)
            keys.append(key)

    preferred = PDF_PREFERRED_COLUMNS.get(suffix)
    if preferred:
        ordered = [k for k in preferred if k in seen]
    else:
        ordered = [k for k in PDF_PRIORITY_FIELDS if k in seen] + sorted(
            k for k in keys if k not in PDF_PRIORITY_FIELDS
        )
    return ordered[:MAX_PDF_COLUMNS]


def _pdf_cell(value) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, list) and all(isinstance(v, (str, int, float, bool)) for v in value):
        value = ", ".join(str(v) for v in value)
    elif isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    text = str(value)
    return text if len(text) <= MAX_CELL_CHARS else text[: MAX_CELL_CHARS - 1] + "…"


def _pdf_section(story: list, styles, suffix: str, docs: list[dict]) -> None:
    story.append(Paragraph(f"{suffix} ({len(docs)} achados)", styles["Heading2"]))
    if not docs:
        story.append(Paragraph("Nenhum achado.", styles["BodyText"]))
        story.append(Spacer(1, 16))
        return

    shown = docs[:MAX_PDF_ROWS_PER_INDEX]
    columns = _pdf_columns(suffix, shown)
    data = [columns] + [[_pdf_cell(doc.get(c)) for c in columns] for doc in shown]

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2a78d6")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    story.append(table)

    if len(docs) > MAX_PDF_ROWS_PER_INDEX:
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"Mostrando {MAX_PDF_ROWS_PER_INDEX} de {len(docs)} — exporte em JSON/CSV para o total completo.",
            styles["Italic"],
        ))
    story.append(Spacer(1, 20))


def export_pdf(
    client_name: str, suffix: str | None = None, *,
    q: str | None = None, filters: dict | None = None, unique: bool = False,
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), title=f"super-recon - {client_name}")
    styles = getSampleStyleSheet()

    story = [
        Paragraph(f"super-recon — relatório de {client_name}", styles["Title"]),
        Paragraph(f"Gerado em {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["BodyText"]),
    ]
    filter_desc = _describe_filters(client_name, q, filters, unique) if suffix else None
    if filter_desc:
        story.append(Paragraph(f"Filtros aplicados: {filter_desc}", styles["BodyText"]))
    story.append(Spacer(1, 20))

    if suffix:
        _pdf_section(story, styles, suffix, _fetch_all(client_name, suffix, q=q, filters=filters, unique=unique))
    else:
        for s in _client_suffixes(client_name):
            _pdf_section(story, styles, s, _fetch_all(client_name, s))

    doc.build(story)
    return buf.getvalue()


# --------------------------------------------------------------------------
# Relatório executivo (score de risco agregado — ver risk_score.py)
# --------------------------------------------------------------------------

# Mesma paleta de cores dos badges de severidade no frontend (ver
# frontend/src/styles.css: --status-good/warning/serious/critical/muted) —
# o PDF precisa bater visualmente com o que o card do dashboard mostra.
_TIER_COLORS = {
    "Nenhum": colors.HexColor("#898781"),
    "Baixo": colors.HexColor("#0ca30c"),
    "Médio": colors.HexColor("#fab219"),
    "Alto": colors.HexColor("#ec835a"),
    "Crítico": colors.HexColor("#d03b3b"),
}

_SEVERITY_LABELS = {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "info": "Informativo"}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Largura útil de uma página A4 retrato com as margens padrão do
# SimpleDocTemplate (72pt cada lado) — usada pra dimensionar as tabelas do
# relatório executivo sem estourar a página (diferente do export_pdf acima,
# que usa landscape pra caber tabelas largas de dado bruto).
_CONTENT_WIDTH = 450


def _risk_tier_banner(story: list, styles, tier: str, score: int, reason: str | None) -> None:
    color = _TIER_COLORS.get(tier, _TIER_COLORS["Nenhum"])
    table = Table([[f"Nível de risco: {tier} (score {score})"]], colWidths=[_CONTENT_WIDTH])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 16),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(table)
    story.append(Spacer(1, 8))
    if reason:
        story.append(Paragraph(reason, styles["Italic"]))
    story.append(Spacer(1, 16))


def _risk_severity_table(story: list, styles, severity_counts: dict, wpscan_vuln_count: int) -> None:
    story.append(Paragraph("Achados por severidade (nuclei + dalfox)", styles["Heading2"]))
    rows = [["Severidade", "Quantidade"]]
    for sev in _SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count:
            rows.append([_SEVERITY_LABELS[sev], str(count)])
    if wpscan_vuln_count:
        rows.append(["Vulnerabilidades WordPress (WPScan)", str(wpscan_vuln_count)])

    if len(rows) == 1:
        story.append(Paragraph("Nenhum achado com severidade identificado.", styles["BodyText"]))
        story.append(Spacer(1, 16))
        return

    table = Table(rows, colWidths=[_CONTENT_WIDTH - 120, 120])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2a78d6")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))


def _risk_surface_section(story: list, styles, surface: dict) -> None:
    story.append(Paragraph("Superfície de ataque (contexto — não entra no score)", styles["Heading2"]))
    rows = [
        ["Subdomínios descobertos", str(surface.get("subdomains", 0))],
        ["Hosts vivos (HTTP)", str(surface.get("live_hosts", 0))],
        ["Portas abertas identificadas", str(surface.get("open_ports", 0))],
    ]
    table = Table(rows, colWidths=[_CONTENT_WIDTH - 120, 120])
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))


def _risk_top_findings_section(story: list, styles, findings: list[dict]) -> None:
    story.append(Paragraph("Achados mais graves", styles["Heading2"]))
    if not findings:
        story.append(Paragraph("Nenhum achado crítico ou alto identificado.", styles["BodyText"]))
        return

    rows = [["Severidade", "Ferramenta", "Nome / host", "CVE"]]
    for f in findings:
        name = f.get("name") or f.get("template_id")
        host = f.get("host") or f.get("url") or "-"
        label = f"{name} — {host}" if name else host
        rows.append([
            _SEVERITY_LABELS.get(f.get("severity"), f.get("severity") or "-"),
            f.get("_suffix", "-"),
            _pdf_cell(label),
            f.get("cve") or "-",
        ])

    table = Table(rows, colWidths=[55, 60, 245, 90], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2a78d6")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
    ]))
    story.append(table)


def export_risk_report(client_name: str) -> bytes:
    """PDF do relatório executivo — a mesma agregação que alimenta o card
    do dashboard (opensearch_client.risk_summary), num formato pra
    apresentar a um cliente não-técnico: nível de risco em destaque, achados
    por severidade, superfície de ataque como contexto e os achados mais
    graves nomeados (não só a contagem)."""
    summary = opensearch_client.risk_summary(client_name)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"super-recon - relatório executivo - {client_name}")
    styles = getSampleStyleSheet()

    story = [
        Paragraph(f"super-recon — relatório executivo de {client_name}", styles["Title"]),
        Paragraph(f"Gerado em {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["BodyText"]),
        Spacer(1, 16),
    ]
    _risk_tier_banner(story, styles, summary["tier"], summary["score"], summary.get("reason"))
    _risk_severity_table(story, styles, summary["severity_counts"], summary["wpscan_vulnerabilities"])
    _risk_surface_section(story, styles, summary["surface"])
    _risk_top_findings_section(story, styles, summary["top_findings"])

    doc.build(story)
    return buf.getvalue()
