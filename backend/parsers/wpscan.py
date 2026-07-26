import json

from .common import base_doc


def _references(refs: dict) -> list[str]:
    """Achata references (url/cve/wpvulndb) da WPVulnDB numa lista de
    strings só de URL — cve/wpvulndb vêm como ids soltos, não links."""
    out = list(refs.get("url") or [])
    out += [f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in (refs.get("cve") or [])]
    out += [f"https://wpscan.com/vulnerability/{vid}" for vid in (refs.get("wpvulndb") or [])]
    return out


def _vuln_docs(base: dict, vulnerabilities: list[dict], *, finding_type: str, component: str, component_version: str | None) -> list[dict]:
    docs = []
    for vuln in vulnerabilities:
        doc = dict(base)
        doc.update({
            "finding_type": finding_type,
            "component": component,
            "component_version": component_version,
            "title": vuln.get("title"),
            "fixed_in": vuln.get("fixed_in"),
            "url": None,
            "confidence": None,
            "references": _references(vuln.get("references") or {}),
        })
        docs.append(doc)
    return docs


def parse(raw_text: str, *, client: str, scan_id: str, target: str) -> list[dict]:
    try:
        obj = json.loads(raw_text)
    except json.JSONDecodeError:
        return []

    base = base_doc(client, scan_id, target, "wpscan")

    # Alvo não é WordPress (ou não respondeu) — sem achado, não é erro (mesmo
    # tratamento que qualquer outra ferramenta que roda em URL viva e não
    # encontra nada, ex: nikto/gobuster).
    if obj.get("scan_aborted"):
        return []

    docs: list[dict] = []

    for item in obj.get("interesting_findings") or []:
        doc = dict(base)
        doc.update({
            "finding_type": "interesting",
            "component": None,
            "component_version": None,
            "title": item.get("to_s"),
            "fixed_in": None,
            "url": item.get("url"),
            "confidence": item.get("confidence"),
            "references": _references(item.get("references") or {}),
        })
        docs.append(doc)

    version = obj.get("version") or {}
    if version.get("number"):
        # "status" (latest/insecure/outdated) é vocabulário do próprio wpscan,
        # sempre em inglês — não precisa de tradução, ao contrário do texto
        # abaixo pra "user" (ver DataTable.jsx: esse aqui é composto por nós).
        status = version.get("status")
        title = f"WordPress {version.get('number')}" + (f" ({status})" if status else "")
        doc = dict(base)
        doc.update({
            "finding_type": "core_version",
            "component": "wordpress core",
            "component_version": version.get("number"),
            "title": title,
            "fixed_in": None,
            "url": None,
            "confidence": version.get("confidence"),
            "references": [],
        })
        docs.append(doc)
    docs += _vuln_docs(
        base, version.get("vulnerabilities") or [],
        finding_type="core_vulnerability", component="wordpress core", component_version=version.get("number"),
    )

    themes = dict(obj.get("themes") or {})
    main_theme = obj.get("main_theme")
    if main_theme and main_theme.get("slug"):
        themes.setdefault(main_theme["slug"], main_theme)
    for slug, theme in themes.items():
        theme_version = (theme.get("version") or {}).get("number")
        docs += _vuln_docs(
            base, theme.get("vulnerabilities") or [],
            finding_type="theme_vulnerability", component=slug, component_version=theme_version,
        )

    for slug, plugin in (obj.get("plugins") or {}).items():
        plugin_version = (plugin.get("version") or {}).get("number")
        docs += _vuln_docs(
            base, plugin.get("vulnerabilities") or [],
            finding_type="plugin_vulnerability", component=slug, component_version=plugin_version,
        )

    for username, user in (obj.get("users") or {}).items():
        # title = username puro (sem frase) — a UI compõe a frase traduzida
        # (ver DataTable.jsx, mesmo padrão do IpProvenance.jsx: dado bruto
        # aqui, texto no idioma selecionado só no frontend).
        doc = dict(base)
        doc.update({
            "finding_type": "user",
            "component": None,
            "component_version": None,
            "title": username,
            "fixed_in": None,
            "url": None,
            "confidence": user.get("confidence"),
            "references": [],
        })
        docs.append(doc)

    return docs
