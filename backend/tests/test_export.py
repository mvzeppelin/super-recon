from app import export


def test_csv_safe_prefixes_formula_equals():
    assert export._csv_safe("=cmd|'/c calc'!A1") == "'=cmd|'/c calc'!A1"


def test_csv_safe_prefixes_plus_minus_at():
    assert export._csv_safe("+1+1").startswith("'")
    assert export._csv_safe("-1+1").startswith("'")
    assert export._csv_safe("@SUM(A1)").startswith("'")


def test_csv_safe_leaves_normal_value_untouched():
    assert export._csv_safe("nginx/1.18.0") == "nginx/1.18.0"


def test_csv_safe_ignores_non_string_values():
    assert export._csv_safe(42) == 42
    assert export._csv_safe(None) is None


def test_docs_to_csv_sanitizes_formula_like_field():
    # achado com valor malicioso vindo do alvo escaneado (ex: banner de serviço)
    docs = [{"tool": "nmap", "banner": "=HYPERLINK(\"http://evil\")"}]
    csv_bytes = export._docs_to_csv(docs)
    text = csv_bytes.decode("utf-8")
    assert "'=HYPERLINK" in text
    assert "\n=HYPERLINK" not in text
