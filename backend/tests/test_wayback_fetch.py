import io
import json
from contextlib import contextmanager

from app import wayback_fetch


def _resp(data):
    @contextmanager
    def cm(*_a, **_kw):
        yield io.BytesIO(json.dumps(data).encode())
    return cm


def test_build_page_url_without_resume_key():
    url = wayback_fetch.build_page_url("acme.com", None)
    assert "url=*.acme.com/*" in url
    assert "resumeKey" not in url


def test_build_page_url_with_resume_key():
    url = wayback_fetch.build_page_url("acme.com", "abc123")
    assert "resumeKey=abc123" in url


def test_split_page_last_page_has_no_resume_key():
    data = [["original"], ["http://a.com/1"], ["http://a.com/2"]]
    urls, resume_key = wayback_fetch.split_page(data)
    assert urls == ["http://a.com/1", "http://a.com/2"]
    assert resume_key is None


def test_split_page_with_resume_key():
    data = [["original"], ["http://a.com/1"], [], ["someResumeKey"]]
    urls, resume_key = wayback_fetch.split_page(data)
    assert urls == ["http://a.com/1"]
    assert resume_key == "someResumeKey"


def test_fetch_paginates_across_multiple_pages():
    pages = [
        [["original"], ["http://a.com/1"], ["http://a.com/2"], [], ["key1"]],
        [["original"], ["http://a.com/3"]],
    ]
    calls = []

    def fake_urlopen(url, timeout=None):
        calls.append(url)
        return _resp(pages[len(calls) - 1])()

    out = io.StringIO()
    err = io.StringIO()
    seen = wayback_fetch.fetch("acme.com", 100, urlopen=fake_urlopen, out=out, err=err)

    assert seen == 3
    assert out.getvalue().splitlines() == ["http://a.com/1", "http://a.com/2", "http://a.com/3"]
    assert len(calls) == 2
    assert "resumeKey=key1" in calls[1]


def test_fetch_stops_at_max_records_mid_page():
    page = [["original"], ["http://a.com/1"], ["http://a.com/2"], ["http://a.com/3"]]

    def fake_urlopen(url, timeout=None):
        return _resp(page)()

    out = io.StringIO()
    seen = wayback_fetch.fetch("acme.com", 2, urlopen=fake_urlopen, out=out, err=io.StringIO())

    assert seen == 2
    assert out.getvalue().splitlines() == ["http://a.com/1", "http://a.com/2"]


def test_fetch_gives_up_after_repeated_page_failures_but_keeps_partial():
    calls = []

    def fake_urlopen(url, timeout=None):
        calls.append(url)
        if len(calls) == 1:
            return _resp([["original"], ["http://a.com/1"], [], ["key1"]])()
        raise TimeoutError("simulado")

    out = io.StringIO()
    err = io.StringIO()
    seen = wayback_fetch.fetch("acme.com", 100, urlopen=fake_urlopen, out=out, err=err)

    assert seen == 1
    assert out.getvalue().splitlines() == ["http://a.com/1"]
    assert len(calls) == 1 + wayback_fetch.MAX_PAGE_RETRIES  # 1 página ok + retries esgotados na 2ª
    assert "desistindo" in err.getvalue()
