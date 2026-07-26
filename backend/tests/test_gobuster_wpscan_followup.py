from unittest.mock import patch

from app import tasks


def _job_ctx():
    return {"client": "acme", "scan_id": "scan-001"}


def test_looks_like_directory_accepts_extensionless_path():
    assert tasks._looks_like_directory("/blog") is True
    assert tasks._looks_like_directory("/wp-content/uploads/wpforms/") is True


def test_looks_like_directory_rejects_file_extension():
    assert tasks._looks_like_directory("/robots.txt") is False
    assert tasks._looks_like_directory("/config.php") is False
    assert tasks._looks_like_directory("/wp-content/uploads/logo.png") is False


def test_followup_dispatches_wpscan_only_for_directory_like_hits():
    hits = [
        {"url": "http://x.com/blog", "path": "/blog"},
        {"url": "http://x.com/robots.txt", "path": "/robots.txt"},
        {"url": "http://x.com/old-site", "path": "/old-site"},
    ]
    with (
        patch.object(tasks, "_scan_cancelled", return_value=False),
        patch.object(tasks.opensearch_client, "query_gobuster_hits", return_value=hits),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks, "group") as mock_group,
    ):
        result = tasks.gobuster_wpscan_followup_task(None, _job_ctx(), "http://x.com")

    # As chamadas reais ficam dentro do primeiro (e único) argumento passado a group([...])
    signatures = mock_group.call_args.args[0]
    dispatched_targets = {sig.args[2] for sig in signatures}
    assert dispatched_targets == {"http://x.com/blog", "http://x.com/old-site"}
    assert result == {"url": "http://x.com", "subpaths_checked": 2}


def test_followup_excludes_root_url_from_subpaths():
    hits = [{"url": "http://x.com", "path": "/"}, {"url": "http://x.com/blog", "path": "/blog"}]
    with (
        patch.object(tasks, "_scan_cancelled", return_value=False),
        patch.object(tasks.opensearch_client, "query_gobuster_hits", return_value=hits),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks, "group") as mock_group,
    ):
        tasks.gobuster_wpscan_followup_task(None, _job_ctx(), "http://x.com")

    signatures = mock_group.call_args.args[0]
    dispatched_targets = {sig.args[2] for sig in signatures}
    assert dispatched_targets == {"http://x.com/blog"}


def test_followup_caps_at_max_subpaths():
    hits = [{"url": f"http://x.com/dir{i}", "path": f"/dir{i}"} for i in range(10)]
    with (
        patch.object(tasks, "_scan_cancelled", return_value=False),
        patch.object(tasks.opensearch_client, "query_gobuster_hits", return_value=hits),
        patch.object(tasks.opensearch_client, "queue_job", return_value="job-id"),
        patch.object(tasks, "group") as mock_group,
    ):
        result = tasks.gobuster_wpscan_followup_task(None, _job_ctx(), "http://x.com")

    assert result["subpaths_checked"] == tasks._GOBUSTER_WPSCAN_MAX_SUBPATHS


def test_followup_is_noop_when_no_directory_like_hits():
    hits = [{"url": "http://x.com/robots.txt", "path": "/robots.txt"}]
    with (
        patch.object(tasks, "_scan_cancelled", return_value=False),
        patch.object(tasks.opensearch_client, "query_gobuster_hits", return_value=hits),
        patch.object(tasks, "group") as mock_group,
    ):
        result = tasks.gobuster_wpscan_followup_task(None, _job_ctx(), "http://x.com")

    mock_group.assert_not_called()
    assert result == {"url": "http://x.com", "subpaths_checked": 0}


def test_followup_skips_when_scan_cancelled():
    with (
        patch.object(tasks, "_scan_cancelled", return_value=True),
        patch.object(tasks.opensearch_client, "query_gobuster_hits") as mock_query,
    ):
        result = tasks.gobuster_wpscan_followup_task(None, _job_ctx(), "http://x.com")

    mock_query.assert_not_called()
    assert result == {"url": "http://x.com", "status": "cancelled"}


def test_followup_skips_when_wpscan_disabled_for_scan():
    job_ctx = {"client": "acme", "scan_id": "scan-001", "enabled_tools": ["gobuster", "nikto"]}
    with (
        patch.object(tasks, "_scan_cancelled", return_value=False),
        patch.object(tasks.opensearch_client, "query_gobuster_hits") as mock_query,
    ):
        result = tasks.gobuster_wpscan_followup_task(None, job_ctx, "http://x.com")

    mock_query.assert_not_called()
    assert result == {"url": "http://x.com", "status": "wpscan_disabled"}
