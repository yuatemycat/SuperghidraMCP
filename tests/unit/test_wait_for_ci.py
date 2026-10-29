"""Unit tests for release CI gatekeeper (scripts/wait_for_ci.py)."""

import json
from unittest.mock import patch

import pytest

import scripts.wait_for_ci as wait_ci


def test_is_target_workflow():
    assert wait_ci.is_target_workflow("Pytest Local Repo Devcontainer Across Versions", "all")
    assert wait_ci.is_target_workflow("Pytest Local Repo macOS Smoke", "all")
    assert wait_ci.is_target_workflow("Pytest Local Repo macOS Compatibility", "all")
    assert not wait_ci.is_target_workflow("Pytest Local Repo CLI Devcontainer Across Versions", "all")

    assert wait_ci.is_target_workflow("Pytest Local Repo CLI Devcontainer Across Versions", "cli")
    assert not wait_ci.is_target_workflow("Pytest Local Repo Devcontainer Across Versions", "cli")

    assert not wait_ci.is_target_workflow("Release", "all")
    assert not wait_ci.is_target_workflow("Release Cli", "cli")
    assert not wait_ci.is_target_workflow("Create and publish a Docker image", "all")


def test_fetch_runs_matches_sha():
    mock_runs = [
        {"databaseId": 101, "name": "Devcontainer", "headSha": "abcdef1234567890"},
        {"databaseId": 102, "name": "Other", "headSha": "9999999999999999"},
    ]
    with patch("subprocess.check_output", return_value=json.dumps(mock_runs)):
        matched = wait_ci.fetch_runs("test/repo", "abcdef123456")
        assert len(matched) == 1
        assert matched[0]["databaseId"] == 101


def test_fetch_runs_raises_on_persistent_failure():
    with patch("subprocess.check_output", side_effect=RuntimeError("gh error")), patch("time.sleep"):
        with pytest.raises(RuntimeError, match="Failed to fetch workflow runs"):
            wait_ci.fetch_runs("test/repo", "abcdef", max_retries=2)


def test_main_aborts_on_discovery_timeout(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["wait_for_ci.py", "--commit", "abc", "--component", "cli", "--discovery-timeout", "1", "--min-runs", "1"],
    )
    with patch("scripts.wait_for_ci.fetch_runs", return_value=[]), patch("time.sleep"):
        code = wait_ci.main()
        assert code == 1, "Must exit 1 (abort) if expected workflows never appear!"


def test_main_aborts_on_workflow_failure(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["wait_for_ci.py", "--commit", "abc", "--component", "cli", "--discovery-timeout", "5", "--min-runs", "1"],
    )
    failed_run = [
        {
            "databaseId": 201,
            "name": "Pytest Local Repo CLI Devcontainer Across Versions",
            "headSha": "abc",
            "status": "completed",
            "conclusion": "failure",
            "url": "https://github.com/test/run/201",
        }
    ]
    with patch("scripts.wait_for_ci.fetch_runs", return_value=failed_run):
        code = wait_ci.main()
        assert code == 1, "Must exit 1 if peer workflow failed!"


def test_main_dynamically_tracks_late_workflows_and_succeeds(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wait_for_ci.py",
            "--commit",
            "abc",
            "--component",
            "all",
            "--discovery-timeout",
            "5",
            "--min-runs",
            "1",
            "--interval",
            "1",
        ],
    )

    poll_states = [
        # Discovery: 1 workflow pending
        [
            {
                "databaseId": 301,
                "name": "Pytest Local Repo Devcontainer Across Versions",
                "headSha": "abc",
                "status": "in_progress",
                "conclusion": None,
            }
        ],
        # Poll 1: run 301 finished, but late run 302 just appeared!
        [
            {
                "databaseId": 301,
                "name": "Pytest Local Repo Devcontainer Across Versions",
                "headSha": "abc",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "databaseId": 302,
                "name": "Pytest Local Repo macOS Smoke",
                "headSha": "abc",
                "status": "in_progress",
                "conclusion": None,
            },
        ],
        # Poll 2: both completed successfully
        [
            {
                "databaseId": 301,
                "name": "Pytest Local Repo Devcontainer Across Versions",
                "headSha": "abc",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "databaseId": 302,
                "name": "Pytest Local Repo macOS Smoke",
                "headSha": "abc",
                "status": "completed",
                "conclusion": "success",
            },
        ],
    ]

    with patch("scripts.wait_for_ci.fetch_runs", side_effect=poll_states), patch("time.sleep"):
        code = wait_ci.main()
        assert code == 0, "Must succeed only after both initial and dynamically discovered runs pass!"
