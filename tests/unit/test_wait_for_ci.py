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
        [
            "wait_for_ci.py",
            "--commit",
            "abc",
            "--component",
            "cli",
            "--discovery-timeout",
            "1",
            "--min-runs",
            "1",
            "--settle-seconds",
            "0",
        ],
    )
    with patch("scripts.wait_for_ci.fetch_runs", return_value=[]), patch("time.sleep"):
        code = wait_ci.main()
        assert code == 1, "Must exit 1 (abort) if expected workflows never appear!"


def test_main_aborts_on_workflow_failure(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wait_for_ci.py",
            "--commit",
            "abc",
            "--component",
            "cli",
            "--discovery-timeout",
            "5",
            "--min-runs",
            "1",
            "--settle-seconds",
            "0",
        ],
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
            "--settle-seconds",
            "0",
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


def test_main_settles_and_catches_third_run_starting_after_first_two_pass(monkeypatch):
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
            "2",
            "--settle-seconds",
            "2",
            "--interval",
            "1",
        ],
    )

    # Initial runs 401 & 402 pass immediately.
    # While settling, 403 (macOS compat) suddenly starts!
    # Finally, 403 completes successfully.
    r401_done = {
        "databaseId": 401,
        "name": "Pytest Local Repo Devcontainer Across Versions",
        "headSha": "abc",
        "status": "completed",
        "conclusion": "success",
    }
    r402_done = {
        "databaseId": 402,
        "name": "Pytest Local Repo macOS Smoke",
        "headSha": "abc",
        "status": "completed",
        "conclusion": "success",
    }
    r403_pending = {
        "databaseId": 403,
        "name": "Pytest Local Repo macOS Compatibility",
        "headSha": "abc",
        "status": "in_progress",
        "conclusion": None,
    }
    r403_done = {
        "databaseId": 403,
        "name": "Pytest Local Repo macOS Compatibility",
        "headSha": "abc",
        "status": "completed",
        "conclusion": "success",
    }

    poll_states = [
        # Discovery: 401 and 402 present
        [r401_done, r402_done],
        # Poll 1 (settling): 401 and 402 done, but 403 appears in_progress!
        [r401_done, r402_done, r403_pending],
        # Poll 2: 403 is still running
        [r401_done, r402_done, r403_pending],
        # Poll 3: 403 completed
        [r401_done, r402_done, r403_done],
        # Poll 4 (settle satisfied): all 3 done
        [r401_done, r402_done, r403_done],
        # Poll 5
        [r401_done, r402_done, r403_done],
    ]

    curr_time = [100.0]

    def fake_monotonic():
        return curr_time[0]

    def fake_sleep(s):
        curr_time[0] += s

    with (
        patch("scripts.wait_for_ci.fetch_runs", side_effect=poll_states),
        patch("time.monotonic", side_effect=fake_monotonic),
        patch("time.sleep", side_effect=fake_sleep),
    ):
        code = wait_ci.main()
        assert code == 0, "Must track late 3rd run and wait for its completion!"


def test_main_required_workflows_blocks_until_present(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wait_for_ci.py",
            "--commit",
            "abc",
            "--component",
            "all",
            "--required-workflows",
            "macos compatibility",
            "--discovery-timeout",
            "1",
            "--min-runs",
            "1",
            "--settle-seconds",
            "0",
        ],
    )
    # Only devcontainer present, macos compatibility missing
    r_only_dev = [
        {
            "databaseId": 501,
            "name": "Pytest Local Repo Devcontainer Across Versions",
            "headSha": "abc",
            "status": "completed",
            "conclusion": "success",
        }
    ]
    with patch("scripts.wait_for_ci.fetch_runs", return_value=r_only_dev), patch("time.sleep"):
        code = wait_ci.main()
        assert code == 1, "Must abort if required workflow is missing after discovery timeout!"
