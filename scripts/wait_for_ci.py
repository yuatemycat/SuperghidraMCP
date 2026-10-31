#!/usr/bin/env python3
"""
Release CI Gatekeeper: Waits for concurrent multi-platform CI matrices
(Ghidra multi-version devcontainer and macOS smoke/compatibility) to finish
successfully before allowing release publishing to PyPI.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wait for peer CI runs to succeed before release.")
    parser.add_argument("--commit", required=True, help="Git commit SHA (headSha) to inspect.")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", "yuatemycat/SuperghidraMCP"),
        help="GitHub repo in 'owner/repo' format.",
    )
    parser.add_argument(
        "--component",
        choices=["all", "cli"],
        default="all",
        help="Component being released ('all' for server or 'cli' for CLI client).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Max wait time in seconds (default: 1800).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=20,
        help="Poll interval in seconds (default: 20).",
    )
    parser.add_argument(
        "--discovery-timeout",
        type=int,
        default=180,
        help="Max time to wait for peer workflows to register in API (default: 180s).",
    )
    parser.add_argument(
        "--min-runs",
        type=int,
        default=None,
        help="Minimum expected peer CI runs (default: 2 for 'all', 1 for 'cli').",
    )
    parser.add_argument(
        "--required-workflows",
        default="",
        help="Comma-separated list of required workflow name substrings (e.g. 'devcontainer,macos smoke').",
    )
    parser.add_argument(
        "--settle-seconds",
        type=int,
        default=30,
        help="Seconds to wait after all discovered workflows pass to ensure no late peer workflow starts.",
    )
    return parser.parse_args()


def fetch_runs(repo: str, commit_sha: str, *, max_retries: int = 3) -> list[dict[str, Any]]:
    cmd = [
        "gh",
        "run",
        "list",
        "--repo",
        repo,
        "--limit",
        "50",
        "--json",
        "databaseId,name,headSha,event,status,conclusion,url",
    ]
    last_err: Exception | None = None
    for attempt in range(max_retries):
        try:
            raw = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
            all_runs = json.loads(raw)
            if not isinstance(all_runs, list):
                raise ValueError(f"Expected list of runs, got {type(all_runs).__name__}")
            matching = [
                r
                for r in all_runs
                if r.get("headSha", "").startswith(commit_sha) or commit_sha.startswith(r.get("headSha", ""))
            ]
            return matching
        except Exception as exc:
            last_err = exc
            if attempt < max_retries - 1:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Failed to fetch workflow runs from gh CLI after {max_retries} attempts: {last_err}")


def is_target_workflow(name: str, component: str) -> bool:
    name_lower = name.lower()
    # Ignore release workflows themselves to prevent deadlock
    if name_lower in ("release", "release cli"):
        return False
    # Ignore container build workflows
    if "docker" in name_lower:
        return False
    if component == "cli":
        return "cli devcontainer" in name_lower
    else:
        if "cli" in name_lower:
            return False
        return any(k in name_lower for k in ("devcontainer across versions", "macos smoke", "macos compatibility"))


def main() -> int:
    args = parse_args()
    required_patterns = [p.strip().lower() for p in args.required_workflows.split(",") if p.strip()]
    default_min = len(required_patterns) if required_patterns else (1 if args.component == "cli" else 2)
    min_expected = args.min_runs if args.min_runs is not None else default_min

    print("=== SuperghidraMCP CI Gatekeeper ===")
    print(f"Repository:         {args.repo}")
    print(f"Commit SHA:         {args.commit}")
    print(f"Component:          {args.component}")
    print(f"Expected Min Runs:  {min_expected}")
    if required_patterns:
        print(f"Required Workflows: {required_patterns}")
    print(f"Discovery Timeout:  {args.discovery_timeout}s")
    print(f"Settle Window:      {args.settle_seconds}s")
    print(f"Poll Timeout:       {args.timeout}s (interval: {args.interval}s)")

    start_time = time.monotonic()
    discovered_target_ids: set[int] = set()

    # Step 1: Wait up to discovery_timeout for minimum expected peer workflows to appear
    print("\n[Step 1/2] Discovering peer CI workflow runs for this commit...")
    discovery_start = time.monotonic()
    target_runs: list[dict[str, Any]] = []

    while True:
        try:
            runs = fetch_runs(args.repo, args.commit)
        except RuntimeError as exc:
            print(f"Error: Run discovery failed: {exc}", file=sys.stderr)
            return 1

        target_runs = [r for r in runs if is_target_workflow(r.get("name", ""), args.component)]
        for r in target_runs:
            discovered_target_ids.add(r["databaseId"])

        discovered_names = [r.get("name", "").lower() for r in target_runs]
        missing_required = [req for req in required_patterns if not any(req in name for name in discovered_names)]

        if len(discovered_target_ids) >= min_expected and not missing_required:
            break

        elapsed_discovery = int(time.monotonic() - discovery_start)
        if elapsed_discovery >= args.discovery_timeout:
            reasons = []
            if len(discovered_target_ids) < min_expected:
                reasons.append(f"found {len(discovered_target_ids)}/{min_expected} min runs")
            if missing_required:
                reasons.append(f"missing required workflow(s): {', '.join(missing_required)}")
            print(
                f"\nError: Expected peer CI workflows did not appear within {elapsed_discovery}s "
                f"({'; '.join(reasons)}). "
                "Aborting release publishing to prevent untested deployment.",
                file=sys.stderr,
            )
            return 1

        time.sleep(min(args.interval, 10))

    print(f"\n[Step 2/2] Tracking {len(discovered_target_ids)} peer CI workflow(s):")
    for r in target_runs:
        print(f"  - [{r['databaseId']}] {r['name']} (event: {r.get('event')})")

    # Step 2: Poll until all tracked workflows are completed successfully and settled
    settle_start_time: float | None = None

    while True:
        elapsed = int(time.monotonic() - start_time)
        if elapsed > args.timeout:
            print(f"\nError: Timed out waiting for CI workflows after {elapsed}s.", file=sys.stderr)
            return 1

        try:
            runs = fetch_runs(args.repo, args.commit)
        except RuntimeError as exc:
            print(f"Warning: Transient API fetch failure ({exc}); will retry in {args.interval}s...")
            time.sleep(args.interval)
            continue

        # Continuous discovery: dynamically track newly registered target workflows
        all_targets = [r for r in runs if is_target_workflow(r.get("name", ""), args.component)]
        for r in all_targets:
            if r["databaseId"] not in discovered_target_ids:
                print(f"  + Dynamically tracked newly registered CI run: [{r['databaseId']}] {r['name']}")
                discovered_target_ids.add(r["databaseId"])
                settle_start_time = None  # Reset settle timer on new workflow discovery

        current_targets = [r for r in runs if r["databaseId"] in discovered_target_ids]

        pending: list[str] = []
        failed: list[tuple[str, str, str]] = []
        succeeded: list[str] = []
        skipped: list[str] = []

        for r in current_targets:
            status = r.get("status")
            conclusion = r.get("conclusion")
            name = r.get("name", "unknown")
            if status != "completed":
                pending.append(name)
            elif conclusion == "success":
                succeeded.append(name)
            elif conclusion in ("skipped", "cancelled"):
                # Treat cancelled/skipped runs as non-blocking skips unless explicitly required
                if any(req in name.lower() for req in required_patterns):
                    failed.append((name, conclusion or "unknown", r.get("url", "")))
                else:
                    skipped.append(name)
            else:
                failed.append((name, conclusion or "unknown", r.get("url", "")))

        if failed:
            print("\nError: One or more peer CI workflows failed! Aborting release publishing.", file=sys.stderr)
            for name, conclusion, url in failed:
                print(f"  FAILED: {name} (conclusion: {conclusion}) -> {url}", file=sys.stderr)
            return 1

        succeeded_names = [r.get("name", "").lower() for r in current_targets if r.get("conclusion") == "success"]
        missing_required = [req for req in required_patterns if not any(req in name for name in succeeded_names)]

        if (
            not pending
            and (len(succeeded) + len(skipped)) >= len(discovered_target_ids)
            and len(succeeded) >= min_expected
            and not missing_required
        ):
            if args.settle_seconds > 0:
                if settle_start_time is None:
                    settle_start_time = time.monotonic()
                settled_so_far = int(time.monotonic() - settle_start_time)
                if settled_so_far < args.settle_seconds:
                    remaining = args.settle_seconds - settled_so_far
                    print(
                        f"[{elapsed}s] All {len(succeeded)} workflows passed; "
                        f"settling for {remaining}s to ensure no late peer workflow starts..."
                    )
                    time.sleep(min(args.interval, remaining if remaining > 0 else 1))
                    continue

            print(f"\nAll {len(succeeded)} peer CI workflows passed successfully after {elapsed}s!")
            for name in succeeded:
                print(f"  PASSED: {name}")
            return 0

        # If any are pending, reset settle timer
        settle_start_time = None

        pending_names = ", ".join(pending)
        status_msg = f"[{elapsed}s] Waiting: {len(succeeded)} passed, {len(pending)} active ({pending_names})..."
        print(status_msg)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
