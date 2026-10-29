#!/usr/bin/env python3
"""
Release CI Gatekeeper: Waits for concurrent multi-platform CI matrices
(Ghidra multi-version devcontainer and macOS smoke/compatibility) to finish
successfully before allowing release publishing to PyPI.
"""

import argparse
import json
import os
import subprocess
import sys
import time


def parse_args():
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
    parser.add_argument("--timeout", type=int, default=1800, help="Max wait time in seconds (default: 1800).")
    parser.add_argument("--interval", type=int, default=20, help="Poll interval in seconds (default: 20).")
    return parser.parse_args()


def fetch_runs(repo: str, commit_sha: str):
    cmd = [
        "gh",
        "run",
        "list",
        "--repo",
        repo,
        "--limit",
        "30",
        "--json",
        "databaseId,name,headSha,event,status,conclusion,url",
    ]
    try:
        raw = subprocess.check_output(cmd, text=True)
        all_runs = json.loads(raw)
    except Exception as exc:
        print(f"Warning: Failed to fetch workflow runs from gh CLI: {exc}", file=sys.stderr)
        return []

    # Match runs with identical commit SHA (short or full)
    matching = [
        r
        for r in all_runs
        if r.get("headSha", "").startswith(commit_sha) or commit_sha.startswith(r.get("headSha", ""))
    ]
    return matching


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
        return any(k in name_lower for k in ("devcontainer across versions", "macos smoke", "macos compatibility"))


def main():
    args = parse_args()
    print("=== SuperghidraMCP CI Gatekeeper ===")
    print(f"Repository: {args.repo}")
    print(f"Commit SHA: {args.commit}")
    print(f"Component:  {args.component}")
    print(f"Timeout:    {args.timeout}s (poll every {args.interval}s)")

    start_time = time.monotonic()
    discovered_target_ids = set()

    # Step 1: Wait up to 60s for concurrent workflows to appear in GitHub API
    print("Discovering peer CI workflow runs for this commit...")
    for _ in range(6):
        runs = fetch_runs(args.repo, args.commit)
        target_runs = [r for r in runs if is_target_workflow(r.get("name", ""), args.component)]
        if target_runs:
            discovered_target_ids = {r["databaseId"] for r in target_runs}
            break
        time.sleep(10)

    if not discovered_target_ids:
        print("Notice: No peer matrix CI workflows detected for this commit. Proceeding.")
        return 0

    print(f"Tracking {len(discovered_target_ids)} peer CI workflow(s):")
    for r in target_runs:
        print(f"  - [{r['databaseId']}] {r['name']} (event: {r.get('event')})")

    # Step 2: Poll until all tracked workflows are completed
    while True:
        elapsed = int(time.monotonic() - start_time)
        if elapsed > args.timeout:
            print(f"Error: Timed out waiting for CI workflows after {elapsed}s.", file=sys.stderr)
            return 1

        runs = fetch_runs(args.repo, args.commit)
        current_targets = [r for r in runs if r["databaseId"] in discovered_target_ids]

        pending = []
        failed = []
        succeeded = []

        for r in current_targets:
            status = r.get("status")
            conclusion = r.get("conclusion")
            name = r.get("name")
            if status != "completed":
                pending.append(name)
            elif conclusion == "success":
                succeeded.append(name)
            else:
                failed.append((name, conclusion, r.get("url")))

        if failed:
            print("\nError: One or more peer CI workflows failed! Aborting release publishing.", file=sys.stderr)
            for name, conclusion, url in failed:
                print(f"  FAILED: {name} (conclusion: {conclusion}) -> {url}", file=sys.stderr)
            return 1

        if not pending and len(succeeded) == len(discovered_target_ids):
            print(f"\nAll {len(succeeded)} peer CI workflows passed successfully after {elapsed}s!")
            for name in succeeded:
                print(f"  PASSED: {name}")
            return 0

        pending_names = ", ".join(pending)
        status_msg = f"[{elapsed}s] Waiting: {len(succeeded)} passed, {len(pending)} active ({pending_names})..."
        print(status_msg)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
