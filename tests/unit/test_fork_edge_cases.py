"""Unit tests verifying edge cases in pyghidra_mcp.forks:
- Fork quota preservation of dead forks with pending/unmerged operations.
- Non-conflict rejection in resolve_conflict.
- Fail-fast validation in resolve_conflict(keep='evidence') when Ghidra tools are unavailable.
- Comment and alias deduplication idempotency in resolve_conflict(keep='both').
- Atomic save order in ForkMerger.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from pyghidra_mcp import forks
from pyghidra_mcp.forks import FORK_META_FILE
from pyghidra_mcp.project_spec import ProjectSpec


def _make_spec(tmp_path: Path, name: str = "test_proj") -> ProjectSpec:
    spec = ProjectSpec.from_cli(tmp_path / "projects", name)
    spec.project_directory.mkdir(parents=True, exist_ok=True)
    spec.gpr_path.write_text("")
    rep = spec.project_directory / f"{name}.rep"
    (rep / "idata").mkdir(parents=True, exist_ok=True)
    (rep / "idata" / "~index.dat").write_text("VERSION=1\n")
    (rep / "project.prp").write_text("<props/>")
    spec.pyghidra_mcp_dir.mkdir(parents=True, exist_ok=True)
    return spec


def test_fork_quota_does_not_discard_dead_fork_with_pending_ops(tmp_path: Path):
    spec = _make_spec(tmp_path)

    # Create first fork and write an unmerged edit
    f1 = forks.create_fork(spec, "fork_with_work", max_forks=2)
    f1.record("rename_function", binary="app.elf", address="0x1000", old="FUN_1", new="worker_1")
    # Simulate process death without merging
    meta = json.loads((f1.fork_dir / FORK_META_FILE).read_text())
    meta["pid"] = 99999999
    (f1.fork_dir / FORK_META_FILE).write_text(json.dumps(meta))

    # Create second fork
    forks.create_fork(spec, "fork_live", max_forks=2)

    # Attempting to create a third fork with max_forks=2 should raise RuntimeError
    # because the dead fork f1 has pending edits and cannot be discarded
    with pytest.raises(RuntimeError, match="Fork quota exceeded"):
        forks.create_fork(spec, "fork_overflow", max_forks=2)

    # Verify f1 still exists
    existing_ids = [f["fork_id"] for f in forks.list_forks(spec.pyghidra_mcp_dir)]
    assert f1.fork_id in existing_ids


def test_resolve_conflict_rejects_non_conflict_seq(tmp_path: Path):
    spec = _make_spec(tmp_path)
    fork_session = forks.create_fork(spec, "fork_test")
    fork_session.record("rename_function", binary="app.elf", address="0x1000", old="FUN_1", new="worker_1")

    # Calling resolve_conflict on seq=1 before any merge has recorded it as a conflict
    with pytest.raises(ValueError, match="is not an unresolved conflict"):
        forks.resolve_conflict(spec.pyghidra_mcp_dir, fork_id=fork_session.fork_id, seq=1, keep="primary")


def test_resolve_conflict_keep_evidence_fails_when_tools_missing(tmp_path: Path):
    spec = _make_spec(tmp_path)
    fork_session = forks.create_fork(spec, "fork_ev")
    fork_session.record(
        "rename_function",
        binary="app.elf",
        address="0x1000",
        old="FUN_1",
        new="strong_symbol",
        provenance="smt_proven",
        epistemic_status="observed",
        primary_provenance="default",
    )

    # Mark conflict in merge_state.json manually
    state_file = fork_session.fork_dir / "merge_state.json"
    state = {
        "applied_seqs": [],
        "conflicts": {"1": "name conflict"},
        "resolved": {},
        "merges": [],
    }
    state_file.write_text(json.dumps(state))

    # resolve_conflict with keep="evidence" with no context and no tools must raise ValueError
    # and NOT mark it as applied
    with pytest.raises(ValueError, match="active Ghidra tools are not available"):
        forks.resolve_conflict(spec.pyghidra_mcp_dir, fork_id=fork_session.fork_id, seq=1, keep="evidence", tools=None)

    # Check state was not updated
    reloaded_state = forks.load_merge_state(fork_session.fork_dir)
    assert "1" not in reloaded_state.get("resolved", {})
    assert "1" in reloaded_state.get("conflicts", {})


def test_resolve_conflict_keep_both_comment_is_idempotent(tmp_path: Path):
    spec = _make_spec(tmp_path)
    fork_session = forks.create_fork(spec, "fork_comments")
    fork_session.record(
        "set_comment",
        binary="app.elf",
        address="0x1000",
        comment_type="eol",
        old=None,
        new="Important logic here",
    )

    # Mark conflict in merge_state.json
    state = {
        "applied_seqs": [],
        "conflicts": {"1": "comment conflict"},
        "resolved": {},
        "merges": [],
    }
    (fork_session.fork_dir / "merge_state.json").write_text(json.dumps(state))

    comments_store = {("0x1000", "eol"): "Existing primary comment"}
    fake_tools = SimpleNamespace(
        get_comment=lambda addr, ctype: comments_store.get((addr, ctype)),
        set_comment=lambda addr, val, ctype: comments_store.update({(addr, ctype): val}),
        get_program_info=lambda bin_name: SimpleNamespace(name=bin_name),
    )

    # First resolve
    forks.resolve_conflict(
        spec.pyghidra_mcp_dir,
        fork_id=fork_session.fork_id,
        seq=1,
        keep="both",
        tools=fake_tools,
    )

    first_val = comments_store[("0x1000", "eol")]
    assert f"[{fork_session.fork_id}]: Important logic here" in first_val

    # Put seq 1 back into conflicts to simulate retry
    state["conflicts"]["1"] = "comment conflict"
    (fork_session.fork_dir / "merge_state.json").write_text(json.dumps(state))

    # Second resolve must not duplicate the tag
    forks.resolve_conflict(
        spec.pyghidra_mcp_dir,
        fork_id=fork_session.fork_id,
        seq=1,
        keep="both",
        tools=fake_tools,
    )

    second_val = comments_store[("0x1000", "eol")]
    assert second_val.count(f"[{fork_session.fork_id}]: Important logic here") == 1


def test_fork_merger_saves_context_before_merge_state(tmp_path: Path):
    spec = _make_spec(tmp_path)
    fork_session = forks.create_fork(spec, "fork_save_order")
    fork_session.record("rename_function", binary="app.elf", address="0x1000", old="FUN_1", new="worker_1")

    save_called = False
    state_file = fork_session.fork_dir / "merge_state.json"

    def fake_save():
        nonlocal save_called
        save_called = True
        # At the time save() is called, merge_state.json should NOT have recorded the new merge yet
        if state_file.is_file():
            st = json.loads(state_file.read_text())
            assert len(st.get("merges", [])) == 0

    fake_context = SimpleNamespace(
        pyghidra_mcp_dir=spec.pyghidra_mcp_dir,
        get_program_info=lambda name: SimpleNamespace(name=name),
        save=fake_save,
    )

    fake_fn = SimpleNamespace(getName=lambda: "FUN_1")
    fake_tools = SimpleNamespace(
        find_function=lambda addr: fake_fn,
        rename_function=lambda addr, name: None,
        evict_function_cache=lambda fn: None,
    )

    merger = forks.ForkMerger(fake_context, tools_factory=lambda _: fake_tools)
    result = merger.merge(fork_session.fork_id, dry_run=False)

    assert save_called is True
    assert result["counts"].get("applied") == 1
