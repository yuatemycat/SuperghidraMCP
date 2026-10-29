"""Unit tests for fork conflict handling, per-edit resolution, atomic function edits, and sync."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyghidra_mcp import forks
from pyghidra_mcp.project_spec import ProjectSpec


def _make_parent_project(tmp_path: Path, name: str = "proj") -> ProjectSpec:
    spec = ProjectSpec.from_cli(tmp_path / "projects", name)
    spec.project_directory.mkdir(parents=True, exist_ok=True)
    spec.gpr_path.write_text("")
    rep = spec.project_directory / f"{name}.rep"
    (rep / "idata").mkdir(parents=True, exist_ok=True)
    (rep / "idata" / "~index.dat").write_text("VERSION=1\n")
    (rep / "project.prp").write_text("<props/>")
    (spec.project_directory / f"{name}.lock").write_text("held")
    (spec.pyghidra_mcp_dir / "chromadb").mkdir(parents=True, exist_ok=True)
    (spec.pyghidra_mcp_dir / "chromadb" / "chroma.sqlite3").write_bytes(b"db")
    return spec


class FakeTools:
    """In-memory stand-in for GhidraTools over one program."""

    def __init__(self, state):
        self.state = state

    def find_function(self, address):
        if address not in self.state["functions"]:
            raise ValueError(f"Function or symbol '{address}' not found.")
        fn = self.state["functions"][address]
        return SimpleNamespace(
            getName=lambda: fn["name"],
            getSignature=lambda: fn["signature"],
            getComment=lambda: fn.get("comment"),
        )

    def rename_function(self, address, new_name):
        self.state["functions"][address]["name"] = new_name

    def find_variable(self, function_address, *, storage=None, names=()):
        variables = self.state["variables"].get(function_address, [])
        for var in variables:
            if storage and var["storage"] == storage:
                break
        else:
            var = next((v for n in names for v in variables if v["name"] == n), None)
            if var is None:
                raise ValueError("Variable not found")
        return (
            None,
            "local",
            SimpleNamespace(
                getName=lambda: var["name"],
                getDataType=lambda: SimpleNamespace(getDisplayName=lambda: var["type"]),
            ),
        )

    def _variable(self, function_address, name):
        return next(v for v in self.state["variables"][function_address] if v["name"] == name)

    def rename_variable(self, function_address, variable_name, new_name):
        self._variable(function_address, variable_name)["name"] = new_name

    def set_variable_type(self, function_address, variable_name, type_name):
        self._variable(function_address, variable_name)["type"] = type_name

    def set_function_prototype(self, address, prototype):
        self.state["functions"][address]["signature"] = prototype

    def get_comment(self, address, comment_type):
        return self.state["comments"].get((address, comment_type))

    def set_comment(self, address, comment, comment_type):
        self.state["comments"][(address, comment_type)] = comment


class FakePrimary:
    def __init__(self, pyghidra_mcp_dir, programs):
        self.pyghidra_mcp_dir = pyghidra_mcp_dir
        self.programs = programs
        self.save = Mock()
        self.imported: list[Path] = []

    def get_program_info(self, binary_name):
        if binary_name not in self.programs:
            raise ValueError(f"Binary {binary_name} not found.")
        return self.programs[binary_name]

    def list_binaries(self):
        return list(self.programs)

    def import_binary_backgrounded(self, path):
        self.imported.append(Path(path))
        return SimpleNamespace(message=f"Queued 1 import(s) from {path} in the background.")


BIN = "/target.exe-abc123"


def _program_state():
    return {
        "functions": {
            "1000": {"name": "FUN_1000", "signature": "undefined FUN_1000(void)"},
            "2000": {"name": "FUN_2000", "signature": "undefined FUN_2000(void)"},
        },
        "variables": {"1000": [{"name": "local_10", "storage": "Stack[-0x10]:4", "type": "int"}]},
        "comments": {},
    }


@pytest.fixture
def conflict_setup(tmp_path):
    parent = _make_parent_project(tmp_path)
    fork = forks.create_fork(parent, label="agent_c")
    state = _program_state()
    primary = FakePrimary(parent.pyghidra_mcp_dir, {BIN: state})
    merger = forks.ForkMerger(primary, FakeTools)
    return parent, fork, state, primary, merger


# 1. State Tracking & Merge Conflicts Recording
# ---------------------------------------------------------------------------------


def test_load_and_save_merge_state_tracks_conflicts(tmp_path):
    fork_dir = tmp_path / "fork_1"
    fork_dir.mkdir()
    state = forks.load_merge_state(fork_dir)
    assert state["conflicts"] == {}
    assert state["resolved"] == {}
    assert state["merges"] == []

    state["conflicts"]["1"] = {
        "seq": 1,
        "op": "rename_function",
        "primary_value": "orig",
        "fork_value": "new",
        "target": "function @ 1000",
        "created_at": "2026-10-28T00:00:00Z",
    }
    forks.save_merge_state(fork_dir, state)

    reloaded = forks.load_merge_state(fork_dir)
    assert reloaded["conflicts"]["1"]["fork_value"] == "new"


def test_merge_records_conflict_metadata(conflict_setup):
    _parent, fork, state, _primary, merger = conflict_setup
    state["functions"]["1000"]["name"] = "primary_changed"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="fork_changed")

    res = merger.merge(fork.fork_id)
    assert res["counts"] == {"conflict": 1}

    # Verify conflict details in merge_state.json
    merge_state = forks.load_merge_state(fork.fork_dir)
    assert "1" in merge_state["conflicts"]
    c = merge_state["conflicts"]["1"]
    assert c["seq"] == 1
    assert c["op"] == "rename_function"
    assert c["primary_value"] == "primary_changed"
    assert c["fork_value"] == "fork_changed"
    assert "1000" in c["target"]
    assert "created_at" in c
    assert c["binary"] == BIN

    # Check describe_fork includes conflicts
    desc = forks.describe_fork(fork.fork_dir)
    assert len(desc["conflicts"]) == 1
    assert desc["conflicts"][0]["seq"] == 1


# 2. Per-Edit Conflict Resolution (resolve_conflict)
# ---------------------------------------------------------------------------------


def test_resolve_conflict_keep_primary(conflict_setup):
    parent, fork, state, _primary, merger = conflict_setup
    state["functions"]["1000"]["name"] = "primary_name"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="fork_name")
    merger.merge(fork.fork_id)

    # Resolve conflict choosing keep='primary'
    outcome = forks.resolve_conflict(parent.pyghidra_mcp_dir, fork.fork_id, seq=1, keep="primary")
    assert outcome["status"] == "discarded"
    assert outcome["keep"] == "primary"

    # Primary retains its name
    assert state["functions"]["1000"]["name"] == "primary_name"

    # Verify merge state updated: seq removed from conflicts and marked discarded in resolved
    merge_state = forks.load_merge_state(fork.fork_dir)
    assert "1" not in merge_state["conflicts"]
    assert merge_state["resolved"]["1"] == "discarded"

    # Subsequent merge has 0 pending ops
    res = merger.merge(fork.fork_id)
    assert res["entries"] == []
    assert res["pending_ops"] == 0


def test_resolve_conflict_keep_fork(conflict_setup):
    _parent, fork, state, _primary, merger = conflict_setup
    state["functions"]["1000"]["name"] = "primary_name"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="fork_name")
    merger.merge(fork.fork_id)

    # Resolve conflict choosing keep='fork'
    outcome = merger.resolve_conflict(fork.fork_id, seq=1, keep="fork")
    assert outcome["status"] in ("applied", "overwritten")
    assert outcome["keep"] == "fork"

    # Primary function name updated to fork's name
    assert state["functions"]["1000"]["name"] == "fork_name"

    # Conflict cleared from merge_state
    merge_state = forks.load_merge_state(fork.fork_dir)
    assert "1" not in merge_state["conflicts"]
    assert "1" in merge_state["resolved"]


def test_resolve_conflict_keep_both_comments(conflict_setup):
    _parent, fork, state, _primary, merger = conflict_setup
    state["comments"][("1000", "plate")] = "Primary analysis note"
    fork.record(
        "set_comment",
        BIN,
        address="1000",
        comment_type="plate",
        old=None,
        new="Fork additional notes",
    )
    merger.merge(fork.fork_id)

    outcome = merger.resolve_conflict(fork.fork_id, seq=1, keep="both")
    assert outcome["status"] == "applied"
    assert outcome["keep"] == "both"

    combined = state["comments"][("1000", "plate")]
    assert "Primary analysis note" in combined
    assert f"[{fork.fork_id}]: Fork additional notes" in combined

    merge_state = forks.load_merge_state(fork.fork_dir)
    assert "1" not in merge_state["conflicts"]
    assert merge_state["resolved"]["1"] == "applied"


def test_resolve_conflict_keep_both_renames(conflict_setup):
    _parent, fork, state, _primary, merger = conflict_setup
    state["functions"]["1000"]["name"] = "crypto_init"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="ssl_setup")
    merger.merge(fork.fork_id)

    outcome = merger.resolve_conflict(fork.fork_id, seq=1, keep="both")
    assert outcome["status"] == "applied"

    # Keeps primary name
    assert state["functions"]["1000"]["name"] == "crypto_init"
    # Preserves fork name as alias comment on function
    plate = state["comments"][("1000", "plate")]
    assert f"[Alternative name from fork {fork.fork_id}]: ssl_setup" in plate

    merge_state = forks.load_merge_state(fork.fork_dir)
    assert "1" not in merge_state["conflicts"]
    assert merge_state["resolved"]["1"] == "applied"


# 3. Automatic Comment & Alias Preservation
# ---------------------------------------------------------------------------------


def test_automatic_comment_combination_on_conflict(conflict_setup):
    _parent, fork, state, _primary, merger = conflict_setup
    state["comments"][("1000", "eol")] = "Primary comment"
    fork.record("set_comment", BIN, address="1000", comment_type="eol", old=None, new="Fork comment")

    # With combine_comments=True
    res = merger.merge(fork.fork_id, combine_comments=True)
    assert res["counts"]["applied"] == 1
    assert "1" not in res.get("conflicts", {})

    combined = state["comments"][("1000", "eol")]
    assert "Primary comment" in combined
    assert f"[{fork.fork_id}]: Fork comment" in combined


def test_automatic_comment_combination_on_conflict_combine_mode(conflict_setup):
    _parent, fork, state, _primary, merger = conflict_setup
    state["comments"][("1000", "repeatable")] = "Initial doc"
    fork.record("set_comment", BIN, address="1000", comment_type="repeatable", old=None, new="Extra doc")

    # With on_conflict='combine'
    res = merger.merge(fork.fork_id, on_conflict="combine")
    assert res["counts"]["applied"] == 1

    combined = state["comments"][("1000", "repeatable")]
    assert "Initial doc" in combined
    assert f"[{fork.fork_id}]: Extra doc" in combined


def test_preserve_alias_on_function_rename_conflict(conflict_setup):
    _parent, fork, state, _primary, merger = conflict_setup
    state["functions"]["1000"]["name"] = "primary_handler"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="fork_handler")

    # Skip conflict but preserve alias
    res = merger.merge(fork.fork_id, on_conflict="skip", preserve_alias=True)
    assert res["counts"]["conflict"] == 1
    # Function keeps primary name
    assert state["functions"]["1000"]["name"] == "primary_handler"
    # Fork's name preserved in plate comment
    plate = state["comments"].get(("1000", "plate"), "")
    assert f"[Alternative name from fork {fork.fork_id}]: fork_handler" in plate


def test_preserve_alias_on_overwrite(conflict_setup):
    _parent, fork, state, _primary, merger = conflict_setup
    state["functions"]["1000"]["name"] = "primary_handler"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="fork_handler")

    # Overwrite conflict with preserve_alias=True
    res = merger.merge(fork.fork_id, on_conflict="overwrite", preserve_alias=True)
    assert res["counts"]["overwritten"] == 1
    # Function renamed to fork's name
    assert state["functions"]["1000"]["name"] == "fork_handler"
    # Primary's losing name preserved in plate comment
    plate = state["comments"].get(("1000", "plate"), "")
    assert "primary_handler" in plate


# 4. Function-Scoped Atomic Edits (atomic_by_function=True)
# ---------------------------------------------------------------------------------


def test_atomic_by_function_holds_back_all_edits_on_conflict(conflict_setup):
    _parent, fork, state, _primary, merger = conflict_setup
    # Set up function 1000 with a variable conflict
    state["variables"]["1000"][0]["name"] = "different_name"

    # Op 1: rename function 1000 (would apply cleanly)
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="parser")
    # Op 2: rename variable in 1000 (conflicts with different_name!)
    fork.record(
        "rename_variable",
        BIN,
        function_address="1000",
        storage="Stack[-0x10]:4",
        old="local_10",
        new="count",
    )
    # Op 3: set plate comment on 1000 (would apply cleanly)
    fork.record("set_comment", BIN, address="1000", comment_type="plate", old=None, new="parser entry")

    # Function 2000: op 4 (independent function, should apply cleanly)
    fork.record("rename_function", BIN, address="2000", old="FUN_2000", new="helper")

    res = merger.merge(fork.fork_id, atomic_by_function=True)

    # Function 1000 had a conflict, so Op 1 and Op 3 are held back ('skipped'), Op 2 is 'conflict'
    statuses = {e["seq"]: e["status"] for e in res["entries"]}
    assert statuses[1] == "skipped"
    assert statuses[2] == "conflict"
    assert statuses[3] == "skipped"
    assert "held back: conflict in function 1000" in res["entries"][0]["detail"]

    # Function 1000 was held back: untouched on primary!
    assert state["functions"]["1000"]["name"] == "FUN_1000"
    assert ("1000", "plate") not in state["comments"]

    # Function 2000 succeeded!
    assert statuses[4] == "applied"
    assert state["functions"]["2000"]["name"] == "helper"

    # Merge state shows function 2000 resolved, function 1000 pending
    merge_state = forks.load_merge_state(fork.fork_dir)
    assert "4" in merge_state["resolved"]
    assert "1" not in merge_state["resolved"]
    assert "2" not in merge_state["resolved"]
    assert "3" not in merge_state["resolved"]
    assert "2" in merge_state["conflicts"]


# 5. Fork Notification & Sync (sync_fork)
# ---------------------------------------------------------------------------------


def test_sync_fork_reports_reconciled_state(conflict_setup):
    parent, fork, state, _primary, merger = conflict_setup
    state["functions"]["1000"]["name"] = "diverged"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="clean_name")
    fork.record("rename_function", BIN, address="2000", old="FUN_2000", new="helper_applied")

    # Merge: seq 1 conflicts, seq 2 applies
    merger.merge(fork.fork_id)

    sync_result = forks.sync_fork(parent.pyghidra_mcp_dir, fork.fork_id)
    assert sync_result["fork_id"] == fork.fork_id
    assert sync_result["total_ops"] == 2
    assert sync_result["resolved_ops"] == 1
    assert sync_result["pending_ops"] == 1
    assert "2" in sync_result["resolved"]
    assert len(sync_result["conflicts"]) == 1
    assert sync_result["conflicts"][0]["seq"] == 1

    # ForkSession.sync() method parity
    session_sync = fork.sync()
    assert session_sync["fork_id"] == sync_result["fork_id"]
    assert session_sync["resolved_ops"] == sync_result["resolved_ops"]
