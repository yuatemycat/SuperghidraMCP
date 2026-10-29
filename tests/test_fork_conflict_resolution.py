"""Integration and regression test suite for fork conflict resolution, comment combination,
alias preservation, function-scoped atomic edits, and session conflict notifications.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyghidra_mcp import forks, mcp_tools, server
from pyghidra_mcp.project_spec import ProjectSpec

# ---------------------------------------------------------------------------------
# Fixtures and In-Memory Harness
# ---------------------------------------------------------------------------------


def _make_parent_project(tmp_path: Path, name: str = "proj") -> ProjectSpec:
    """Create a synthetic parent project directory structure for testing."""
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

    def __init__(self, state: dict):
        self.state = state

    def find_function(self, address: str):
        if address not in self.state["functions"]:
            raise ValueError(f"Function or symbol '{address}' not found.")
        fn = self.state["functions"][address]
        return SimpleNamespace(
            getName=lambda: fn["name"],
            getSignature=lambda: fn["signature"],
            getComment=lambda: fn.get("comment"),
            getEntryPoint=lambda: SimpleNamespace(toString=lambda: address),
        )

    def rename_function(self, address: str, new_name: str):
        self.state["functions"][address]["name"] = new_name

    def find_variable(self, function_address: str, *, storage: str | None = None, names: tuple = ()):
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

    def _variable(self, function_address: str, name: str):
        return next(v for v in self.state["variables"][function_address] if v["name"] == name)

    def rename_variable(self, function_address: str, variable_name: str, new_name: str):
        self._variable(function_address, variable_name)["name"] = new_name

    def set_variable_type(self, function_address: str, variable_name: str, type_name: str):
        self._variable(function_address, variable_name)["type"] = type_name

    def set_function_prototype(self, address: str, prototype: str):
        self.state["functions"][address]["signature"] = prototype

    def get_comment(self, address: str, comment_type: str):
        return self.state["comments"].get((address, comment_type))

    def set_comment(self, address: str, comment: str, comment_type: str):
        self.state["comments"][(address, comment_type)] = comment

    def evict_function_cache(self, _func):
        pass


class FakePrimary:
    """In-memory stand-in for Primary PyGhidraContext."""

    def __init__(self, pyghidra_mcp_dir: Path, programs: dict):
        self.pyghidra_mcp_dir = pyghidra_mcp_dir
        self.programs = programs
        self.save = Mock()
        self.imported: list[Path] = []
        self.fork_session = None
        self.read_only = False

    def get_program_info(self, binary_name: str):
        if binary_name not in self.programs:
            raise ValueError(f"Binary {binary_name} not found.")
        return self.programs[binary_name]

    def list_binaries(self):
        return list(self.programs)

    def import_binary_backgrounded(self, path: Path):
        self.imported.append(Path(path))
        return SimpleNamespace(message=f"Queued 1 import(s) from {path} in the background.")


BIN = "/target.exe-abc123"


def _program_state() -> dict:
    return {
        "functions": {
            "1000": {"name": "FUN_1000", "signature": "undefined FUN_1000(void)"},
            "2000": {"name": "FUN_2000", "signature": "undefined FUN_2000(void)"},
        },
        "variables": {
            "1000": [{"name": "local_10", "storage": "Stack[-0x10]:4", "type": "int"}],
            "2000": [],
        },
        "comments": {},
    }


def _tool_ctx(pyghidra_context: object):
    ctx = Mock()
    ctx.request_context.lifespan_context = pyghidra_context
    return ctx


@pytest.fixture
def fork_setup(tmp_path: Path):
    parent = _make_parent_project(tmp_path)
    state = _program_state()
    primary = FakePrimary(parent.pyghidra_mcp_dir, {BIN: state})
    merger = forks.ForkMerger(primary, FakeTools)
    return parent, state, primary, merger


# ---------------------------------------------------------------------------------
# 1. test_merge_records_conflict_in_merge_state
# ---------------------------------------------------------------------------------


def test_merge_records_conflict_in_merge_state(fork_setup):
    """Two forks edit the same function name. Fork A merges successfully.
    Fork B merges, encounters a conflict. Verify the conflict is recorded in merge_state['conflicts'][seq].
    """
    parent, state, _primary, merger = fork_setup

    fork_a = forks.create_fork(parent, label="fork_a")
    fork_b = forks.create_fork(parent, label="fork_b")

    # Fork A renames FUN_1000 -> process_packet
    fork_a.record("rename_function", BIN, address="1000", old="FUN_1000", new="process_packet")

    # Fork B also renames FUN_1000 -> handle_network_stream
    fork_b.record("rename_function", BIN, address="1000", old="FUN_1000", new="handle_network_stream")

    # Fork A merges cleanly into primary
    res_a = merger.merge(fork_a.fork_id, auto_discard=False)
    assert res_a["counts"] == {"applied": 1}
    assert state["functions"]["1000"]["name"] == "process_packet"

    # Fork B attempts to merge: encounters conflict because primary now has process_packet
    res_b = merger.merge(fork_b.fork_id, auto_discard=False)
    assert res_b["counts"] == {"conflict": 1}
    assert res_b["pending_ops"] == 1

    # Verify conflict is recorded in merge_state['conflicts'][seq]
    merge_state_b = forks.load_merge_state(fork_b.fork_dir)
    conflicts_dict = merge_state_b["conflicts"]

    # Key may be str or int
    seq_key = "1" if "1" in conflicts_dict else 1
    assert seq_key in conflicts_dict

    conflict = conflicts_dict[seq_key]
    assert conflict["seq"] == 1
    assert conflict["op"] == "rename_function"
    assert conflict["fork_value"] == "handle_network_stream"
    assert conflict["primary_value"] == "process_packet"
    assert "1000" in conflict["target"]
    assert "created_at" in conflict


# ---------------------------------------------------------------------------------
# 2. test_resolve_conflict_keep_fork
# ---------------------------------------------------------------------------------


def test_resolve_conflict_keep_fork(fork_setup):
    """Call resolve_conflict(..., keep='fork').
    Verify fork's edit is applied to primary, marked resolved, and removed from conflicts.
    """
    parent, state, _primary, merger = fork_setup

    fork_a = forks.create_fork(parent, label="fork_a")
    fork_b = forks.create_fork(parent, label="fork_b")

    fork_a.record("rename_function", BIN, address="1000", old="FUN_1000", new="primary_name")
    fork_b.record("rename_function", BIN, address="1000", old="FUN_1000", new="fork_b_winner")

    merger.merge(fork_a.fork_id, auto_discard=False)
    assert state["functions"]["1000"]["name"] == "primary_name"

    merger.merge(fork_b.fork_id, auto_discard=False)

    # Verify initial conflict state
    merge_state_b = forks.load_merge_state(fork_b.fork_dir)
    assert "1" in merge_state_b["conflicts"] or 1 in merge_state_b["conflicts"]

    # Call resolve_conflict with keep='fork'
    outcome = merger.resolve_conflict(fork_b.fork_id, seq=1, keep="fork")
    assert outcome["keep"] == "fork"
    assert outcome["status"] in ("applied", "overwritten")

    # Verify fork's edit is applied to primary
    assert state["functions"]["1000"]["name"] == "fork_b_winner"

    # Verify sequence is marked resolved and removed from conflicts
    updated_state = forks.load_merge_state(fork_b.fork_dir)
    assert "1" in updated_state["resolved"]
    assert updated_state["resolved"]["1"] in forks.RESOLVED_STATUSES
    assert "1" not in updated_state["conflicts"]
    assert 1 not in updated_state["conflicts"]


# ---------------------------------------------------------------------------------
# 3. test_resolve_conflict_keep_primary
# ---------------------------------------------------------------------------------


def test_resolve_conflict_keep_primary(fork_setup):
    """Call resolve_conflict(..., keep='primary').
    Verify primary's edit is retained, sequence is marked resolved, and conflict is removed.
    """
    parent, state, primary, merger = fork_setup

    fork_a = forks.create_fork(parent, label="fork_a")
    fork_b = forks.create_fork(parent, label="fork_b")

    fork_a.record("rename_function", BIN, address="1000", old="FUN_1000", new="stable_primary_name")
    fork_b.record("rename_function", BIN, address="1000", old="FUN_1000", new="discarded_fork_name")

    merger.merge(fork_a.fork_id, auto_discard=False)
    merger.merge(fork_b.fork_id, auto_discard=False)

    # Call resolve_conflict with keep='primary'
    outcome = forks.resolve_conflict(
        parent.pyghidra_mcp_dir,
        fork_b.fork_id,
        seq=1,
        keep="primary",
        context=primary,
        merger=merger,
    )
    assert outcome["keep"] == "primary"
    assert outcome["status"] == "discarded"

    # Verify primary's edit is retained
    assert state["functions"]["1000"]["name"] == "stable_primary_name"

    # Verify sequence is marked resolved and removed from conflicts
    updated_state = forks.load_merge_state(fork_b.fork_dir)
    assert "1" in updated_state["resolved"]
    assert updated_state["resolved"]["1"] == "discarded"
    assert "1" not in updated_state["conflicts"]
    assert 1 not in updated_state["conflicts"]


# ---------------------------------------------------------------------------------
# 4. test_resolve_conflict_keep_both_comments
# ---------------------------------------------------------------------------------


def test_resolve_conflict_keep_both_comments(fork_setup):
    """Conflicting comments on an address. Call resolve_conflict(..., keep='both').
    Verify both comments are merged cleanly into primary.
    """
    parent, state, _primary, merger = fork_setup

    # Primary has an existing plate comment on 1000
    state["comments"][("1000", "plate")] = "Primary security analysis: potential overflow"

    fork = forks.create_fork(parent, label="fork_reviewer")
    fork.record(
        "set_comment",
        BIN,
        address="1000",
        comment_type="plate",
        old=None,
        new="Fork audit note: validated via symbolic execution",
    )

    merger.merge(fork.fork_id, auto_discard=False)

    # Verify conflict was recorded
    initial_merge_state = forks.load_merge_state(fork.fork_dir)
    assert "1" in initial_merge_state["conflicts"] or 1 in initial_merge_state["conflicts"]

    # Call resolve_conflict with keep='both'
    outcome = merger.resolve_conflict(fork.fork_id, seq=1, keep="both")
    assert outcome["keep"] == "both"
    assert outcome["status"] == "applied"

    # Verify both comments are merged cleanly into primary
    merged_comment = state["comments"][("1000", "plate")]
    assert "Primary security analysis: potential overflow" in merged_comment
    assert "Fork audit note: validated via symbolic execution" in merged_comment
    assert f"[{fork.fork_id}]" in merged_comment

    # Verify marked resolved and conflict cleared
    updated_state = forks.load_merge_state(fork.fork_dir)
    assert "1" in updated_state["resolved"]
    assert "1" not in updated_state["conflicts"]


# ---------------------------------------------------------------------------------
# 5. test_resolve_conflict_keep_both_rename_alias
# ---------------------------------------------------------------------------------


def test_resolve_conflict_keep_both_rename_alias(fork_setup):
    """Conflicting function rename. Call resolve_conflict(..., keep='both').
    Verify primary keeps its name, and fork's proposed name is saved as an alias comment on the function.
    """
    parent, state, _primary, merger = fork_setup

    state["functions"]["1000"]["name"] = "crypto_aes_encrypt"

    fork = forks.create_fork(parent, label="fork_alias")
    fork.record(
        "rename_function",
        BIN,
        address="1000",
        old="FUN_1000",
        new="cipher_encrypt_block",
    )

    merger.merge(fork.fork_id, auto_discard=False)

    # Call resolve_conflict with keep='both'
    outcome = merger.resolve_conflict(fork.fork_id, seq=1, keep="both")
    assert outcome["keep"] == "both"
    assert outcome["status"] == "applied"

    # Verify primary keeps its existing name
    assert state["functions"]["1000"]["name"] == "crypto_aes_encrypt"

    # Verify fork's proposed name is saved as an alias comment on the function
    plate = state["comments"].get(("1000", "plate"), "")
    assert "cipher_encrypt_block" in plate
    assert f"[Alternative name from fork {fork.fork_id}]: cipher_encrypt_block" in plate

    # Verify sequence is marked resolved and conflict cleared
    updated_state = forks.load_merge_state(fork.fork_dir)
    assert "1" in updated_state["resolved"]
    assert "1" not in updated_state["conflicts"]


# ---------------------------------------------------------------------------------
# 6. test_function_scoped_atomic_grouping
# ---------------------------------------------------------------------------------


def test_function_scoped_atomic_grouping(fork_setup):
    """A fork changes both a prototype and a variable in the same function.
    If the variable rename conflicts, verify the entire function's edits are held back
    together (preventing partial updates).
    """
    parent, state, _primary, merger = fork_setup

    # Introduce a conflict on function 1000's variable
    state["variables"]["1000"][0]["name"] = "primary_var_name"

    fork = forks.create_fork(parent, label="fork_atomic")

    # Op 1: Change function prototype on 1000 (would apply cleanly on its own)
    fork.record(
        "set_function_prototype",
        BIN,
        address="1000",
        old="undefined FUN_1000(void)",
        new="int FUN_1000(int flag)",
        prototype="int FUN_1000(int flag)",
    )

    # Op 2: Rename variable on 1000 (conflicts! fork expected local_10, primary has primary_var_name)
    fork.record(
        "rename_variable",
        BIN,
        function_address="1000",
        storage="Stack[-0x10]:4",
        old="local_10",
        new="flag_count",
    )

    # Op 3: In an unrelated function 2000, rename function (clean, should apply)
    fork.record("rename_function", BIN, address="2000", old="FUN_2000", new="independent_helper")

    # Execute merge with atomic_by_function=True
    result = merger.merge(fork.fork_id, atomic_by_function=True, auto_discard=False)

    entries_by_seq = {e["seq"]: e for e in result["entries"]}

    # Op 2 is in conflict
    assert entries_by_seq[2]["status"] == "conflict"

    # Op 1 was held back together with Op 2
    assert entries_by_seq[1]["status"] == "skipped"
    assert "held back" in entries_by_seq[1]["detail"].lower()

    # Function 1000 was completely protected from partial application:
    # 1. Prototype remains UNCHANGED on primary
    assert state["functions"]["1000"]["signature"] == "undefined FUN_1000(void)"
    # 2. Variable name remains UNCHANGED on primary
    assert state["variables"]["1000"][0]["name"] == "primary_var_name"

    # Function 2000 was independent and successfully merged
    assert entries_by_seq[3]["status"] == "applied"
    assert state["functions"]["2000"]["name"] == "independent_helper"

    # In merge_state, only Op 3 is resolved, Ops 1 and 2 remain pending
    merge_state = forks.load_merge_state(fork.fork_dir)
    assert "3" in merge_state["resolved"]
    assert "1" not in merge_state["resolved"]
    assert "2" not in merge_state["resolved"]
    assert "2" in merge_state["conflicts"]


# ---------------------------------------------------------------------------------
# 7. test_session_info_reports_conflicts_to_fork
# ---------------------------------------------------------------------------------


def test_session_info_reports_conflicts_to_fork(fork_setup):
    """In a fork session that has conflicts in merge state, verify get_session_info()
    reports the conflicts and pending resolution advice.
    """
    parent, state, _primary, merger = fork_setup

    fork = forks.create_fork(parent, label="fork_with_conflicts")
    state["functions"]["1000"]["name"] = "diverged_name"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="unmerged_name")

    # Trigger conflict
    merger.merge(fork.fork_id, auto_discard=False)

    # Construct mock context representing the fork session
    fork_context = SimpleNamespace(
        fork_session=fork,
        pyghidra_mcp_dir=fork.project_spec.pyghidra_mcp_dir,
        read_only=False,
    )
    ctx = _tool_ctx(fork_context)

    # 1. Test mcp_tools.get_session_info
    info = mcp_tools.get_session_info(ctx)
    assert info["role"] == "fork"
    assert info["fork_id"] == fork.fork_id
    assert info["journal_ops"] == 1
    assert len(info["conflicts"]) == 1
    assert info["conflicts"][0]["seq"] == 1

    # Verify actionable conflict advice is reported
    assert "advice" in info or "hint" in info
    combined_advice = f"{info.get('advice', '')} {info.get('hint', '')}"
    assert "unresolved conflicts" in combined_advice.lower()
    assert "resolve_conflict" in combined_advice
    assert "sync_fork" in combined_advice

    # 2. Test server.server_instructions reflects the advice
    instructions = server.server_instructions(fork_context)
    assert "resolve_conflict" in instructions
    assert "sync_fork" in instructions


# ---------------------------------------------------------------------------------
# 8. test_sync_fork_reports_status
# ---------------------------------------------------------------------------------


def test_sync_fork_reports_status(fork_setup):
    """Verify sync_fork() returns up-to-date status and resolved operations."""
    parent, state, primary, merger = fork_setup

    fork = forks.create_fork(parent, label="fork_sync_tester")

    # Op 1: Clean function rename
    fork.record("rename_function", BIN, address="2000", old="FUN_2000", new="clean_rename")

    # Op 2: Conflicting function rename
    state["functions"]["1000"]["name"] = "primary_conflict"
    fork.record("rename_function", BIN, address="1000", old="FUN_1000", new="fork_conflict")

    # Merge fork: Op 1 applies, Op 2 conflicts
    merge_res = merger.merge(fork.fork_id, auto_discard=False)
    assert merge_res["counts"]["applied"] == 1
    assert merge_res["counts"]["conflict"] == 1

    # 1. Test low-level forks.sync_fork
    status = forks.sync_fork(parent.pyghidra_mcp_dir, fork.fork_id)
    assert status["fork_id"] == fork.fork_id
    assert status["total_ops"] == 2
    assert status["resolved_ops"] == 1
    assert status["pending_ops"] == 1
    assert "1" in status["resolved"]
    assert status["resolved"]["1"] == "applied"
    assert len(status["conflicts"]) == 1
    assert status["conflicts"][0]["seq"] == 2
    assert "synced_at" in status

    # 2. Test ForkSession.sync() method parity
    session_status = fork.sync()
    assert session_status["fork_id"] == fork.fork_id
    assert session_status["resolved_ops"] == 1
    assert session_status["pending_ops"] == 1

    # 3. Test mcp_tools.sync_fork tool from primary session
    primary_ctx = _tool_ctx(primary)
    tool_primary_status = mcp_tools.sync_fork(primary_ctx, fork_id=fork.fork_id)
    assert tool_primary_status["fork_id"] == fork.fork_id
    assert tool_primary_status["resolved_ops"] == 1

    # 4. Test mcp_tools.sync_fork tool from fork session (implicit fork_id)
    fork_context = SimpleNamespace(
        fork_session=fork,
        pyghidra_mcp_dir=fork.project_spec.pyghidra_mcp_dir,
        read_only=False,
    )
    fork_ctx = _tool_ctx(fork_context)
    tool_fork_status = mcp_tools.sync_fork(fork_ctx)
    assert tool_fork_status["fork_id"] == fork.fork_id
    assert tool_fork_status["resolved_ops"] == 1
    assert tool_fork_status["pending_ops"] == 1
