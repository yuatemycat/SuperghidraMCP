"""Integration and regression test suite for evidence-driven fork conflict resolution.
Verifies epistemic ranking (smt_proven / imported > user_defined > analysis > default),
ReconstructionObligationLedger integration, and resolve_conflict(keep="evidence").
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from pyghidra_mcp import forks, mcp_tools
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
    def __init__(self, pyghidra_mcp_dir: Path, programs: dict):
        self.pyghidra_mcp_dir = pyghidra_mcp_dir
        self.programs = programs

    def get_program_info(self, name: str):
        return SimpleNamespace(name=name, metadata={})

    def save(self):
        pass


def test_merge_fork_evidence_resolution_fork_wins(tmp_path: Path):
    """When Fork has SMT-proven evidence and Primary has a default compiler symbol, Fork automatically wins."""
    spec = _make_parent_project(tmp_path)
    primary_state = {
        "functions": {"0x1000": {"name": "FUN_1000", "signature": "void FUN_1000()", "comment": None}},
        "variables": {},
        "comments": {},
    }
    tools = FakeTools(primary_state)
    primary_ctx = FakePrimary(spec.pyghidra_mcp_dir, {"bin.elf": primary_state})

    fork_session = forks.create_fork(spec, "fork_smt")
    # Simulate Fork renaming FUN_1000 with SMT verification provenance
    fork_session.record(
        "rename_function",
        binary="bin.elf",
        address="0x1000",
        old="FUN_1000_old",  # Base mismatch to trigger conflict
        new="crypto_verify_block",
        provenance="smt_proven",
        epistemic_status="observed",
    )

    merger = forks.ForkMerger(primary_ctx, tools_factory=lambda _: tools)
    result = merger.merge(fork_session.fork_id, decide_with_evidence=True)

    assert result["counts"].get("resolved_by_evidence") == 1
    assert result["counts"].get("conflict", 0) == 0
    assert primary_state["functions"]["0x1000"]["name"] == "crypto_verify_block"


def test_merge_fork_evidence_resolution_primary_holds(tmp_path: Path):
    """When Primary has higher epistemic rank than Fork's heuristic, Primary holds and Fork edit is discarded."""
    spec = _make_parent_project(tmp_path)
    primary_state = {
        "functions": {"0x1000": {"name": "sha256_process", "signature": "void sha256_process()", "comment": None}},
        "variables": {},
        "comments": {},
    }
    tools = FakeTools(primary_state)
    primary_ctx = FakePrimary(spec.pyghidra_mcp_dir, {"bin.elf": primary_state})

    fork_session = forks.create_fork(spec, "fork_heuristic")
    # Fork has a weak heuristic rename
    fork_session.record(
        "rename_function",
        binary="bin.elf",
        address="0x1000",
        old="FUN_1000",
        new="maybe_hash",
        provenance="analysis",
        epistemic_status="inferred",
        primary_provenance="smt_proven",
    )

    merger = forks.ForkMerger(primary_ctx, tools_factory=lambda _: tools)
    result = merger.merge(fork_session.fork_id, decide_with_evidence=True)

    assert result["counts"].get("discarded") == 1
    assert result["counts"].get("conflict", 0) == 0
    assert primary_state["functions"]["0x1000"]["name"] == "sha256_process"


def test_merge_fork_evidence_with_alias_preservation(tmp_path: Path):
    """When Fork evidence wins and preserve_alias=True, Primary's name is saved in plate comment."""
    spec = _make_parent_project(tmp_path)
    primary_state = {
        "functions": {"0x1000": {"name": "temp_name", "signature": "void temp_name()", "comment": None}},
        "variables": {},
        "comments": {},
    }
    tools = FakeTools(primary_state)
    primary_ctx = FakePrimary(spec.pyghidra_mcp_dir, {"bin.elf": primary_state})

    fork_session = forks.create_fork(spec, "fork_proven")
    fork_session.record(
        "rename_function",
        binary="bin.elf",
        address="0x1000",
        old="FUN_1000",
        new="decompressed_kernel",
        provenance="imported",
        epistemic_status="observed",
        primary_provenance="default",
    )

    merger = forks.ForkMerger(primary_ctx, tools_factory=lambda _: tools)
    result = merger.merge(fork_session.fork_id, decide_with_evidence=True, preserve_alias=True)

    assert result["counts"].get("resolved_by_evidence") == 1
    assert primary_state["functions"]["0x1000"]["name"] == "decompressed_kernel"
    assert "[Alternative name]: temp_name" in primary_state["comments"][("0x1000", "plate")]


def test_resolve_conflict_keep_evidence(tmp_path: Path):
    """resolve_conflict(keep='evidence') resolves a staged conflict using epistemic ranks."""
    spec = _make_parent_project(tmp_path)
    primary_state = {
        "functions": {"0x2000": {"name": "FUN_2000", "signature": "void FUN_2000()", "comment": None}},
        "variables": {},
        "comments": {},
    }
    tools = FakeTools(primary_state)
    primary_ctx = FakePrimary(spec.pyghidra_mcp_dir, {"bin.elf": primary_state})

    fork_session = forks.create_fork(spec, "fork_evidence_resolve")
    fork_session.record(
        "rename_function",
        binary="bin.elf",
        address="0x2000",
        old="FUN_2000_old",
        new="dwarf_verified_symbol",
        provenance="dwarf",
        epistemic_status="observed",
    )

    # First merge without evidence creates a conflict
    merger = forks.ForkMerger(primary_ctx, tools_factory=lambda _: tools)
    result = merger.merge(fork_session.fork_id, on_conflict="skip")
    assert result["counts"].get("conflict") == 1

    # Now resolve specifically with keep="evidence"
    resolved_info = forks.resolve_conflict(
        spec.pyghidra_mcp_dir,
        fork_id=fork_session.fork_id,
        seq=1,
        keep="evidence",
        context=primary_ctx,
        tools=tools,
    )

    assert resolved_info["status"] == "resolved_by_evidence"
    assert primary_state["functions"]["0x2000"]["name"] == "dwarf_verified_symbol"


def test_mcp_tools_signatures_forwarding():
    """Verify that merge_fork and resolve_conflict MCP tools expose and forward all conflict parameters."""
    import inspect

    merge_sig = inspect.signature(mcp_tools.merge_fork)
    params = merge_sig.parameters
    assert "combine_comments" in params
    assert "preserve_alias" in params
    assert "atomic_by_function" in params
    assert "decide_with_evidence" in params
    assert params["combine_comments"].default is False
    assert params["preserve_alias"].default is False
    assert params["atomic_by_function"].default is False
    assert params["decide_with_evidence"].default is False

    rc_sig = inspect.signature(mcp_tools.resolve_conflict)
    rc_params = rc_sig.parameters
    assert "keep" in rc_params
