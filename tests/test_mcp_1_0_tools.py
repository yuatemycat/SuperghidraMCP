"""Comprehensive test suite for the 6 new SuperGhidra 1.0 MCP tools in SuperghidraMCP.

Verifies:
1. Tool registration on server.mcp
2. Input schema parameter definitions, types, required fields, and defaults
3. Input validation and path resolution guardrails
4. Expected response models and attributes when invoked
5. End-to-end execution over MCP v2 protocol using InMemoryTransport
"""

from __future__ import annotations

import json
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from mcp import ClientSession

try:
    from mcp.client._memory import InMemoryTransport
except ImportError:
    import anyio
    from mcp.shared.memory import create_client_server_memory_streams

    @asynccontextmanager
    async def InMemoryTransport(server):
        lowlevel = getattr(server, "_lowlevel_server", getattr(server, "_mcp_server", server))
        async with create_client_server_memory_streams() as ((client_read, client_write), (server_read, server_write)):
            async with anyio.create_task_group() as tg:
                tg.start_soon(lambda: lowlevel.run(server_read, server_write, lowlevel.create_initialization_options()))
                yield client_read, client_write
                tg.cancel_scope.cancel()


from pyghidra_mcp import mcp_tools, server
from pyghidra_mcp.models import (
    AppleDispatchResult,
    CrateAuditResult,
    DecompileAllResult,
    Il2CppRecoverResult,
    InspectAnalysisViewResult,
    TraceNativeValuesResult,
)

NEW_1_0_TOOLS = [
    "inspect_analysis_view",
    "trace_native_values",
    "decompile_all",
    "apple_dispatch",
    "il2cpp_recover",
    "crate_audit",
]


# =============================================================================
# Section 1: Server Tool Registration & Schema Verification
# =============================================================================


def test_all_six_1_0_tools_registered_on_server():
    """Verify all 6 new 1.0 tools are registered on server.mcp."""
    registered_tools = {t.name for t in server.mcp._tool_manager.list_tools()}
    for tool_name in NEW_1_0_TOOLS:
        assert tool_name in registered_tools, f"Tool '{tool_name}' missing from server.mcp registration"


@pytest.mark.asyncio
async def test_inspect_analysis_view_schema():
    """Verify inspect_analysis_view parameter schema, defaults, and requirements."""
    tools = await server.mcp.list_tools()
    tool = next((t for t in tools if t.name == "inspect_analysis_view"), None)
    assert tool is not None, "inspect_analysis_view tool not listed by server"

    props = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("properties", {})
    required = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("required", [])

    assert "parent_evidence_id" in props
    assert "parent_evidence_id" in required
    assert "facet" in props
    assert props["facet"].get("default") == "compilable_c"
    assert "offset" in props
    assert props["offset"].get("default") == 0
    assert "limit" in props
    assert props["limit"].get("default") == 64
    assert "filter_expr" in props


@pytest.mark.asyncio
async def test_trace_native_values_schema():
    """Verify trace_native_values parameter schema, defaults, and requirements."""
    tools = await server.mcp.list_tools()
    tool = next((t for t in tools if t.name == "trace_native_values"), None)
    assert tool is not None, "trace_native_values tool not listed by server"

    props = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("properties", {})
    required = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("required", [])

    assert "binary_path" in props
    assert "binary_path" in required
    assert "procedure" in props
    assert "procedure" in required
    assert "max_depth" in props
    assert props["max_depth"].get("default") == 3
    assert "max_nodes" in props
    assert props["max_nodes"].get("default") == 2500


@pytest.mark.asyncio
async def test_decompile_all_schema():
    """Verify decompile_all parameter schema, defaults, and requirements."""
    tools = await server.mcp.list_tools()
    tool = next((t for t in tools if t.name == "decompile_all"), None)
    assert tool is not None, "decompile_all tool not listed by server"

    props = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("properties", {})
    required = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("required", [])

    assert "binary_path" in props
    assert "binary_path" in required
    assert "output_directory" in props
    assert "output_directory" in required
    assert "filter_compilable" in props
    assert props["filter_compilable"].get("default") is True
    assert "verify_z3" in props
    assert props["verify_z3"].get("default") is False
    assert "arch" in props
    assert props["arch"].get("default") == "x86_64"
    assert "resume" in props
    assert props["resume"].get("default") is True


@pytest.mark.asyncio
async def test_apple_dispatch_schema():
    """Verify apple_dispatch parameter schema, defaults, and requirements."""
    tools = await server.mcp.list_tools()
    tool = next((t for t in tools if t.name == "apple_dispatch"), None)
    assert tool is not None, "apple_dispatch tool not listed by server"

    props = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("properties", {})
    required = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("required", [])

    assert "binary_path" in props
    assert "binary_path" in required
    assert "arch" in props
    assert props["arch"].get("default") == "arm64e"
    assert "max_input_bytes" in props
    assert props["max_input_bytes"].get("default") == 67108864


@pytest.mark.asyncio
async def test_il2cpp_recover_schema():
    """Verify il2cpp_recover parameter schema, defaults, and requirements."""
    tools = await server.mcp.list_tools()
    tool = next((t for t in tools if t.name == "il2cpp_recover"), None)
    assert tool is not None, "il2cpp_recover tool not listed by server"

    props = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("properties", {})
    required = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("required", [])

    assert "global_metadata_dat_path" in props
    assert "global_metadata_dat_path" in required
    assert "binary_path" in props


@pytest.mark.asyncio
async def test_crate_audit_schema():
    """Verify crate_audit parameter schema, defaults, and requirements."""
    tools = await server.mcp.list_tools()
    tool = next((t for t in tools if t.name == "crate_audit"), None)
    assert tool is not None, "crate_audit tool not listed by server"

    props = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("properties", {})
    required = (getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})).get("required", [])

    assert "binary_path" in props
    assert "binary_path" in required


# =============================================================================
# Section 2: Input Schema Validation & Error Handling
# =============================================================================


def test_trace_native_values_rejects_missing_file():
    """trace_native_values rejects non-existent binary path."""
    with pytest.raises(Exception):
        mcp_tools.trace_native_values(
            binary_path="/nonexistent/path/to/binary_12345.so",
            procedure="main",
        )


def test_decompile_all_rejects_missing_binary():
    """decompile_all rejects non-existent binary path."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_sub = Path(tmp_dir) / "export_sub"
        with pytest.raises(Exception):
            mcp_tools.decompile_all(
                binary_path="/nonexistent/missing_binary.bin",
                output_directory=str(out_sub),
            )


def test_apple_dispatch_rejects_missing_file():
    """apple_dispatch rejects non-existent file."""
    with pytest.raises(Exception):
        mcp_tools.apple_dispatch(
            binary_path="/nonexistent/path/to/MachO_binary",
        )


def test_il2cpp_recover_rejects_missing_metadata():
    """il2cpp_recover rejects non-existent global-metadata.dat."""
    with pytest.raises(Exception):
        mcp_tools.il2cpp_recover(
            global_metadata_dat_path="/nonexistent/global-metadata.dat",
        )


def test_crate_audit_rejects_missing_binary():
    """crate_audit rejects non-existent binary path."""
    with pytest.raises(Exception):
        mcp_tools.crate_audit(
            binary_path="/nonexistent/rust_or_go_binary",
        )


# =============================================================================
# Section 3: Expected Tool Responses & Invocations
# =============================================================================


def test_inspect_analysis_view_invocation():
    """Verify inspect_analysis_view returns InspectAnalysisViewResult with paged items."""
    from superghidra.core.views import InspectAnalysisViewResponse

    mock_resp = InspectAnalysisViewResponse(
        parent_evidence_id="ev_deadbeef1234",
        facet="compilable_c",
        total_count=3,
        offset=0,
        limit=10,
        truncated=False,
        items=["int add(int a, int b) { return a + b; }", "void test() {}"],
        filter_expr=None,
    )

    with patch("superghidra.core.views.inspect_analysis_view", return_value=mock_resp):
        res = mcp_tools.inspect_analysis_view(
            parent_evidence_id="ev_deadbeef1234",
            facet="compilable_c",
            offset=0,
            limit=10,
        )

    assert isinstance(res, InspectAnalysisViewResult)
    assert res.status == "ok"
    assert res.parent_evidence_id == "ev_deadbeef1234"
    assert res.facet == "compilable_c"
    assert res.total_count == 3
    assert len(res.items) == 2
    assert res.truncated is False
    assert "compilable_c" in res.message


def test_inspect_analysis_view_cache_miss_empty():
    """Verify inspect_analysis_view returns clean 0-item result on cache miss."""
    res = mcp_tools.inspect_analysis_view(
        parent_evidence_id="ev_nonexistent_evidence",
        facet="assembly",
        offset=0,
        limit=20,
    )

    assert isinstance(res, InspectAnalysisViewResult)
    assert res.status == "ok"
    assert res.parent_evidence_id == "ev_nonexistent_evidence"
    assert res.total_count == 0
    assert len(res.items) == 0


def test_trace_native_values_invocation():
    """Verify trace_native_values returns TraceNativeValuesResult with graph stats."""

    @dataclass
    class FakeTraceReport:
        nodes: list = field(default_factory=lambda: [{"id": "n1"}, {"id": "n2"}])
        edges: list = field(default_factory=lambda: [{"from": "n1", "to": "n2"}])
        procedures_visited: list = field(default_factory=lambda: ["main", "helper"])
        max_depth: int = 3
        max_nodes: int = 2500
        omitted_ops_total: int = 0
        omitted_edges_total: int = 0
        is_truncated: bool = False

        def to_dict(self):
            return {
                "nodes": self.nodes,
                "edges": self.edges,
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "procedures_visited": self.procedures_visited,
                "is_truncated": self.is_truncated,
            }

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
        bin_path = f.name

    try:
        with patch("superghidra.lifters.trace_values.trace_native_values", return_value=FakeTraceReport()):
            res = mcp_tools.trace_native_values(
                binary_path=bin_path,
                procedure="main",
                max_depth=3,
                max_nodes=2500,
            )

        assert isinstance(res, TraceNativeValuesResult)
        assert res.status == "ok"
        assert res.root_procedure == "main"
        assert res.node_count == 2
        assert res.edge_count == 1
        assert "main" in res.procedures_visited
        assert res.is_truncated is False
        assert "Traced 2 nodes" in res.message
    finally:
        Path(bin_path).unlink(missing_ok=True)


def test_decompile_all_invocation():
    """Verify decompile_all returns DecompileAllResult with batch manifest counts."""
    from superghidra.core.bulk_decompile import BulkDecompileManifest

    fake_manifest = BulkDecompileManifest(
        target_sha256="abc123def456",
        output_directory="/tmp/export_dir",
        analysis_profile_digest="digest_123",
        total_functions=100,
        decompiled_count=98,
        external_count=2,
        skipped_count=0,
        failed_count=0,
        circuit_breaker_tripped=False,
        diagnostics="",
    )

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
        bin_path = f.name

    with tempfile.TemporaryDirectory() as base_tmp:
        out_sub = str(Path(base_tmp) / "export_sub")
        try:
            with patch("superghidra.core.bulk_decompile.BulkDecompiler") as mock_runner_cls:
                mock_runner = MagicMock()
                mock_runner.run.return_value = fake_manifest
                mock_runner_cls.return_value = mock_runner

                res = mcp_tools.decompile_all(
                    binary_path=bin_path,
                    output_directory=out_sub,
                    filter_compilable=True,
                    verify_z3=False,
                    arch="x86_64",
                    resume=True,
                )

            assert isinstance(res, DecompileAllResult)
            assert res.status == "ok"
            assert res.total_functions == 100
            assert res.decompiled_count == 98
            assert res.failed_count == 0
            assert res.circuit_breaker_tripped is False
            assert "98/100" in res.message
        finally:
            Path(bin_path).unlink(missing_ok=True)


def test_apple_dispatch_invocation():
    """Verify apple_dispatch returns AppleDispatchResult with runtime counts."""

    @dataclass
    class FakeAppleReport:
        arch: str = "arm64"
        bits: int = 64
        image_base: int = 0x100000000
        counts: dict = field(
            default_factory=lambda: {
                "objc_classes": 12,
                "swift5_types": 4,
                "chained_fixups": 88,
            }
        )
        limitations: list = field(default_factory=list)
        epistemic_status: str = "observed"

        def to_dict(self):
            return {
                "arch": self.arch,
                "bits": self.bits,
                "image_base": hex(self.image_base),
                "chained_fixups": {"entries": []},
                "swift5": {"types": []},
                "objc": {"classes": []},
                "counts": self.counts,
                "limitations": self.limitations,
                "epistemic_status": self.epistemic_status,
            }

    with tempfile.NamedTemporaryFile(suffix=".macho", delete=False) as f:
        f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        bin_path = f.name

    try:
        with patch("superghidra.formats.apple_dispatch.parse_apple_dispatch", return_value=FakeAppleReport()):
            res = mcp_tools.apple_dispatch(
                binary_path=bin_path,
                arch="arm64",
            )

        assert isinstance(res, AppleDispatchResult)
        assert res.status == "ok"
        assert res.arch == "arm64"
        assert res.bits == 64
        assert res.counts["objc_classes"] == 12
        assert res.counts["swift5_types"] == 4
        assert res.epistemic_status == "observed"
        assert "12 ObjC classes" in res.message
    finally:
        Path(bin_path).unlink(missing_ok=True)


def test_il2cpp_recover_invocation():
    """Verify il2cpp_recover returns Il2CppRecoverResult with Unity assemblies & types."""

    @dataclass
    class FakeIl2CppReport:
        is_valid: bool = True
        version: int = 29
        counts: dict = field(
            default_factory=lambda: {
                "assemblies": 5,
                "types": 42,
                "methods": 120,
            }
        )
        limitations: list = field(default_factory=list)
        epistemic_status: str = "observed"

        def to_dict(self):
            return {
                "is_valid": self.is_valid,
                "version": self.version,
                "assemblies": [{"name": "Assembly-CSharp.dll"}],
                "types": [{"name": "PlayerController"}],
                "string_literals_count": 850,
                "counts": self.counts,
                "limitations": self.limitations,
                "epistemic_status": self.epistemic_status,
            }

    with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
        f.write(b"\xaf\x1b\xb1\xfa" + b"\x00" * 60)
        meta_path = f.name

    try:
        with patch("superghidra.formats.il2cpp_metadata.recover_il2cpp_metadata", return_value=FakeIl2CppReport()):
            res = mcp_tools.il2cpp_recover(
                global_metadata_dat_path=meta_path,
            )

        assert isinstance(res, Il2CppRecoverResult)
        assert res.status == "ok"
        assert res.is_valid is True
        assert res.version == 29
        assert len(res.assemblies) == 1
        assert len(res.types) == 1
        assert res.string_literals_count == 850
        assert "v29" in res.message
    finally:
        Path(meta_path).unlink(missing_ok=True)


def test_crate_audit_invocation():
    """Verify crate_audit returns CrateAuditResult with Rust and Go summaries."""

    @dataclass
    class FakeRustGoReport:
        binary_format: str = "ELF"
        is_64bit: bool = True
        limitations: list = field(default_factory=list)
        epistemic_status: str = "observed"

        def to_dict(self):
            return {
                "binary_format": self.binary_format,
                "is_64bit": self.is_64bit,
                "rust": {
                    "has_audit_data": True,
                    "package_name": "my_daemon",
                    "rustc_commit": "1234abcd5678",
                    "crates": [{"name": "tokio", "version": "1.35.0"}],
                },
                "go": {
                    "has_buildinfo": False,
                    "go_version": None,
                    "main_module": None,
                },
                "limitations": self.limitations,
                "epistemic_status": self.epistemic_status,
            }

    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
        bin_path = f.name

    try:
        with patch("superghidra.formats.rust_go_metadata.audit_crates_and_go", return_value=FakeRustGoReport()):
            res = mcp_tools.crate_audit(
                binary_path=bin_path,
            )

        assert isinstance(res, CrateAuditResult)
        assert res.status == "ok"
        assert res.binary_format == "ELF"
        assert res.is_64bit is True
        assert len(res.rust.get("crates", [])) == 1
        assert res.rust.get("crates", [])[0]["name"] == "tokio"
        assert "1 crates" in res.message
    finally:
        Path(bin_path).unlink(missing_ok=True)


# =============================================================================
# Section 4: MCP Protocol Integration via ClientSession & InMemoryTransport
# =============================================================================


@pytest.mark.asyncio
async def test_mcp_protocol_call_inspect_analysis_view():
    """Test calling inspect_analysis_view over real MCP ClientSession transport."""
    server.mcp._pyghidra_context = MagicMock(spec=[])
    async with InMemoryTransport(server.mcp) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "inspect_analysis_view",
                {"parent_evidence_id": "ev_session_test", "facet": "compilable_c"},
            )

    assert getattr(result, "is_error", getattr(result, "isError", False)) is False
    data = json.loads(result.content[0].text)
    assert data["status"] == "ok"
    assert data["parent_evidence_id"] == "ev_session_test"
    assert data["facet"] == "compilable_c"
    assert "items" in data


@pytest.mark.asyncio
async def test_mcp_protocol_call_trace_native_values_error():
    """Test calling trace_native_values with missing file over MCP session returns error."""
    server.mcp._pyghidra_context = MagicMock(spec=[])
    async with InMemoryTransport(server.mcp) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "trace_native_values",
                {"binary_path": "/invalid/missing/binary.so", "procedure": "main"},
            )

    assert getattr(result, "is_error", getattr(result, "isError", False)) is True
    assert "not exist" in result.content[0].text.lower() or "error" in result.content[0].text.lower()
