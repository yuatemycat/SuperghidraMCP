"""
Unit tests for the 6 new 1.0 tools in SuperghidraMCP:
- inspect_analysis_view
- trace_native_values
- decompile_all
- apple_dispatch
- il2cpp_recover
- crate_audit
"""

import struct
from pathlib import Path

from pyghidra_mcp import mcp_tools, server
from pyghidra_mcp.models import (
    AppleDispatchResult,
    CrateAuditResult,
    DecompileAllResult,
    Il2CppRecoverResult,
    InspectAnalysisViewResult,
    TraceNativeValuesResult,
)


def test_tools_registered_in_server():
    """Verify all 6 new 1.0 tools are registered in server.mcp."""
    tool_names = {t.name for t in server.mcp._tool_manager.list_tools()}
    for tool_name in (
        "inspect_analysis_view",
        "trace_native_values",
        "decompile_all",
        "apple_dispatch",
        "il2cpp_recover",
        "crate_audit",
    ):
        assert tool_name in tool_names, f"Tool '{tool_name}' not registered in server.mcp"


def test_inspect_analysis_view():
    """Verify inspect_analysis_view queries L2 cache safely."""
    res = mcp_tools.inspect_analysis_view(
        parent_evidence_id="nonexistent-evidence-id-12345",
        facet="compilable_c",
        offset=0,
        limit=32,
    )
    assert isinstance(res, InspectAnalysisViewResult)
    assert res.status == "ok"
    assert res.facet == "compilable_c"
    assert res.total_count == 0
    assert res.items == []
    assert res.truncated is False


def test_trace_native_values(tmp_path: Path):
    """Verify trace_native_values traces high-P-code def-use values."""
    dummy_bin = tmp_path / "dummy.elf"
    dummy_bin.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 57)
    res = mcp_tools.trace_native_values(
        binary_path=str(dummy_bin),
        procedure="main",
        max_depth=2,
        max_nodes=100,
    )
    assert isinstance(res, TraceNativeValuesResult)
    assert res.status == "ok"
    assert res.root_procedure == "main"
    assert res.max_depth == 2
    assert res.max_nodes == 100


def test_decompile_all(tmp_path: Path):
    """Verify decompile_all initializes bulk decompiler run."""
    dummy_bin = tmp_path / "app.elf"
    dummy_bin.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 57)
    out_dir = tmp_path / "export_dir"
    res = mcp_tools.decompile_all(
        binary_path=str(dummy_bin),
        output_directory=str(out_dir),
        filter_compilable=True,
        verify_z3=False,
        arch="x86_64",
    )
    assert isinstance(res, DecompileAllResult)
    assert res.status == "ok"
    assert res.output_directory == str(out_dir)
    assert (out_dir / ".superghidra-export.meta.json").exists()


def test_apple_dispatch(tmp_path: Path):
    """Verify apple_dispatch parses Mach-O headers and metadata."""
    dummy_macho = tmp_path / "app_arm64e"
    # Mach-O 64-bit header: magic(0xFEEDFACF), cputype(CPU_TYPE_ARM64 = 0x0100000C), cpusubtype(2 = arm64e)
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 2, 2, 0, 0, 0, 0)
    dummy_macho.write_bytes(hdr + b"\x00" * 64)
    res = mcp_tools.apple_dispatch(
        binary_path=str(dummy_macho),
        arch="arm64e",
    )
    assert isinstance(res, AppleDispatchResult)
    assert res.status == "ok"
    assert res.bits == 64
    assert res.arch in ("arm64e", "arm64")


def test_il2cpp_recover(tmp_path: Path):
    """Verify il2cpp_recover parses global-metadata.dat."""
    dummy_meta = tmp_path / "global-metadata.dat"
    # header: magic(0xFAB11BAF), version(29), followed by zero offsets
    hdr = struct.pack("<II", 0xFAB11BAF, 29) + b"\x00" * 512
    dummy_meta.write_bytes(hdr)
    res = mcp_tools.il2cpp_recover(
        global_metadata_dat_path=str(dummy_meta),
    )
    assert isinstance(res, Il2CppRecoverResult)
    assert res.status == "ok"
    assert res.version == 29
    assert res.is_valid is True


def test_crate_audit(tmp_path: Path):
    """Verify crate_audit parses static binary toolchain metadata."""
    dummy_bin = tmp_path / "rust_app.elf"
    dummy_bin.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 57)
    res = mcp_tools.crate_audit(
        binary_path=str(dummy_bin),
    )
    assert isinstance(res, CrateAuditResult)
    assert res.status == "ok"
    assert res.binary_format == "ELF"
    assert res.is_64bit is True
