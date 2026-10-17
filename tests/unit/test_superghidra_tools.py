"""Unit tests for SuperGhidra native MCP tools in pyghidra-mcp."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from pyghidra_mcp import mcp_tools
from pyghidra_mcp.models import (
    ClearCacheResult,
    GovernorModeResult,
    GpuAdrpScanResult,
    GpuSeedFunctionsResult,
    HibernateResult,
    RvaTranslateResult,
)


def test_rva_translate_forward_and_reverse():
    """Verify instant VA <-> RVA translation with zero JVM overhead."""
    t0 = time.perf_counter()
    res = mcp_tools.rva_translate("0x00CF2D84", "0x100000")
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert isinstance(res, RvaTranslateResult)
    assert res.status == "ok"
    assert res.va == "0x00CF2D84"
    assert res.rva == "0x00BF2D84"
    assert res.va_int == 0x00CF2D84
    assert res.rva_int == 0x00BF2D84
    assert res.image_base == "0x00100000"
    assert res.time_ms < 1.0
    assert elapsed_ms < 5.0

    # Reverse calculation from RVA
    rev = mcp_tools.rva_translate("0x00BF2D84", "0x100000")
    assert rev.status == "ok"
    assert rev.va_int == 0x00BF2D84


def test_clear_cache():
    """Verify persistent L2 SQLite cache purging."""
    with patch("ghidra_oracle.L2SQLiteCache") as mock_cache_cls:
        mock_instance = MagicMock()
        mock_instance.clear.return_value = 14
        mock_cache_cls.return_value = mock_instance

        mock_ctx = MagicMock()
        mock_pinfo = MagicMock()
        mock_ctx.request_context.lifespan_context.open_programs = {"test.so": mock_pinfo}

        res = mcp_tools.clear_cache(mock_ctx)
        assert isinstance(res, ClearCacheResult)
        assert res.status == "ok"
        assert res.cleared_entries == 14
        assert "14 entries removed" in res.message
        mock_pinfo.decompiler_pool.invalidate_all.assert_called_once()


def test_hibernate():
    """Verify hibernate triggers decompiler pool hibernation and JVM GC."""
    mock_ctx = MagicMock()
    mock_pinfo = MagicMock()
    mock_ctx.request_context.lifespan_context.open_programs = {"binary.so": mock_pinfo}

    res = mcp_tools.hibernate(mock_ctx)
    assert isinstance(res, HibernateResult)
    assert res.status == "ok"
    assert res.hibernated is True
    mock_pinfo.decompiler_pool.hibernate.assert_called_once()


def test_set_governor_mode():
    """Verify governor mode hot-swapping and policy returns."""
    mock_ctx = MagicMock()
    mock_pinfo = MagicMock()
    mock_pinfo.decompiler_pool.set_resource_mode.return_value = {
        "status": "ok",
        "mode": "turbo",
        "idle_timeout_sec": 0.0,
        "message": "Decompiler pool resource mode updated to 'turbo'",
    }
    mock_ctx.request_context.lifespan_context.open_programs = {"libg.so": mock_pinfo}

    res = mcp_tools.set_governor_mode("turbo", mock_ctx)
    assert isinstance(res, GovernorModeResult)
    assert res.status == "ok"
    assert res.mode == "turbo"
    assert res.policy is not None
    assert res.policy.mode == "turbo"

    # Test invalid mode raises error
    with pytest.raises(Exception):
        mcp_tools.set_governor_mode("invalid_mode_xyz", mock_ctx)


def test_gpu_adrp_scan():
    """Verify candidate ADRP+ADD/LDR detection over program bytes."""
    # Synthetic 64-byte stream with 1 ADRP + ADD pair
    # ADRP x1, #0
    # ADD x2, x1, #0x40
    insns = np.zeros(16, dtype=np.uint32)
    insns[0] = 0x90000001
    insns[1] = 0x91000000 | (1 << 5) | 2 | (0x40 << 10)
    raw_bytes = insns.tobytes()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(raw_bytes)
        bin_path = f.name

    try:
        mock_ctx = MagicMock()
        mock_pinfo = MagicMock()
        mock_pinfo.file_path = bin_path
        mock_pinfo.program.getImageBase().getOffset.return_value = 0x100000
        mock_ctx.request_context.lifespan_context.get_program_info.return_value = mock_pinfo

        res = mcp_tools.gpu_adrp_scan("test_bin", mock_ctx, max_matches=50)
        assert isinstance(res, GpuAdrpScanResult)
        assert res.status == "ok"
        assert res.binary_name == "test_bin"
        assert res.total_matches >= 1
        assert len(res.matches) >= 1
        m0 = res.matches[0]
        assert m0.paired_type == "ADD"
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)


def test_gpu_seed_functions():
    """Verify function entry point recovery over program bytes."""
    # Synthetic stream with PACIASP + STP prologue
    insns = np.zeros(16, dtype=np.uint32)
    insns[0] = 0xD503233F  # PACIASP
    insns[1] = 0xA9BF7BFD  # STP x29, x30, [sp, #-16]!
    raw_bytes = insns.tobytes()

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(raw_bytes)
        bin_path = f.name

    try:
        mock_ctx = MagicMock()
        mock_pinfo = MagicMock()
        mock_pinfo.file_path = bin_path
        mock_pinfo.program.getImageBase().getOffset.return_value = 0x100000
        mock_ctx.request_context.lifespan_context.get_program_info.return_value = mock_pinfo

        res = mcp_tools.gpu_seed_functions("test_bin", mock_ctx, max_functions=100)
        assert isinstance(res, GpuSeedFunctionsResult)
        assert res.status == "ok"
        assert res.binary_name == "test_bin"
        assert res.total_seeds >= 1
        assert len(res.seeds) >= 1
        assert "prologue" in res.seeds[0].sources[0]
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)
