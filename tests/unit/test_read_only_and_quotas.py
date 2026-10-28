"""
Unit tests for Read-Only session mode and CLI quota flags.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from pyghidra_mcp import mcp_tools, server
from pyghidra_mcp.context import PyGhidraContext


def test_cli_read_only_and_quota_options_default_values(monkeypatch):
    captured = {}

    def fake_init_pyghidra_context(**kwargs):
        captured.update(kwargs)
        return Mock()

    monkeypatch.setattr(server, "init_pyghidra_context", fake_init_pyghidra_context)
    monkeypatch.setattr(server, "run_headless_server", lambda *args, **kwargs: None)

    runner = CliRunner()
    result = runner.invoke(server.main, ["--project-name", "testproj"])

    assert result.exit_code == 0, result.output
    assert captured.get("read_only") is False
    assert captured.get("max_forks") == 4
    assert captured.get("max_fork_disk_mb") == 2048


def test_cli_read_only_flag_and_custom_quotas(monkeypatch):
    captured = {}

    def fake_init_pyghidra_context(**kwargs):
        captured.update(kwargs)
        return Mock()

    monkeypatch.setattr(server, "init_pyghidra_context", fake_init_pyghidra_context)
    monkeypatch.setattr(server, "run_headless_server", lambda *args, **kwargs: None)

    runner = CliRunner()
    result = runner.invoke(
        server.main,
        [
            "--project-name",
            "testproj",
            "--read-only",
            "--max-forks",
            "8",
            "--max-fork-disk-mb",
            "4096",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured.get("read_only") is True
    assert captured.get("max_forks") == 8
    assert captured.get("max_fork_disk_mb") == 4096


def test_cli_envvar_options(monkeypatch):
    captured = {}

    def fake_init_pyghidra_context(**kwargs):
        captured.update(kwargs)
        return Mock()

    monkeypatch.setattr(server, "init_pyghidra_context", fake_init_pyghidra_context)
    monkeypatch.setattr(server, "run_headless_server", lambda *args, **kwargs: None)

    runner = CliRunner()
    result = runner.invoke(
        server.main,
        ["--project-name", "testproj"],
        env={
            "PYGHIDRA_MCP_READ_ONLY": "1",
            "PYGHIDRA_MCP_MAX_FORKS": "12",
            "PYGHIDRA_MCP_MAX_FORK_DISK_MB": "8192",
        },
    )

    assert result.exit_code == 0, result.output
    assert captured.get("read_only") is True
    assert captured.get("max_forks") == 12
    assert captured.get("max_fork_disk_mb") == 8192


def test_read_only_session_disallows_mutations():
    fake_ctx = Mock()
    ro_context = SimpleNamespace(read_only=True)
    fake_ctx.request_context.lifespan_context = ro_context

    with pytest.raises(Exception, match="Session is read-only"):
        mcp_tools.rename_function("bin", "0x1000", "new_name", fake_ctx)

    with pytest.raises(Exception, match="Session is read-only"):
        mcp_tools.rename_variable("bin", "0x1000", "var", "new_var", fake_ctx)

    with pytest.raises(Exception, match="Session is read-only"):
        mcp_tools.set_variable_type("bin", "0x1000", "var", "int", fake_ctx)

    with pytest.raises(Exception, match="Session is read-only"):
        mcp_tools.set_function_prototype("bin", "0x1000", "void fn()", fake_ctx)

    with pytest.raises(Exception, match="Session is read-only"):
        mcp_tools.set_comment("bin", "0x1000", "comment", "eol", fake_ctx)

    with pytest.raises(Exception, match="Session is read-only"):
        mcp_tools.delete_project_binary("bin", fake_ctx)

    with pytest.raises(Exception, match="Session is read-only"):
        mcp_tools.merge_fork("fork-1", fake_ctx)

    with pytest.raises(Exception, match="Session is read-only"):
        mcp_tools.discard_fork("fork-1", fake_ctx)


def test_read_only_context_save_and_close_preserves_disk():
    ctx = Mock(spec=PyGhidraContext)
    ctx.read_only = True
    ctx.programs = {"p": Mock()}
    ctx.project = Mock()

    # Call un-bound save
    PyGhidraContext.save(ctx)
    ctx.project.save.assert_not_called()
