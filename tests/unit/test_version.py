from unittest.mock import Mock

import pytest

try:
    import tomllib as tomli
except ImportError:
    import tomli
from click.testing import CliRunner
from mcp import ClientSession

try:
    from mcp.client._memory import InMemoryTransport
except ImportError:
    from contextlib import asynccontextmanager

    import anyio
    from mcp.shared.memory import create_client_server_memory_streams

    @asynccontextmanager
    async def InMemoryTransport(server):
        lowlevel = getattr(server, "_lowlevel_server", getattr(server, "_mcp_server", server))
        async with create_client_server_memory_streams() as ((client_read, client_write), (server_read, server_write)):
            async with anyio.create_task_group() as tg:
                tg.start_soon(
                    lambda: lowlevel.run(
                        server_read,
                        server_write,
                        lowlevel.create_initialization_options(),
                    )
                )
                yield client_read, client_write
                tg.cancel_scope.cancel()


from pyghidra_mcp import __version__
from pyghidra_mcp.server import main, mcp


def test_version_matches_pyproject():
    """Ensures that the version in pyproject.toml and __init__.py match."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)
    assert __version__ == pyproject["project"]["version"]


@pytest.mark.asyncio
async def test_server_reports_package_version_to_mcp_clients(monkeypatch):
    monkeypatch.setattr(mcp, "_pyghidra_context", Mock(), raising=False)

    async with InMemoryTransport(mcp) as (read, write):
        async with ClientSession(read, write) as session:
            result = await session.initialize()

    server_info = getattr(result, "server_info", None) or getattr(result, "serverInfo", None)
    assert server_info.version == __version__


def test_server_cli_reports_package_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_mcp_dependency_uses_supported_v2():
    """Keep the MCP API and declared dependency on the same major version."""
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)

    expected = "mcp[cli]>=2.0.0,<3"
    assert expected in pyproject["project"]["dependencies"]
    assert expected in pyproject["dependency-groups"]["dev"]
    assert expected in pyproject["project"]["optional-dependencies"]["dev"]
