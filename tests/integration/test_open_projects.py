import json
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_open_existing_notepad_project(server_params_existing_notepad_project):
    """Test opening existing notepad project from other_projects/"""
    async with stdio_client(server_params_existing_notepad_project) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Should be able to list binaries from notepad project (may be empty)
            results = await session.call_tool("list_project_binaries", {})
            assert results is not None
            assert len(results.content) > 0

            program_infos = json.loads(results.content[0].text)
            assert "programs" in program_infos
            programs = program_infos["programs"]
            assert isinstance(programs, list)  # Should be a list, even if empty


@pytest.mark.asyncio
async def test_open_custom_named_project(server_params_custom_project_name):
    """Test opening/creating project with custom name"""
    async with stdio_client(server_params_custom_project_name) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Should create project and work (even if empty)
            results = await session.call_tool("list_project_binaries", {})
            assert results is not None

            program_infos = json.loads(results.content[0].text)
            assert "programs" in program_infos
            assert isinstance(program_infos["programs"], list)


@pytest.mark.asyncio
async def test_open_nested_project_location(server_params_nested_project_location):
    """Test opening project in deeply nested location"""
    async with stdio_client(server_params_nested_project_location) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Should handle nested paths and create directories as needed
            results = await session.call_tool("list_project_binaries", {})
            assert results is not None

            program_infos = json.loads(results.content[0].text)
            assert "programs" in program_infos


@pytest.mark.asyncio
async def test_project_directory_structure_created(
    server_params_custom_project_name, custom_project_directory
):
    """Test that pyghidra-mcp creates expected directories"""
    async with stdio_client(server_params_custom_project_name) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Verify project directories were created
            project_path = custom_project_directory / "my_analysis_project"
            assert project_path.exists()
            pyghidra_mcp_dir = project_path / "my_project-pyghidra-mcp"
            assert pyghidra_mcp_dir.exists()
            assert (pyghidra_mcp_dir / "chromadb").exists()  # pyghidra addition
            # Note: gzfs is created at pyghidra-mcp level


@pytest.mark.asyncio
async def test_pyghidra_additions_created_for_new_project(
    server_params_custom_project_name, custom_project_directory
):
    """Verify pyghidra-mcp adds chromadb and gzfs directories to new projects"""
    async with stdio_client(server_params_custom_project_name) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            project_path = custom_project_directory / "my_analysis_project"

            # pyghidra-mcp specific directories should be created
            pyghidra_mcp_dir = project_path / "my_project-pyghidra-mcp"
            chromadb_path = pyghidra_mcp_dir / "chromadb"
            assert chromadb_path.exists(), "ChromaDB directory should be created"

            # GZFS directory should be created at pyghidra-mcp level
            gzfs_path = pyghidra_mcp_dir / "gzfs"
            assert gzfs_path.exists(), "GZFS directory should be created"


@pytest.mark.asyncio
async def test_existing_project_pyghidra_integration(server_params_existing_notepad_project):
    """Test that pyghidra-mcp integrates with existing project structure"""
    async with stdio_client(server_params_existing_notepad_project) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Should create chromadb in notepad-pyghidra-mcp directory alongside existing project
            notepad_project = Path(__file__).parent.parent.parent / "other_projects" / "notepad"
            chromadb_path = notepad_project.parent / "notepad-pyghidra-mcp" / "chromadb"
            assert chromadb_path.exists(), "ChromaDB should be added to existing projects"

            # Should still be able to list binaries (may be empty)
            results = await session.call_tool("list_project_binaries", {})
            program_infos = json.loads(results.content[0].text)
            assert isinstance(program_infos["programs"], list), "Should return a list of programs"
