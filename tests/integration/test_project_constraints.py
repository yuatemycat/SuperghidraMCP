import json
import tempfile
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.fixture(scope="module")
def readonly_directory():
    """Create a temporary directory with read-only permissions"""
    with tempfile.TemporaryDirectory() as temp_dir:
        readonly_dir = Path(temp_dir) / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)  # Read-only
        yield readonly_dir
        # Cleanup: restore write permissions before deletion
        readonly_dir.chmod(0o755)


@pytest.fixture(scope="module")
def valid_gpr_file():
    """Create a temporary .gpr file for testing"""
    with tempfile.TemporaryDirectory() as temp_dir:
        gpr_path = Path(temp_dir) / "test_project.gpr"
        gpr_path.write_text("test gpr content")
        yield gpr_path


@pytest.fixture(scope="module")
def server_params_gpr_constraint_violation(valid_gpr_file):
    """Server params that should fail .gpr constraint test"""
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(valid_gpr_file),
            "--project-name",
            "custom_name",  # This should cause violation
            "--no-threaded",
        ],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params_gpr_valid(valid_gpr_file):
    """Server params for valid .gpr file usage"""
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(valid_gpr_file),
            "--no-threaded",
        ],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params_readonly_violation(readonly_directory):
    """Server params that should fail due to read-only directory"""
    project_path = readonly_directory / "project"
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "pyghidra_mcp",
            "--project-path",
            str(project_path),
            "--project-name",
            "test_project",
            "--no-threaded",
        ],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params_directory_valid():
    """Server params for valid directory with project name"""
    with tempfile.TemporaryDirectory() as temp_dir:
        project_path = Path(temp_dir) / "test_project"
        yield StdioServerParameters(
            command="python",
            args=[
                "-m",
                "pyghidra_mcp",
                "--project-path",
                str(project_path),
                "--project-name",
                "test_project",
                "--no-threaded",
            ],
            env={"GHIDRA_INSTALL_DIR": "/ghidra"},
        )


@pytest.mark.asyncio
async def test_gpr_with_custom_project_name_raises_error(server_params_gpr_constraint_violation):
    """Test that .gpr file + custom --project-name raises BadParameter"""
    with pytest.raises(Exception) as exc_info:
        async with stdio_client(server_params_gpr_constraint_violation) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

    # Check that the error message contains our constraint text
    # The actual error is wrapped in an ExceptionGroup, so we check the cause
    error_str = str(exc_info.value)
    assert (
        "Cannot use --project-name when specifying a .gpr file" in error_str
        or "Invalid value" in error_str
    )


@pytest.mark.asyncio
async def test_gpr_derives_name_from_filename(server_params_gpr_valid, valid_gpr_file):
    """Test that .gpr file uses filename stem as project name"""
    async with stdio_client(server_params_gpr_valid) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Verify project was created successfully
            results = await session.call_tool("list_project_binaries", {})
            assert results is not None
            assert len(results.content) > 0

            program_infos = json.loads(results.content[0].text)
            assert "programs" in program_infos
            assert isinstance(program_infos["programs"], list)

            # Verify directory structure uses derived name
            expected_project_name = valid_gpr_file.stem  # "test_project"
            expected_artifact_dir = valid_gpr_file.parent / f"{expected_project_name}-pyghidra-mcp"
            assert (
                expected_artifact_dir.exists()
            ), f"Expected artifact directory {expected_artifact_dir} to be created"


@pytest.mark.asyncio
async def test_directory_with_project_name_works(server_params_directory_valid):
    """Test that directory path + --project-name works normally"""
    async with stdio_client(server_params_directory_valid) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Should work without issues
            results = await session.call_tool("list_project_binaries", {})
            assert results is not None
            assert len(results.content) > 0

            program_infos = json.loads(results.content[0].text)
            assert "programs" in program_infos
            assert isinstance(program_infos["programs"], list)


@pytest.mark.asyncio
async def test_readonly_directory_fails_with_clear_error(server_params_readonly_violation):
    """Test failure when parent directory is read-only"""
    try:
        async with stdio_client(server_params_readonly_violation) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
        # If we get here, the test failed
        raise AssertionError("Expected ClickException for read-only directory")
    except Exception as e:
        # Should fail with a clear error message about writeability
        assert "Cannot write to" in str(e)
        assert "directory" in str(e)
        assert "Please check permissions" in str(e)


@pytest.mark.asyncio
async def test_gpr_project_structure_created_correctly(valid_gpr_file):
    """Verify .gpr projects create correct directory structure"""
    with tempfile.TemporaryDirectory() as temp_dir:
        gpr_path = Path(temp_dir) / "structure_test.gpr"
        gpr_path.write_text("test content")

        server_params = StdioServerParameters(
            command="python",
            args=[
                "-m",
                "pyghidra_mcp",
                "--project-path",
                str(gpr_path),
                "--no-threaded",
            ],
            env={"GHIDRA_INSTALL_DIR": "/ghidra"},
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Verify correct directory structure
                expected_project_name = gpr_path.stem
                expected_artifact_dir = gpr_path.parent / f"{expected_project_name}-pyghidra-mcp"

                assert (
                    expected_artifact_dir.exists()
                ), "pyghidra-mcp artifact directory should be created"
                assert (
                    expected_artifact_dir / "chromadb"
                ).exists(), "chromadb directory should be created"
                assert (expected_artifact_dir / "gzfs").exists(), "gzfs directory should be created"


@pytest.mark.asyncio
async def test_directory_project_structure_created_correctly():
    """Verify directory projects create correct directory structure"""
    with tempfile.TemporaryDirectory() as temp_dir:
        project_path = Path(temp_dir) / "dir_test_project"

        server_params = StdioServerParameters(
            command="python",
            args=[
                "-m",
                "pyghidra_mcp",
                "--project-path",
                str(project_path),
                "--project-name",
                "dir_test_project",
                "--no-threaded",
            ],
            env={"GHIDRA_INSTALL_DIR": "/ghidra"},
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Verify correct directory structure
                expected_artifact_dir = project_path / "dir_test_project-pyghidra-mcp"

                assert (
                    expected_artifact_dir.exists()
                ), "pyghidra-mcp artifact directory should be created"
                assert (
                    expected_artifact_dir / "chromadb"
                ).exists(), "chromadb directory should be created"
                assert (expected_artifact_dir / "gzfs").exists(), "gzfs directory should be created"


@pytest.mark.asyncio
async def test_gpr_edge_case_filenames():
    """Test .gpr files with various filename patterns"""
    test_cases = ["My-Project.gpr", "project_v2.gpr", "test-project-123.gpr"]

    for filename in test_cases:
        with tempfile.TemporaryDirectory() as temp_dir:
            gpr_path = Path(temp_dir) / filename
            gpr_path.write_text("test content")

            server_params = StdioServerParameters(
                command="python",
                args=[
                    "-m",
                    "pyghidra_mcp",
                    "--project-path",
                    str(gpr_path),
                    "--no-threaded",
                ],
                env={"GHIDRA_INSTALL_DIR": "/ghidra"},
            )

            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()

                    # Verify project was created with correct derived name
                    expected_project_name = gpr_path.stem
                    expected_artifact_dir = (
                        gpr_path.parent / f"{expected_project_name}-pyghidra-mcp"
                    )
                    assert (
                        expected_artifact_dir.exists()
                    ), f"Expected artifact directory for {filename}"
