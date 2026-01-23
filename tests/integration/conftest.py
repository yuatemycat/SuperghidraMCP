import json
import os
import tempfile
from pathlib import Path

import pytest
from mcp import StdioServerParameters


@pytest.fixture(scope="module")
def test_binary():
    """Create a simple test binary for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_one() {
    printf("Function One");
}

void function_two() {
    printf("Function Two");
}

int main() {
    printf("Hello, World!");
    function_one();
    function_two();
    return 0;
}
"""
        )
        c_file = f.name

    bin_file = c_file.replace(".c", "")

    os.system(f"gcc -o {bin_file} {c_file}")

    yield bin_file

    os.unlink(c_file)
    os.unlink(bin_file)


@pytest.fixture(scope="module")
def test_shared_object():
    """
    Create a simple shared object for testing.
    """
    # 1. Write the C source to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(
            """
#include <stdio.h>

void function_one() {
    printf("Function One");
}

void function_two() {
    printf("Function Two");
}

// No main() needed for a shared library
"""
        )
        c_file = f.name

    # 2. Compile as a shared object
    so_file = c_file.replace(".c", ".so")
    cmd = f"gcc -fPIC -shared -o {so_file} {c_file}"
    ret = os.system(cmd)
    if ret != 0:
        raise RuntimeError(f"Compilation failed: {cmd}")

    # 3. Yield path to .so for tests
    yield so_file

    # 4. Clean up
    os.unlink(c_file)
    os.unlink(so_file)


@pytest.fixture(scope="module")
def server_params_no_input():
    """Get server parameters with no test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--wait-for-analysis"],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--wait-for-analysis", test_binary],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params_no_thread(test_binary):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--no-threaded", test_binary],  # no-thread for chromadb_testing
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params_shared_object(test_shared_object):
    """Get server parameters with a test binary."""
    return StdioServerParameters(
        command="python",  # Executable
        # Run with test binary
        args=["-m", "pyghidra_mcp", "--wait-for-analysis", test_shared_object],
        # Optional environment variables
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture()
def find_binary_in_list_response():
    """Return a helper that finds a binary by generated name in a list_project_binaries response."""

    def _finder(response, binary_name):
        text_content = response.content[0].text
        program_infos = json.loads(text_content)["programs"]

        for program in program_infos:
            if binary_name in program["name"]:
                return program

        return None

    return _finder


@pytest.fixture(scope="module")
def server_params_existing_notepad_project():
    """Server with existing notepad project from other_projects/"""
    project_path = Path(__file__).parent.parent.parent / "other_projects" / "notepad.gpr"
    return StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", "--project-path", str(project_path), "--wait-for-analysis"],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def custom_project_directory():
    """Create temporary directory for custom named projects"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture(scope="module")
def server_params_custom_project_name(custom_project_directory):
    """Server with custom project path and name"""
    custom_project = custom_project_directory / "my_analysis_project"
    return StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", "--project-path", str(custom_project), "--wait-for-analysis"],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )


@pytest.fixture(scope="module")
def server_params_nested_project_location(custom_project_directory):
    """Server with nested project location"""
    nested_project = custom_project_directory / "deeply/nested/location/test_project"
    return StdioServerParameters(
        command="python",
        args=["-m", "pyghidra_mcp", "--project-path", str(nested_project), "--wait-for-analysis"],
        env={"GHIDRA_INSTALL_DIR": "/ghidra"},
    )
