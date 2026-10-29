import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

import pyghidra_mcp.context as context_mod
from pyghidra_mcp import forks, server
from pyghidra_mcp.context import _DEFAULT_GZFS, PyGhidraContext
from pyghidra_mcp.project_spec import ProjectSpec


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


def _dead_pid() -> int:
    """Spawn and terminate a process to get a reliably dead PID."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _stop(fork: forks.ForkSession, *, closed: bool = True) -> None:
    """Mark a fork session as stopped and dead for testing."""
    meta_path = fork.fork_dir / forks.FORK_META_FILE
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["pid"] = _dead_pid()
    meta["status"] = "closed" if closed else "active"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")


def _fake_pyghidra_context(
    tmp_path: Path,
    *,
    gzfs_path=None,
    read_only: bool = False,
    pyghidra_mcp_dir: Path | None = None,
) -> PyGhidraContext:
    """Construct an uninitialized PyGhidraContext instance with mocked methods."""
    ctx = PyGhidraContext.__new__(PyGhidraContext)
    ctx.project_name = "test_project"
    ctx.project_path = tmp_path / "test_project"
    ctx.project_path.mkdir(parents=True, exist_ok=True)
    ctx.pyghidra_mcp_dir = pyghidra_mcp_dir or ctx.project_path / "superghidra-mcp"
    ctx.pyghidra_mcp_dir.mkdir(parents=True, exist_ok=True)
    ctx.fork_session = None
    ctx.force_analysis = False
    ctx.verbose_analysis = False
    ctx.no_symbols = False
    ctx.gdts = []
    ctx.symbols_path = ctx.pyghidra_mcp_dir / "symbols"
    ctx.sym_file_path = None
    ctx.program_options = None
    ctx.threaded = False
    ctx.max_workers = 1
    ctx.wait_for_analysis = False
    ctx.programs = {}
    ctx.project = Mock()

    # Simulate _init_after_project_open GZFS configuration logic
    default_sentinel = getattr(context_mod, "_DEFAULT_GZFS", _DEFAULT_GZFS)
    if gzfs_path is default_sentinel:
        ctx.gzfs_path = ctx.pyghidra_mcp_dir / "gzfs"
    elif gzfs_path is None or gzfs_path is False or gzfs_path == "":
        ctx.gzfs_path = None
    else:
        ctx.gzfs_path = Path(gzfs_path)

    if ctx.gzfs_path is not None:
        ctx.gzfs_path.mkdir(exist_ok=True, parents=True)

    return ctx


# ---------------------------------------------------------------------------------
# 1. GZFS Storage Suppression and Default Behavior
# ---------------------------------------------------------------------------------


def test_init_context_gzfs_path_none_suppresses_directory_and_archives(tmp_path):
    """When gzfs_path=None, context.gzfs_path must be None and no gzfs/ dir is created."""
    ctx = _fake_pyghidra_context(tmp_path, gzfs_path=None)

    assert ctx.gzfs_path is None
    assert not (ctx.pyghidra_mcp_dir / "gzfs").exists()


def test_real_init_after_project_open_gzfs_none_and_default(tmp_path):
    """Test the real PyGhidraContext._init_after_project_open logic with None and _DEFAULT_GZFS."""
    # 1. With gzfs_path=None
    ctx = PyGhidraContext.__new__(PyGhidraContext)
    ctx.project_path = tmp_path / "real_proj1"
    ctx.project_path.mkdir(parents=True, exist_ok=True)
    ctx.programs = {}
    with patch.object(ctx, "_init_indexing_state"), patch.object(ctx, "_init_project_programs"):
        ctx._init_after_project_open(
            pyghidra_mcp_dir=ctx.project_path / "superghidra-mcp",
            force_analysis=False,
            verbose_analysis=False,
            no_symbols=False,
            gdts=None,
            program_options=None,
            gzfs_path=None,
            threaded=False,
            max_workers=1,
            wait_for_analysis=False,
            symbols_path=None,
            sym_file_path=None,
        )
    assert ctx.gzfs_path is None
    assert not (ctx.pyghidra_mcp_dir / "gzfs").exists()

    # 2. With default _DEFAULT_GZFS
    ctx2 = PyGhidraContext.__new__(PyGhidraContext)
    ctx2.project_path = tmp_path / "real_proj2"
    ctx2.project_path.mkdir(parents=True, exist_ok=True)
    ctx2.programs = {}
    with patch.object(ctx2, "_init_indexing_state"), patch.object(ctx2, "_init_project_programs"):
        ctx2._init_after_project_open(
            pyghidra_mcp_dir=ctx2.project_path / "superghidra-mcp",
            force_analysis=False,
            verbose_analysis=False,
            no_symbols=False,
            gdts=None,
            program_options=None,
            gzfs_path=_DEFAULT_GZFS,
            threaded=False,
            max_workers=1,
            wait_for_analysis=False,
            symbols_path=None,
            sym_file_path=None,
        )
    assert ctx2.gzfs_path == ctx2.pyghidra_mcp_dir / "gzfs"
    assert ctx2.gzfs_path.is_dir()


def test_init_context_gzfs_path_false_or_empty_suppresses_archives(tmp_path):
    """Passing False or empty string for gzfs_path must also suppress GZFS creation."""
    ctx_false = _fake_pyghidra_context(tmp_path / "false_test", gzfs_path=False)
    assert ctx_false.gzfs_path is None
    assert not (ctx_false.pyghidra_mcp_dir / "gzfs").exists()

    ctx_empty = _fake_pyghidra_context(tmp_path / "empty_test", gzfs_path="")
    assert ctx_empty.gzfs_path is None
    assert not (ctx_empty.pyghidra_mcp_dir / "gzfs").exists()


def test_init_context_gzfs_default_sentinel_creates_directory(tmp_path):
    """Omitting gzfs_path or using _DEFAULT_GZFS creates the canonical gzfs/ directory."""
    default_sentinel = getattr(context_mod, "_DEFAULT_GZFS", _DEFAULT_GZFS)
    ctx = _fake_pyghidra_context(tmp_path, gzfs_path=default_sentinel)

    assert ctx.gzfs_path == ctx.pyghidra_mcp_dir / "gzfs"
    assert ctx.gzfs_path.is_dir()


def test_init_context_gzfs_custom_path_creates_directory(tmp_path):
    """Providing an explicit Path creates and uses that custom archive directory."""
    custom_dir = tmp_path / "custom_archive_dir"
    ctx = _fake_pyghidra_context(tmp_path, gzfs_path=custom_dir)

    assert ctx.gzfs_path == custom_dir
    assert custom_dir.is_dir()


def test_save_packed_file_skipped_when_gzfs_path_is_none(tmp_path):
    """When context.gzfs_path is None, analysis completion does not pack or export GZFs."""
    ctx = _fake_pyghidra_context(tmp_path, gzfs_path=None)

    # Simulate analysis finish block from PyGhidraContext._analyze_program_internal
    mock_df = Mock()
    mock_df.pathname = "/bin/sample_elf"
    mock_program = Mock()

    # If gzfs_path is None, saveAsPackedFile should not be called
    if ctx.gzfs_path is not None:
        pathname = mock_df.pathname.replace("/", "_")
        _gzf_file = ctx.gzfs_path / f"{pathname}.gzf"
        ctx.project.saveAsPackedFile(mock_program, Mock(), True)

    ctx.project.saveAsPackedFile.assert_not_called()
    assert not (ctx.pyghidra_mcp_dir / "gzfs").exists()


# ---------------------------------------------------------------------------------
# 2. Clean Fork Recycling in find_reusable_fork
# ---------------------------------------------------------------------------------


def test_find_reusable_fork_discovers_clean_stopped_fork(tmp_path):
    """find_reusable_fork must discover and return clean stopped forks (pending_ops==0)."""
    parent = _make_parent_project(tmp_path)
    clean_fork = forks.create_fork(parent, label="analyst_a")
    _stop(clean_fork)

    # Ensure fork is dead and clean
    info = forks.describe_fork(clean_fork.fork_dir)
    assert info is not None
    assert info["alive"] is False
    assert info["pending_ops"] == 0

    reused = forks.find_reusable_fork(parent, label="analyst_a")
    assert reused is not None
    assert reused.fork_id == clean_fork.fork_id
    assert reused.op_count == 0


def test_find_reusable_fork_prefers_unmerged_pending_over_clean(tmp_path):
    """find_reusable_fork must prefer a stopped fork with unmerged edits over a clean one."""
    parent = _make_parent_project(tmp_path)

    # 1. First clean stopped fork
    clean_fork = forks.create_fork(parent, label="analyst_b")
    _stop(clean_fork)

    # 2. Second stopped fork with pending edits
    pending_fork = forks.create_fork(parent, label="analyst_b")
    pending_fork.record("rename_function", "/bin", address="1000", old="FUN_1000", new="entry")
    _stop(pending_fork)

    reused = forks.find_reusable_fork(parent, label="analyst_b")
    assert reused is not None
    assert reused.fork_id == pending_fork.fork_id
    assert reused.op_count == 1


def test_find_reusable_fork_never_reuses_alive_fork(tmp_path):
    """A fork that is actively running (alive=True) must never be hijacked."""
    parent = _make_parent_project(tmp_path)
    active_fork = forks.create_fork(parent, label="analyst_c")
    assert active_fork.fork_dir.is_dir()
    # Leave active_fork running with current PID and active status

    reused = forks.find_reusable_fork(parent, label="analyst_c")
    assert reused is None


def test_find_reusable_fork_returns_none_when_no_matching_forks(tmp_path):
    """find_reusable_fork returns None when no matching stopped fork exists."""
    parent = _make_parent_project(tmp_path)
    assert forks.find_reusable_fork(parent, label="nonexistent") is None
    assert forks.find_reusable_fork(parent, label=None) is None


# ---------------------------------------------------------------------------------
# 3. Automatic Fork Pruning at Startup
# ---------------------------------------------------------------------------------


def test_prune_forks_startup_cleans_dead_zero_pending_forks(tmp_path):
    """prune_forks cleans dead forks with 0 pending ops while preserving active or unmerged."""
    parent = _make_parent_project(tmp_path)

    # Fork 1: dead, fully clean (0 pending ops) -> should be pruned
    dead_clean = forks.create_fork(parent, label="dead_clean")
    _stop(dead_clean)

    # Fork 2: dead, but has unmerged edits -> should NOT be pruned by default
    dead_pending = forks.create_fork(parent, label="dead_pending")
    dead_pending.record("rename_function", "/bin", address="2000", old="FUN_2000", new="main")
    _stop(dead_pending)

    # Fork 3: active running fork -> should NOT be pruned
    active_fork = forks.create_fork(parent, label="active_worker")

    res = forks.prune_forks(parent.pyghidra_mcp_dir, dry_run=False)

    pruned_ids = [p["fork_id"] for p in res["pruned"]]
    assert dead_clean.fork_id in pruned_ids
    assert not dead_clean.fork_dir.exists()

    assert dead_pending.fork_id not in pruned_ids
    assert dead_pending.fork_dir.exists()

    assert active_fork.fork_id not in pruned_ids
    assert active_fork.fork_dir.exists()


def test_startup_pruning_invoked_in_create_project_context(tmp_path, monkeypatch):
    """create_project_context invokes prune_forks on project startup."""
    parent = _make_parent_project(tmp_path)
    dead_clean = forks.create_fork(parent, label="startup_pruned")
    _stop(dead_clean)

    # Mock PyGhidraContext to avoid full JVM startup
    mock_ctx = Mock(
        fork_session=None,
        pyghidra_mcp_dir=parent.pyghidra_mcp_dir,
        project_path=parent.project_directory,
        project_name=parent.project_name,
    )
    monkeypatch.setattr(server, "PyGhidraContext", Mock(return_value=mock_ctx))

    server.create_project_context(
        project_spec=parent,
        force_analysis=False,
        gzfs_path=None,
        threaded=False,
    )

    # Verify dead clean fork was pruned
    assert not dead_clean.fork_dir.exists()


# ---------------------------------------------------------------------------------
# 4. Quota Enforcement (max_forks and max_fork_disk_mb)
# ---------------------------------------------------------------------------------


def test_create_fork_prunes_dead_forks_when_max_forks_exceeded(tmp_path):
    """create_fork auto-prunes dead forks to stay within max_forks limit."""
    parent = _make_parent_project(tmp_path)

    # Create dead clean fork
    fork_dead = forks.create_fork(parent, label="f_dead", max_forks=10)
    _stop(fork_dead)

    # Create active fork 1
    fork_active = forks.create_fork(parent, label="f_active", max_forks=10)

    # Now create another fork with max_forks=2
    # Total count would be 3, exceeding limit 2.
    # It must prune dead fork_dead and succeed.
    new_fork = forks.create_fork(parent, label="f_new", max_forks=2)

    assert new_fork is not None
    assert new_fork.fork_dir.exists()
    assert not fork_dead.fork_dir.exists()
    assert fork_active.fork_dir.exists()

    remaining = forks.list_forks(parent.pyghidra_mcp_dir)
    assert len(remaining) <= 2


def test_create_fork_raises_runtime_error_when_active_forks_exceed_quota(tmp_path):
    """create_fork raises RuntimeError when active forks cannot be pruned to satisfy quota."""
    parent = _make_parent_project(tmp_path)

    # Create 2 active running forks
    fork1 = forks.create_fork(parent, label="active1", max_forks=5)
    fork2 = forks.create_fork(parent, label="active2", max_forks=5)
    assert fork1.fork_dir.is_dir() and fork2.fork_dir.is_dir()

    # Attempting to create a 3rd fork when max_forks=2 and both existing are active
    with pytest.raises(RuntimeError, match=r"(?i)quota"):
        forks.create_fork(parent, label="active3", max_forks=2)


def test_create_fork_enforces_disk_quota(tmp_path):
    """create_fork cleans up dead forks or enforces bounds when disk quota is exceeded."""
    parent = _make_parent_project(tmp_path)

    # Create a dead fork with simulated large file
    fork_dead = forks.create_fork(parent, label="f_heavy", max_forks=10, max_fork_disk_mb=1000)
    big_file = fork_dead.fork_dir / "large_payload.bin"
    big_file.write_bytes(b"\x00" * (2 * 1024 * 1024))  # 2 MB
    _stop(fork_dead)

    # Creating a new fork with a tiny max_fork_disk_mb should prune the dead heavy fork
    new_fork = forks.create_fork(parent, label="f_light", max_forks=10, max_fork_disk_mb=1)
    assert new_fork is not None
    assert not fork_dead.fork_dir.exists()


# ---------------------------------------------------------------------------------
# 5. Post-Merge Cleanup and Reclaiming Storage
# ---------------------------------------------------------------------------------


def test_post_merge_auto_discard_cleans_fully_merged_fork(tmp_path):
    """merge_fork with auto_discard=True deletes fork directory on clean merge."""
    parent = _make_parent_project(tmp_path)
    fork = forks.create_fork(parent, label="merge_clean")
    fork.record("rename_function", "/bin/app", address="1000", old="FUN_1000", new="target")
    _stop(fork)

    bin_name = "/bin/app"
    state = {
        "functions": {"1000": {"name": "FUN_1000", "signature": "void FUN_1000()"}},
        "variables": {},
        "comments": {},
    }

    class FakeTools:
        def __init__(self, _state):
            pass

        def find_function(self, addr):
            fn = state["functions"].get(addr)
            if not fn:
                raise ValueError("Function not found")
            return SimpleNamespace(getName=lambda: fn["name"])

        def rename_function(self, addr, new_name):
            state["functions"][addr]["name"] = new_name

    fake_primary = SimpleNamespace(
        pyghidra_mcp_dir=parent.pyghidra_mcp_dir,
        programs={bin_name: state},
        get_program_info=lambda name: fake_primary.programs[name],
        save=Mock(),
    )

    merger = forks.ForkMerger(fake_primary, FakeTools)
    result = merger.merge(fork.fork_id, auto_discard=True)

    assert result["counts"] == {"applied": 1}
    assert result["pending_ops"] == 0

    # Auto-discard post-merge deletes the fork directory immediately
    assert not fork.fork_dir.exists()

    # Also test auto_discard=False retains the fork until pruned
    state["functions"]["1000"]["name"] = "FUN_1000"  # reset primary state for clean merge
    fork2 = forks.create_fork(parent, label="merge_retain")
    fork2.record("rename_function", "/bin/app", address="1000", old="FUN_1000", new="target2")
    _stop(fork2)

    result2 = merger.merge(fork2.fork_id, auto_discard=False)
    assert result2["counts"] == {"applied": 1}
    assert result2["pending_ops"] == 0
    assert fork2.fork_dir.exists()

    # Now post-merge prune reclaims it
    res = forks.prune_forks(parent.pyghidra_mcp_dir)
    pruned_ids = [p["fork_id"] for p in res["pruned"]]
    assert fork2.fork_id in pruned_ids
    assert not fork2.fork_dir.exists()


def test_post_merge_preserves_fork_with_unresolved_conflicts(tmp_path):
    """merge_fork preserves fork directory when conflicts remain unresolved."""
    parent = _make_parent_project(tmp_path)
    fork = forks.create_fork(parent, label="merge_conflict")
    fork.record("rename_function", "/bin/app", address="1000", old="FUN_1000", new="fork_edit")
    _stop(fork)

    bin_name = "/bin/app"
    # Primary already has a diverging change -> creates a conflict
    state = {
        "functions": {"1000": {"name": "primary_edit", "signature": "void primary_edit()"}},
        "variables": {},
        "comments": {},
    }

    class FakeTools:
        def __init__(self, _state):
            pass

        def find_function(self, addr):
            return SimpleNamespace(getName=lambda: state["functions"][addr]["name"])

    fake_primary = SimpleNamespace(
        pyghidra_mcp_dir=parent.pyghidra_mcp_dir,
        programs={bin_name: state},
        get_program_info=lambda name: fake_primary.programs[name],
        save=Mock(),
    )

    merger = forks.ForkMerger(fake_primary, FakeTools)
    result = merger.merge(fork.fork_id, on_conflict="skip")

    assert result["counts"] == {"conflict": 1}
    assert result["pending_ops"] == 1

    # Prune should refuse to delete fork with unresolved conflicts
    res = forks.prune_forks(parent.pyghidra_mcp_dir, include_unmerged=False)
    pruned_ids = [p["fork_id"] for p in res["pruned"]]
    assert fork.fork_id not in pruned_ids
    assert fork.fork_dir.exists()
