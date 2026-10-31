"""Unit tests for Chroma index isolation and read-only parent collection querying in forks."""

from pathlib import Path

from pyghidra_mcp.forks import create_fork
from pyghidra_mcp.indexing_mixin import COLLECTION_COMPLETE_KEY, IndexingMixin
from pyghidra_mcp.project_spec import ProjectSpec


class _ProbeIndexer(IndexingMixin):
    def __init__(self, local_dir: Path, parent_dir: Path | None = None):
        self.programs = {}
        self._init_indexing_state(
            local_dir,
            threaded=False,
            parent_pyghidra_mcp_dir=parent_dir,
        )


def _make_spec(root: Path, name: str = "app") -> ProjectSpec:
    proj_dir = root / name
    proj_dir.mkdir(parents=True, exist_ok=True)
    rep_dir = proj_dir / f"{name}.rep"
    rep_dir.mkdir(parents=True, exist_ok=True)
    (rep_dir / "project.prp").write_text("<props/>")
    gpr = proj_dir / f"{name}.gpr"
    gpr.write_text("gpr")
    mcp_dir = proj_dir / f"{name}-superghidra-mcp"
    mcp_dir.mkdir(parents=True, exist_ok=True)
    return ProjectSpec(
        project_directory=proj_dir,
        project_name=name,
        gpr_path=gpr,
        pyghidra_mcp_dir=mcp_dir,
        was_gpr_path=False,
    )


def test_fork_reads_complete_parent_collection_without_modifying_parent(tmp_path):
    parent_spec = _make_spec(tmp_path, "main_app")
    parent_chroma = parent_spec.pyghidra_mcp_dir / "chromadb"
    parent_chroma.mkdir(parents=True, exist_ok=True)

    # Primary populates and marks complete
    primary_indexer = _ProbeIndexer(parent_spec.pyghidra_mcp_dir)
    p_col = primary_indexer.chroma_client.create_collection(
        name="bin_one",
        metadata={COLLECTION_COMPLETE_KEY: True, "function_count": 2},
    )
    p_col.add(ids=["fn1", "fn2"], documents=["int fn1() {}", "int fn2() {}"])

    # Create a fork
    fork_session = create_fork(parent_spec, label="worker")
    fork_spec = fork_session.project_spec

    # Fork indexer has its own local dir, parent dir points to parent
    fork_indexer = _ProbeIndexer(
        fork_spec.pyghidra_mcp_dir,
        parent_dir=fork_session.parent_pyghidra_mcp_dir,
    )

    # Fork queries collection: it should find it in parent
    col = fork_indexer._open_complete_collection("bin_one")
    assert col is not None
    assert col.count() == 2

    # Fork imports a new binary and indexes it locally
    fork_col = fork_indexer.chroma_client.create_collection(
        name="bin_fork_only",
        metadata={COLLECTION_COMPLETE_KEY: True},
    )
    fork_col.add(ids=["fork_fn"], documents=["void fork_fn() {}"])

    # Verify primary collections are completely untouched
    primary_cols = [c.name for c in primary_indexer.chroma_client.list_collections()]
    assert "bin_one" in primary_cols
    assert "bin_fork_only" not in primary_cols, "Fork collection must not leak into primary!"


def test_fork_does_not_delete_incomplete_parent_collection(tmp_path):
    parent_spec = _make_spec(tmp_path, "main_app")
    parent_chroma = parent_spec.pyghidra_mcp_dir / "chromadb"
    parent_chroma.mkdir(parents=True, exist_ok=True)

    # Primary has an incomplete collection (e.g. index in progress)
    primary_indexer = _ProbeIndexer(parent_spec.pyghidra_mcp_dir)
    primary_indexer.chroma_client.create_collection(
        name="bin_in_progress",
        metadata={COLLECTION_COMPLETE_KEY: False},
    )

    # Fork starts up
    fork_session = create_fork(parent_spec, label="worker2")
    fork_indexer = _ProbeIndexer(
        fork_session.project_spec.pyghidra_mcp_dir,
        parent_dir=fork_session.parent_pyghidra_mcp_dir,
    )

    # Fork opens collection: it is incomplete in parent, so returns None
    assert fork_indexer._open_complete_collection("bin_in_progress") is None

    # CRITICAL: Verify the collection was NOT deleted from the parent!
    primary_cols = [c.name for c in primary_indexer.chroma_client.list_collections()]
    assert "bin_in_progress" in primary_cols, "Parent collection must never be deleted by fork!"


def test_fork_writes_stay_in_fork_state_dir(tmp_path):
    parent_spec = _make_spec(tmp_path, "main_app")
    fork_session = create_fork(parent_spec, label="worker3")

    fork_chroma = fork_session.project_spec.pyghidra_mcp_dir / "chromadb"
    fork_chroma.mkdir(parents=True, exist_ok=True)
    test_file = fork_chroma / "local_file.txt"
    test_file.write_text("fork data")

    parent_chroma = parent_spec.pyghidra_mcp_dir / "chromadb"
    assert not (parent_chroma / "local_file.txt").exists()


def test_parent_chroma_client_raises_permission_error_on_mutation(tmp_path):
    import pytest

    parent_spec = _make_spec(tmp_path, "main_app_ro")
    parent_chroma = parent_spec.pyghidra_mcp_dir / "chromadb"
    parent_chroma.mkdir(parents=True, exist_ok=True)

    primary_indexer = _ProbeIndexer(parent_spec.pyghidra_mcp_dir)
    primary_indexer.chroma_client.create_collection(
        name="bin_ro",
        metadata={COLLECTION_COMPLETE_KEY: True},
    )

    fork_session = create_fork(parent_spec, label="worker_ro")
    fork_indexer = _ProbeIndexer(
        fork_session.project_spec.pyghidra_mcp_dir,
        parent_dir=fork_session.parent_pyghidra_mcp_dir,
    )

    # 1. Client mutations raise PermissionError
    with pytest.raises(PermissionError, match=r"read-only"):
        fork_indexer.parent_chroma_client.create_collection("illegal")

    with pytest.raises(PermissionError, match=r"read-only"):
        fork_indexer.parent_chroma_client.delete_collection("bin_ro")

    # 2. Collection mutations raise PermissionError
    col = fork_indexer.parent_chroma_client.get_collection("bin_ro")
    with pytest.raises(PermissionError, match=r"read-only"):
        col.add(ids=["illegal"], documents=["dummy"])

    with pytest.raises(PermissionError, match=r"read-only"):
        col.delete(ids=["illegal"])

    # 3. Primary indexer in same process continues to write normally without PermissionError
    primary_col = primary_indexer.chroma_client.get_collection("bin_ro")
    primary_col.add(ids=["primary_new_fn"], documents=["int primary_fn() {}"])
    assert primary_col.count() == 1
