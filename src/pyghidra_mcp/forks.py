"""
Multi-agent project sharing through project forks.

Ghidra lets only one process open a project for update; a second process gets a
``LockException``. Instead of failing, a server that finds its project locked can
clone it into a *fork* and work there. Every edit made on the fork is appended to
a journal, and the session that owns the main project (the *primary*) later
replays that journal with ``merge_fork``.

On-disk layout, inside the main project's pyghidra-mcp directory::

    <name>-superghidra-mcp/forks/<fork_id>/
        <name>.gpr, <name>.rep/     cloned Ghidra project (same program paths)
        <name>-superghidra-mcp/     the fork's own Chroma index and GZFs
        fork.json                   written by the fork process only
        journal.jsonl               append-only edit log, written by the fork only
        merge_state.json            written by the merging (primary) process only

Each file has exactly one writing process, so no cross-process locking is needed.
Journal entries carry the value before and after each edit, which lets a merge
tell "not yet applied" apart from "changed independently on the primary" (a
conflict) without diffing program databases.
"""

import json
import logging
import os
import re
import shutil
import socket
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pyghidra_mcp.project_spec import ProjectSpec

logger = logging.getLogger(__name__)

FORKS_DIRNAME = "forks"
FORK_META_FILE = "fork.json"
JOURNAL_FILE = "journal.jsonl"
MERGE_STATE_FILE = "merge_state.json"

# Ghidra's project lock lives beside the .gpr marker; never clone a held lock.
_LOCK_FILE_SUFFIXES = (".lock", ".lock~", ".ulock")

# Merge outcomes that are final: the entry is not replayed by later merges.
RESOLVED_STATUSES = frozenset(
    {
        "applied",
        "already_applied",
        "overwritten",
        "queued",
        "ignored",
        "discarded",
        "resolved_both",
        "combined",
        "resolved_by_evidence",
    }
)

_merge_lock = threading.Lock()


def _epistemic_rank(
    provenance: str | None = None,
    epistemic_status: str | None = None,
    symbol_name: str | None = None,
) -> int:
    """Returns numerical rank (0-4) for epistemic evidence strength:
    4: smt_proven, imported (DWARF/PDB/FLIRT), or observed bytes
    3: user_defined (committed overlay or human annotation)
    2: analysis / inferred with verified obligation
    1: analysis / inferred heuristic
    0: default / unknown / auto-generated compiler names (FUN_*, local_*, DAT_*)
    """
    if provenance:
        p = str(provenance).lower()
        if any(k in p for k in ("smt_proven", "imported", "dwarf", "pdb")):
            return 4
        if "user_defined" in p or "human" in p:
            return 3
        if "verified" in p:
            return 2
        if "analysis" in p or "inferred" in p:
            return 1
        if "default" in p or "unknown" in p:
            return 0

    if epistemic_status:
        s = str(epistemic_status).lower()
        if "observed" in s:
            return 4
        if "inferred" in s:
            return 1
        if "unknown" in s:
            return 0

    if symbol_name:
        import re

        if re.match(r"^(FUN_[0-9a-fA-F]+|local_[0-9a-fA-F]+|uVar\d+|DAT_[0-9a-fA-F]+|param_\d+)$", symbol_name):
            return 0
        return 1

    return 0


class ProjectLockedError(RuntimeError):
    """Another process holds the Ghidra project lock."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """Write atomically; retry briefly because Windows refuses to replace open files."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    for attempt in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


def pid_alive(pid: int | None) -> bool:
    """Return True if a process with ``pid`` exists on this host."""
    if not pid or pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if sys.platform == "win32":
        # os.kill(pid, 0) would *terminate* the process on Windows.
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        process_query_limited_information = 0x1000
        still_active = 259

        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            # On Windows, error_access_denied occurs for SYSTEM/privileged services (e.g. svchost)
            # whose PIDs were recycled after a user-level Python process terminated.
            # PyGhidra processes run as the current user, so query limited info never denies access.
            return False
        try:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            if exit_code.value != still_active:
                return False
            # Verify the process is actually python, java, or a pyghidra/superghidra runner
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(len(buf))
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                exe_name = Path(buf.value).name.lower()
                allowed_prefixes = ("python", "pyghidra", "superghidra", "java", "javaw", "pytest")
                if not any(exe_name.startswith(p) for p in allowed_prefixes):
                    return False
            return True
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def read_journal(fork_dir: Path) -> list[dict[str, Any]]:
    """Read complete journal entries; a torn trailing line is still being written."""
    path = fork_dir / JOURNAL_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    entries = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get("seq"), int):
            entries.append(entry)
    return entries


def load_merge_state(fork_dir: Path) -> dict[str, Any]:
    state = _read_json(fork_dir / MERGE_STATE_FILE)
    state.setdefault("resolved", {})
    state.setdefault("merges", [])
    state.setdefault("conflicts", {})
    return state


def save_merge_state(fork_dir: Path, state: dict[str, Any]) -> None:
    state.setdefault("conflicts", {})
    _write_json(fork_dir / MERGE_STATE_FILE, state)


def _default_runner(fn: Callable[[], Any]) -> Any:
    return fn()


def _null_tools_factory(p: Any) -> Any:
    return None


def forks_root(pyghidra_mcp_dir: Path) -> Path:
    return Path(pyghidra_mcp_dir) / FORKS_DIRNAME


def _sanitize_label(label: str | None) -> str | None:
    if not label:
        return None
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", label).strip("._-")[:32]
    return cleaned or None


@dataclass
class ForkSession:
    """The journaling side of a fork, owned by the process working on it."""

    fork_id: str
    fork_dir: Path
    project_name: str
    parent_project: Path
    label: str | None = None
    seed_index: bool = True
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _next_seq: int = field(default=1, repr=False)

    @property
    def project_spec(self) -> ProjectSpec:
        legacy = self.fork_dir / f"{self.project_name}-pyghidra-mcp"
        canonical = self.fork_dir / f"{self.project_name}-superghidra-mcp"
        state_dir = legacy if legacy.exists() and not canonical.exists() else canonical
        return ProjectSpec(
            project_directory=self.fork_dir,
            project_name=self.project_name,
            gpr_path=self.fork_dir / f"{self.project_name}.gpr",
            pyghidra_mcp_dir=state_dir,
            was_gpr_path=False,
        )

    @property
    def parent_pyghidra_mcp_dir(self) -> Path:
        return self.fork_dir.parent.parent

    @property
    def op_count(self) -> int:
        return self._next_seq - 1

    @classmethod
    def load(cls, fork_dir: Path) -> "ForkSession":
        meta = _read_json(fork_dir / FORK_META_FILE)
        if not meta:
            raise ValueError(f"Not a pyghidra-mcp fork: {fork_dir}")
        session = cls(
            fork_id=meta["fork_id"],
            fork_dir=fork_dir,
            project_name=meta["project_name"],
            parent_project=Path(meta["parent_project"]),
            label=meta.get("label"),
            seed_index=meta.get("seed_index", True),
        )
        journal = read_journal(fork_dir)
        session._next_seq = max((e["seq"] for e in journal), default=0) + 1
        return session

    def record(self, op: str, binary: str, **fields: Any) -> dict[str, Any]:
        """Append one edit to the journal and flush it to disk before returning."""
        with self._lock:
            entry = {"seq": self._next_seq, "ts": time.time(), "op": op, "binary": binary}
            entry.update(fields)
            with open(self.fork_dir / JOURNAL_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._next_seq += 1
        return entry

    def mark(self, status: str) -> None:
        meta = _read_json(self.fork_dir / FORK_META_FILE)
        meta["status"] = status
        meta["pid"] = os.getpid()
        meta["host"] = socket.gethostname()
        meta[f"{status}_at"] = _now_iso()
        _write_json(self.fork_dir / FORK_META_FILE, meta)

    def sync(self) -> dict[str, Any]:
        return sync_fork(self.parent_pyghidra_mcp_dir, self.fork_id)


def _ignore_lock_files(_directory: str, names: list[str]) -> list[str]:
    return [name for name in names if name.endswith(_LOCK_FILE_SUFFIXES)]


def get_fork_disk_usage_bytes(fork_dir: Path) -> int:
    """Calculate total disk usage of a fork directory in bytes, ignoring shared links/junctions."""
    size_bytes = 0
    try:
        for p in fork_dir.rglob("*"):
            try:
                # Do not count files inside shared symlinks or directory junctions
                is_linked = any(
                    part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction())
                    for part in p.parents
                    if part != fork_dir
                )
                if is_linked or p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()):
                    continue
                if p.is_file():
                    size_bytes += p.stat().st_size
            except OSError:
                pass
    except OSError:
        pass
    return size_bytes


def _reflink_copy(src: str, dst: str, *, follow_symlinks: bool = True) -> None:
    """Copy a file using copy-on-write (reflink/clonefile) where supported, falling back to copy2."""
    if hasattr(os, "clonefile"):
        try:
            # os.clonefile is available on macOS 10.12+ (APFS)
            os.clonefile(src, dst)
            return
        except OSError:
            pass

    # On Linux, try FICLONE ioctl if supported (Btrfs, XFS)
    try:
        import fcntl

        if hasattr(os, "O_RDONLY") and hasattr(os, "O_WRONLY") and hasattr(fcntl, "ioctl"):
            ficlone_req = 0x40049409
            src_fd = os.open(src, os.O_RDONLY)
            try:
                dst_fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
                try:
                    fcntl.ioctl(dst_fd, ficlone_req, src_fd)
                    shutil.copystat(src, dst, follow_symlinks=follow_symlinks)
                    return
                finally:
                    os.close(dst_fd)
            finally:
                os.close(src_fd)
    except Exception:
        pass

    shutil.copy2(src, dst, follow_symlinks=follow_symlinks)


def create_fork(
    parent: ProjectSpec,
    label: str | None = None,
    *,
    seed_index: bool = True,
    max_forks: int = 4,
    max_fork_disk_mb: int = 2048,
) -> ForkSession:
    """Clone the parent project's last saved state into a new fork directory.

    Enforces fork count and disk usage quotas before cloning.
    Programs the lock holder has modified but not saved are not part of the
    clone. Merges compare against the primary's *current* values, so that
    staleness shows up as conflicts rather than silent overwrites.
    """
    # Enforce fork quotas
    existing = list_forks(parent.pyghidra_mcp_dir)
    total_bytes = sum(get_fork_disk_usage_bytes(Path(f["path"])) for f in existing)
    total_mb = total_bytes / (1024 * 1024)

    # Estimate new fork size based on project .rep storage (Chroma index is shared read-only)
    rep_dir = Path(parent.project_directory) / f"{parent.project_name}.rep"
    est_new_fork_bytes = get_fork_disk_usage_bytes(rep_dir) if rep_dir.is_dir() else 0
    est_total_mb = (total_bytes + est_new_fork_bytes) / (1024 * 1024)

    if len(existing) >= max_forks or est_total_mb >= max_fork_disk_mb:
        prune_forks(parent.pyghidra_mcp_dir, dry_run=False)
        existing = list_forks(parent.pyghidra_mcp_dir)
        total_bytes = sum(get_fork_disk_usage_bytes(Path(f["path"])) for f in existing)
        total_mb = total_bytes / (1024 * 1024)
        est_total_mb = (total_bytes + est_new_fork_bytes) / (1024 * 1024)

    while len(existing) >= max_forks or est_total_mb >= max_fork_disk_mb:
        # Only discard dead forks that have NO pending or unmerged edits
        reclaimable_dead = [
            f
            for f in existing
            if f.get("alive") is False and f.get("pending_ops", 0) == 0 and f.get("unmerged_ops", 0) == 0
        ]
        if not reclaimable_dead:
            break
        oldest_dead = min(reclaimable_dead, key=lambda f: f.get("created_at", ""))
        logger.warning(
            "Fork quota exceeded (%d forks, %.1f MB >= limit %d forks, %d MB). Discarding oldest clean dead fork %s.",
            len(existing),
            total_mb,
            max_forks,
            max_fork_disk_mb,
            oldest_dead["fork_id"],
        )
        discard_fork(parent.pyghidra_mcp_dir, oldest_dead["fork_id"])
        existing = list_forks(parent.pyghidra_mcp_dir)
        total_bytes = sum(get_fork_disk_usage_bytes(Path(f["path"])) for f in existing)
        total_mb = total_bytes / (1024 * 1024)
        est_total_mb = (total_bytes + est_new_fork_bytes) / (1024 * 1024)

    if len(existing) >= max_forks or est_total_mb >= max_fork_disk_mb:
        raise RuntimeError(
            f"Fork quota exceeded: {len(existing)} active fork(s) consuming {total_mb:.1f} MB "
            f"exceed configured limits (max_forks={max_forks}, max_fork_disk_mb={max_fork_disk_mb} MB). "
            "No stopped or dead forks available to reclaim."
        )

    label = _sanitize_label(label)
    fork_id = "-".join(part for part in (time.strftime("%Y%m%d-%H%M%S"), label, uuid.uuid4().hex[:6]) if part)
    fork_dir = forks_root(parent.pyghidra_mcp_dir) / fork_id
    fork_dir.mkdir(parents=True)
    name = parent.project_name

    started = time.monotonic()
    try:
        shutil.copy2(parent.gpr_path, fork_dir / f"{name}.gpr")
        shutil.copytree(
            parent.project_directory / f"{name}.rep",
            fork_dir / f"{name}.rep",
            ignore=_ignore_lock_files,
            copy_function=_reflink_copy,
        )
    except Exception:
        shutil.rmtree(fork_dir, ignore_errors=True)
        raise

    legacy_parent = (
        parent.pyghidra_mcp_dir.name.endswith("-pyghidra-mcp") or parent.pyghidra_mcp_dir.name == "pyghidra-mcp"
    )
    suffix = "-pyghidra-mcp" if legacy_parent else "-superghidra-mcp"
    state_dir = fork_dir / f"{name}{suffix}"
    state_dir.mkdir()
    # Note on Chroma indexing:
    # We deliberately DO NOT create a directory junction or symlink here because
    # OS-level symlinks/junctions forward write operations directly to the primary index.
    # Instead, IndexingMixin provides read-only parent collection querying
    # via parent_chroma_client, while any new collections or binary additions
    # in this fork are isolated in the fork's own local state_dir / "chromadb".

    actual_fork_bytes = get_fork_disk_usage_bytes(fork_dir)
    actual_total_mb = (total_bytes + actual_fork_bytes) / (1024 * 1024)
    if actual_total_mb > max_fork_disk_mb:
        shutil.rmtree(fork_dir, ignore_errors=True)
        raise RuntimeError(
            f"Fork quota exceeded after creation: total storage {actual_total_mb:.1f} MB "
            f"exceeds limit {max_fork_disk_mb} MB. Fork {fork_id} was removed."
        )

    _write_json(
        fork_dir / FORK_META_FILE,
        {
            "fork_id": fork_id,
            "label": label,
            "project_name": name,
            "parent_project": str(parent.gpr_path.absolute()),
            "created_at": _now_iso(),
            "status": "active",
            "pid": os.getpid(),
            "host": socket.gethostname(),
        },
    )
    logger.info("Created fork %s of %s in %.1fs.", fork_id, name, time.monotonic() - started)
    return ForkSession(
        fork_id=fork_id,
        fork_dir=fork_dir,
        project_name=name,
        parent_project=parent.gpr_path.absolute(),
        label=label,
        seed_index=seed_index,
    )


def find_reusable_fork(parent: ProjectSpec, label: str | None = None) -> ForkSession | None:
    """Return a stopped fork that can be reused:
    1. First, the newest stopped fork matching ``label`` that has unmerged edits (pending_ops > 0).
    2. Otherwise, the newest clean stopped fork (pending_ops == 0 and alive is False).
    """
    cleaned_label = _sanitize_label(label)
    all_forks = list_forks(parent.pyghidra_mcp_dir)
    stopped = [info for info in all_forks if info.get("alive") is False]

    # 1. First priority: stopped fork matching label with pending edits
    if cleaned_label:
        pending_candidates = [
            info for info in stopped if info.get("label") == cleaned_label and info.get("pending_ops", 0) > 0
        ]
        if pending_candidates:
            newest = max(pending_candidates, key=lambda info: info.get("created_at", ""))
            return ForkSession.load(Path(newest["path"]))

    # 2. Second priority: clean stopped fork (pending_ops == 0 and alive is False)
    clean_candidates = [info for info in stopped if info.get("pending_ops", 0) == 0]
    if clean_candidates:
        if cleaned_label:
            same_label = [info for info in clean_candidates if info.get("label") == cleaned_label]
            if same_label:
                newest = max(same_label, key=lambda info: info.get("created_at", ""))
                return ForkSession.load(Path(newest["path"]))
            unlabeled = [info for info in clean_candidates if not info.get("label")]
            if unlabeled:
                newest = max(unlabeled, key=lambda info: info.get("created_at", ""))
                session = ForkSession.load(Path(newest["path"]))
                session.label = cleaned_label
                return session
        else:
            unlabeled = [info for info in clean_candidates if not info.get("label")]
            if unlabeled:
                newest = max(unlabeled, key=lambda info: info.get("created_at", ""))
                return ForkSession.load(Path(newest["path"]))

    return None


def describe_fork(fork_dir: Path) -> dict[str, Any] | None:
    meta = _read_json(fork_dir / FORK_META_FILE)
    if not meta.get("fork_id"):
        return None
    journal = read_journal(fork_dir)
    merge_state = load_merge_state(fork_dir)
    resolved = merge_state["resolved"]
    resolved_count = sum(1 for entry in journal if str(entry["seq"]) in resolved)

    status = meta.get("status", "active")
    alive: bool | None
    if status == "closed":
        alive = False
    elif meta.get("host") == socket.gethostname():
        alive = pid_alive(meta.get("pid"))
    else:
        alive = None  # cannot check a process on another host

    return {
        "fork_id": meta["fork_id"],
        "label": meta.get("label"),
        "status": status,
        "alive": alive,
        "pid": meta.get("pid"),
        "created_at": meta.get("created_at", ""),
        "journal_ops": len(journal),
        "resolved_ops": resolved_count,
        "pending_ops": len(journal) - resolved_count,
        "conflicts": list(merge_state.get("conflicts", {}).values()),
        "path": str(fork_dir),
    }


def list_forks(pyghidra_mcp_dir: Path) -> list[dict[str, Any]]:
    root = forks_root(pyghidra_mcp_dir)
    if not root.is_dir():
        return []
    forks = [describe_fork(child) for child in sorted(root.iterdir()) if child.is_dir()]
    return [info for info in forks if info is not None]


def resolve_fork_dir(pyghidra_mcp_dir: Path, fork_id: str) -> Path:
    root = forks_root(pyghidra_mcp_dir)
    fork_dir = root / fork_id
    # fork_id comes from a client; refuse anything that escapes the forks root.
    if fork_dir.resolve().parent != root.resolve() or not (fork_dir / FORK_META_FILE).is_file():
        known = [info["fork_id"] for info in list_forks(pyghidra_mcp_dir)]
        raise ValueError(f"Fork '{fork_id}' not found. Known forks: {known}")
    return fork_dir


def discard_fork(pyghidra_mcp_dir: Path, fork_id: str) -> dict[str, Any]:
    fork_dir = resolve_fork_dir(pyghidra_mcp_dir, fork_id)
    info = describe_fork(fork_dir) or {}
    if info.get("alive") is not False:
        raise ValueError(
            f"Fork '{fork_id}' may still be in use (pid {info.get('pid')}). "
            "Stop the server working on it before discarding."
        )
    shutil.rmtree(fork_dir)
    return info


def prune_forks(
    pyghidra_mcp_dir: Path,
    *,
    dry_run: bool = False,
    max_age_hours: float = 168.0,
    include_unmerged: bool = False,
) -> dict[str, Any]:
    """Automated fork garbage collection to reclaim storage:
    1. Prunes dead, fully-merged forks (pending_ops == 0 and alive == False).
    2. Prunes dead abandoned forks (alive == False) older than max_age_hours if include_unmerged=True.
    Never deletes an active/live fork process.
    """
    root = forks_root(pyghidra_mcp_dir)
    if not root.is_dir():
        return {"scanned": 0, "pruned": [], "bytes_reclaimed": 0, "dry_run": dry_run}

    all_forks = list_forks(pyghidra_mcp_dir)
    now = datetime.now(timezone.utc)
    pruned_summary = []
    total_bytes = 0

    for f_info in all_forks:
        fid = f_info["fork_id"]
        if f_info.get("alive") is not False:
            continue

        pending = f_info.get("pending_ops", 0)
        fork_path = Path(f_info["path"])

        should_prune = False
        reason = ""

        if pending == 0:
            should_prune = True
            reason = "fully_merged_and_dead"
        elif include_unmerged:
            created_str = f_info.get("created_at")
            if created_str:
                try:
                    created_dt = datetime.fromisoformat(created_str)
                    age_hours = (now - created_dt).total_seconds() / 3600.0
                    if age_hours >= max_age_hours:
                        should_prune = True
                        reason = f"expired_stale_unmerged ({age_hours:.1f}h >= {max_age_hours:.1f}h)"
                except Exception:
                    pass

        if should_prune:
            size_bytes = 0
            try:
                for p in fork_path.rglob("*"):
                    if p.is_file():
                        size_bytes += p.stat().st_size
            except OSError:
                pass

            if not dry_run:
                shutil.rmtree(fork_path, ignore_errors=True)

            total_bytes += size_bytes
            pruned_summary.append(
                {
                    "fork_id": fid,
                    "reason": reason,
                    "reclaimed_bytes": size_bytes,
                    "path": str(fork_path),
                }
            )

    return {
        "scanned": len(all_forks),
        "pruned": pruned_summary,
        "bytes_reclaimed": total_bytes,
        "dry_run": dry_run,
    }


# Merge
# ---------------------------------------------------------------------------------


def _same(a: Any, b: Any) -> bool:
    # Ghidra reports a missing comment as None; a journal may hold "" for it.
    return (a or None) == (b or None)


@dataclass
class _Outcome:
    status: str
    target: str
    detail: str | None = None
    primary_value: Any = None


def _reconcile(
    *,
    target: str,
    current: Any,
    old: Any,
    new: Any,
    apply: Callable[[], Any],
    dry_run: bool,
    on_conflict: str,
    op: dict[str, Any] | None = None,
    decide_with_evidence: bool = False,
) -> _Outcome:
    """Three-way decision for one edit: fork base (old), fork result (new), primary now."""
    if _same(current, new):
        return _Outcome("already_applied", target, primary_value=current)
    if _same(current, old):
        if dry_run:
            return _Outcome("would_apply", target, f"{old!r} -> {new!r}", primary_value=current)
        apply()
        return _Outcome("applied", target, f"{old!r} -> {new!r}", primary_value=current)
    detail = f"primary has {current!r}; fork changed {old!r} -> {new!r}"

    if on_conflict == "evidence" or decide_with_evidence:
        fork_prov = op.get("provenance") if op else None
        fork_status = op.get("epistemic_status") if op else None
        fork_rank = _epistemic_rank(fork_prov, fork_status, symbol_name=str(new))

        prim_prov = op.get("primary_provenance") if op else None
        prim_status = op.get("primary_epistemic_status") if op else None
        prim_rank = _epistemic_rank(prim_prov, prim_status, symbol_name=str(current))

        if fork_rank > prim_rank:
            if dry_run:
                return _Outcome(
                    "would_apply",
                    target,
                    f"{detail} (evidence won: fork rank {fork_rank} > primary rank {prim_rank})",
                    primary_value=current,
                )
            apply()
            return _Outcome(
                "resolved_by_evidence",
                target,
                f"{detail} (evidence won: fork rank {fork_rank} > primary rank {prim_rank})",
                primary_value=current,
            )
        elif prim_rank > fork_rank:
            return _Outcome(
                "discarded",
                target,
                f"{detail} (evidence held: primary rank {prim_rank} > fork rank {fork_rank})",
                primary_value=current,
            )

    if on_conflict == "overwrite":
        if dry_run:
            return _Outcome("would_overwrite", target, detail, primary_value=current)
        apply()
        return _Outcome("overwritten", target, detail, primary_value=current)
    return _Outcome("conflict", target, detail, primary_value=current)


def _merge_rename_function(
    tools: Any,
    op: dict[str, Any],
    dry_run: bool,
    on_conflict: str,
    *,
    preserve_alias: bool = False,
    fork_id: str = "",
    **_kwargs: Any,
) -> _Outcome:
    func = tools.find_function(op["address"])
    current = str(func.getName())
    target = f"function @ {op['address']}"
    old = op["old"]
    new = op["new"]

    if _same(current, new):
        return _Outcome("already_applied", target, primary_value=current)
    if _same(current, old):
        if dry_run:
            return _Outcome("would_apply", target, f"{old!r} -> {new!r}", primary_value=current)
        tools.rename_function(op["address"], new)
        return _Outcome("applied", target, f"{old!r} -> {new!r}", primary_value=current)

    detail = f"primary has {current!r}; fork changed {old!r} -> {new!r}"

    if on_conflict == "evidence" or _kwargs.get("decide_with_evidence"):
        fork_prov = op.get("provenance")
        fork_status = op.get("epistemic_status")
        fork_rank = _epistemic_rank(fork_prov, fork_status, symbol_name=new)

        prim_prov = op.get("primary_provenance")
        prim_status = op.get("primary_epistemic_status")
        prim_rank = _epistemic_rank(prim_prov, prim_status, symbol_name=current)

        if fork_rank > prim_rank:
            if preserve_alias and current:
                alias_str = f"[Alternative name]: {current}"
                existing = tools.get_comment(op["address"], "plate")
                combined_plate = f"{existing}\n\n{alias_str}" if existing else alias_str
                if not dry_run:
                    tools.set_comment(op["address"], combined_plate, "plate")
            if dry_run:
                return _Outcome(
                    "would_apply",
                    target,
                    f"{detail} (evidence won: fork rank {fork_rank} > primary rank {prim_rank})",
                    primary_value=current,
                )
            tools.rename_function(op["address"], new)
            return _Outcome(
                "resolved_by_evidence",
                target,
                f"{detail} (evidence won: fork rank {fork_rank} > primary rank {prim_rank})",
                primary_value=current,
            )
        elif prim_rank > fork_rank:
            if preserve_alias and new:
                alias_str = (
                    f"[Alternative name from fork {fork_id}]: {new}" if fork_id else f"[Alternative name]: {new}"
                )
                existing = tools.get_comment(op["address"], "plate")
                combined_plate = f"{existing}\n\n{alias_str}" if existing else alias_str
                if not dry_run:
                    tools.set_comment(op["address"], combined_plate, "plate")
            return _Outcome(
                "discarded",
                target,
                f"{detail} (evidence held: primary rank {prim_rank} > fork rank {fork_rank})",
                primary_value=current,
            )

    if preserve_alias:
        losing_name = current if on_conflict == "overwrite" else new
        if losing_name:
            alias_str = (
                f"[Alternative name from fork {fork_id}]: {losing_name}"
                if (losing_name == new and fork_id)
                else f"[Alternative name]: {losing_name}"
            )
            existing = tools.get_comment(op["address"], "plate")
            combined_plate = f"{existing}\n\n{alias_str}" if existing else alias_str
            if not dry_run:
                tools.set_comment(op["address"], combined_plate, "plate")
            detail += f" (preserved alias {losing_name!r})"

    if on_conflict == "overwrite":
        if dry_run:
            return _Outcome("would_overwrite", target, detail, primary_value=current)
        tools.rename_function(op["address"], new)
        return _Outcome("overwritten", target, detail, primary_value=current)

    return _Outcome("conflict", target, detail, primary_value=current)


def _merge_rename_variable(
    tools: Any,
    op: dict[str, Any],
    dry_run: bool,
    on_conflict: str,
    *,
    preserve_alias: bool = False,
    fork_id: str = "",
    **_kwargs: Any,
) -> _Outcome:
    _func, _kind, variable = tools.find_variable(
        op["function_address"], storage=op.get("storage"), names=(op["old"], op["new"])
    )
    current = str(variable.getName())
    target = f"variable {op.get('storage') or op['old']} in {op['function_address']}"
    old = op["old"]
    new = op["new"]

    if _same(current, new):
        return _Outcome("already_applied", target, primary_value=current)
    if _same(current, old):
        if dry_run:
            return _Outcome("would_apply", target, f"{old!r} -> {new!r}", primary_value=current)
        tools.rename_variable(op["function_address"], current, new)
        return _Outcome("applied", target, f"{old!r} -> {new!r}", primary_value=current)

    detail = f"primary has {current!r}; fork changed {old!r} -> {new!r}"

    if on_conflict == "evidence" or _kwargs.get("decide_with_evidence"):
        fork_prov = op.get("provenance")
        fork_status = op.get("epistemic_status")
        fork_rank = _epistemic_rank(fork_prov, fork_status, symbol_name=new)

        prim_prov = op.get("primary_provenance")
        prim_status = op.get("primary_epistemic_status")
        prim_rank = _epistemic_rank(prim_prov, prim_status, symbol_name=current)

        if fork_rank > prim_rank:
            if preserve_alias and current:
                alias_str = f"[Alternative variable name]: {current}"
                existing = tools.get_comment(op["function_address"], "plate")
                combined_plate = f"{existing}\n\n{alias_str}" if existing else alias_str
                if not dry_run:
                    tools.set_comment(op["function_address"], combined_plate, "plate")
            if dry_run:
                return _Outcome(
                    "would_apply",
                    target,
                    f"{detail} (evidence won: fork rank {fork_rank} > primary rank {prim_rank})",
                    primary_value=current,
                )
            tools.rename_variable(op["function_address"], current, new)
            return _Outcome(
                "resolved_by_evidence",
                target,
                f"{detail} (evidence won: fork rank {fork_rank} > primary rank {prim_rank})",
                primary_value=current,
            )
        elif prim_rank > fork_rank:
            if preserve_alias and new:
                alias_str = (
                    f"[Alternative variable name from fork {fork_id}]: {new}"
                    if fork_id
                    else f"[Alternative variable name]: {new}"
                )
                existing = tools.get_comment(op["function_address"], "plate")
                combined_plate = f"{existing}\n\n{alias_str}" if existing else alias_str
                if not dry_run:
                    tools.set_comment(op["function_address"], combined_plate, "plate")
            return _Outcome(
                "discarded",
                target,
                f"{detail} (evidence held: primary rank {prim_rank} > fork rank {fork_rank})",
                primary_value=current,
            )

    if preserve_alias:
        losing_name = current if on_conflict == "overwrite" else new
        if losing_name:
            alias_str = (
                f"[Alternative variable name from fork {fork_id}]: {losing_name}"
                if (losing_name == new and fork_id)
                else f"[Alternative variable name]: {losing_name}"
            )
            existing = tools.get_comment(op["function_address"], "plate")
            combined_plate = f"{existing}\n\n{alias_str}" if existing else alias_str
            if not dry_run:
                tools.set_comment(op["function_address"], combined_plate, "plate")
            detail += f" (preserved alias {losing_name!r})"

    if on_conflict == "overwrite":
        if dry_run:
            return _Outcome("would_overwrite", target, detail, primary_value=current)
        tools.rename_variable(op["function_address"], current, new)
        return _Outcome("overwritten", target, detail, primary_value=current)

    return _Outcome("conflict", target, detail, primary_value=current)


def _merge_set_variable_type(
    tools: Any, op: dict[str, Any], dry_run: bool, on_conflict: str, **_kwargs: Any
) -> _Outcome:
    _func, _kind, variable = tools.find_variable(
        op["function_address"], storage=op.get("storage"), names=(op["variable_name"],)
    )
    name = str(variable.getName())
    return _reconcile(
        target=f"type of {name} in {op['function_address']}",
        current=str(variable.getDataType().getDisplayName()),
        old=op["old"],
        new=op["new"],
        apply=lambda: tools.set_variable_type(op["function_address"], name, op["type_name"]),
        dry_run=dry_run,
        on_conflict=on_conflict,
    )


def _merge_set_function_prototype(
    tools: Any, op: dict[str, Any], dry_run: bool, on_conflict: str, **_kwargs: Any
) -> _Outcome:
    func = tools.find_function(op["address"])
    return _reconcile(
        target=f"prototype @ {op['address']}",
        current=str(func.getSignature()),
        old=op["old"],
        new=op["new"],
        apply=lambda: tools.set_function_prototype(op["address"], op["prototype"]),
        dry_run=dry_run,
        on_conflict=on_conflict,
    )


def _merge_set_comment(
    tools: Any,
    op: dict[str, Any],
    dry_run: bool,
    on_conflict: str,
    *,
    combine_comments: bool = False,
    fork_id: str = "",
    **_kwargs: Any,
) -> _Outcome:
    current = tools.get_comment(op["address"], op["comment_type"])
    target = f"{op['comment_type']} comment @ {op['address']}"
    old = op.get("old")
    new = op["new"]

    if _same(current, new):
        return _Outcome("already_applied", target, primary_value=current)
    if _same(current, old):
        if dry_run:
            return _Outcome("would_apply", target, f"{old!r} -> {new!r}", primary_value=current)
        tools.set_comment(op["address"], new, op["comment_type"])
        return _Outcome("applied", target, f"{old!r} -> {new!r}", primary_value=current)

    detail = f"primary has {current!r}; fork changed {old!r} -> {new!r}"

    if on_conflict == "overwrite":
        if dry_run:
            return _Outcome("would_overwrite", target, detail, primary_value=current)
        tools.set_comment(op["address"], new, op["comment_type"])
        return _Outcome("overwritten", target, detail, primary_value=current)

    if combine_comments or on_conflict == "combine":
        if current:
            combined = f"{current}\n\n[{fork_id}]: {new}" if fork_id else f"{current}\n\n{new}"
        else:
            combined = f"[{fork_id}]: {new}" if fork_id else new
        combine_detail = f"combined comments: {current!r} + {new!r}"
        if dry_run:
            return _Outcome("would_apply", target, combine_detail, primary_value=current)
        tools.set_comment(op["address"], combined, op["comment_type"])
        return _Outcome("applied", target, combine_detail, primary_value=current)

    return _Outcome("conflict", target, detail, primary_value=current)


_PROGRAM_EDIT_HANDLERS = {
    "rename_function": _merge_rename_function,
    "rename_variable": _merge_rename_variable,
    "set_variable_type": _merge_set_variable_type,
    "set_function_prototype": _merge_set_function_prototype,
    "set_comment": _merge_set_comment,
}


class ForkMerger:
    """Replays a fork's journal into the project owned by ``context``.

    ``run`` executes each Ghidra mutation; GUI mode passes a Swing-thread runner.
    """

    def __init__(
        self,
        context: Any,
        tools_factory: Callable[[Any], Any],
        run: Callable[[Callable[[], Any]], Any] = lambda fn: fn(),
    ):
        self.context = context
        self.tools_factory = tools_factory
        self.run = run

    def merge(
        self,
        fork_id: str,
        *,
        dry_run: bool = False,
        on_conflict: str = "skip",
        auto_discard: bool = True,
        combine_comments: bool = False,
        preserve_alias: bool = False,
        atomic_by_function: bool = False,
        decide_with_evidence: bool = False,
    ) -> dict[str, Any]:
        if on_conflict not in {"skip", "overwrite", "combine", "evidence"}:
            raise ValueError("on_conflict must be 'skip', 'overwrite', 'combine', or 'evidence'")

        fork_dir = resolve_fork_dir(self.context.pyghidra_mcp_dir, fork_id)
        with _merge_lock:
            state = load_merge_state(fork_dir)
            resolved: dict[str, str] = state["resolved"]
            conflicts: dict[str, dict[str, Any]] = state.setdefault("conflicts", {})
            journal = read_journal(fork_dir)
            entries = []

            # Gather pending operations
            pending_ops = [op for op in journal if str(op["seq"]) not in resolved]

            if atomic_by_function:
                # Group edits by canonical function address: op.get("address") or op.get("function_address")
                # Group key includes binary so separate binaries with identical addresses don't collide.
                groups: dict[Any, list[dict[str, Any]]] = {}
                for op in pending_ops:
                    fn_addr = op.get("function_address")
                    if not fn_addr and op.get("op") == "set_comment" and op.get("address"):
                        try:
                            binary = op.get("binary")
                            if binary and hasattr(self, "context") and hasattr(self.context, "get_program_info"):
                                pinfo = self.context.get_program_info(binary)
                                tools = self.tools_factory(pinfo)
                                func = None
                                target_addr = op["address"]
                                if hasattr(tools, "get_function_containing"):
                                    func = self.run(lambda t=tools, a=target_addr: t.get_function_containing(a))
                                elif hasattr(tools, "find_function"):
                                    func = self.run(lambda t=tools, a=target_addr: t.find_function(a))
                                if func is not None:
                                    if hasattr(func, "getEntryPoint"):
                                        fn_addr = str(func.getEntryPoint())
                                    elif isinstance(func, dict) and "address" in func:
                                        fn_addr = str(func["address"])
                                    else:
                                        ep = getattr(func, "entry_point", None)
                                        if ep is not None:
                                            fn_addr = str(ep)
                        except Exception:
                            pass
                    if not fn_addr:
                        fn_addr = op.get("address")
                    key = (op.get("binary", ""), fn_addr) if fn_addr is not None else f"__seq_{op['seq']}"
                    groups.setdefault(key, []).append(op)

                for _group_key, group_ops in groups.items():
                    has_conflict = False
                    test_outcomes: dict[int, _Outcome] = {}
                    if on_conflict != "overwrite":
                        for op in group_ops:
                            test_out = self._merge_one(
                                op,
                                dry_run=True,
                                on_conflict=on_conflict,
                                combine_comments=combine_comments,
                                preserve_alias=preserve_alias,
                                fork_id=fork_id,
                                decide_with_evidence=decide_with_evidence,
                            )
                            test_outcomes[op["seq"]] = test_out
                            if test_out.status == "conflict":
                                has_conflict = True

                    if has_conflict:
                        # Hold back all edits for that function in that merge pass so the function is never left
                        # in a half-updated inconsistent state.
                        fn_addr = group_ops[0].get("function_address") or group_ops[0].get("address") or ""
                        for op in group_ops:
                            test_out = test_outcomes[op["seq"]]
                            if test_out.status == "conflict":
                                entries.append(
                                    {
                                        "seq": op["seq"],
                                        "op": op["op"],
                                        "binary": op.get("binary", ""),
                                        "target": test_out.target,
                                        "status": "conflict",
                                        "detail": test_out.detail,
                                    }
                                )
                                if not dry_run:
                                    conflicts[str(op["seq"])] = {
                                        **op,
                                        "seq": op["seq"],
                                        "op": op["op"],
                                        "primary_value": test_out.primary_value,
                                        "fork_value": op.get("new"),
                                        "target": test_out.target,
                                        "created_at": _now_iso(),
                                    }
                            else:
                                entries.append(
                                    {
                                        "seq": op["seq"],
                                        "op": op["op"],
                                        "binary": op.get("binary", ""),
                                        "target": test_out.target,
                                        "status": "skipped",
                                        "detail": f"held back: conflict in function {fn_addr}",
                                    }
                                )
                    else:
                        for op in group_ops:
                            outcome = self._merge_one(
                                op,
                                dry_run=dry_run,
                                on_conflict=on_conflict,
                                combine_comments=combine_comments,
                                preserve_alias=preserve_alias,
                                fork_id=fork_id,
                                decide_with_evidence=decide_with_evidence,
                            )
                            entries.append(
                                {
                                    "seq": op["seq"],
                                    "op": op["op"],
                                    "binary": op.get("binary", ""),
                                    "target": outcome.target,
                                    "status": outcome.status,
                                    "detail": outcome.detail,
                                }
                            )
                            if not dry_run:
                                if outcome.status == "conflict":
                                    conflicts[str(op["seq"])] = {
                                        **op,
                                        "seq": op["seq"],
                                        "op": op["op"],
                                        "primary_value": outcome.primary_value,
                                        "fork_value": op.get("new"),
                                        "target": outcome.target,
                                        "created_at": _now_iso(),
                                    }
                                elif outcome.status in RESOLVED_STATUSES:
                                    resolved[str(op["seq"])] = outcome.status
                                    conflicts.pop(str(op["seq"]), None)
            else:
                for op in pending_ops:
                    outcome = self._merge_one(
                        op,
                        dry_run=dry_run,
                        on_conflict=on_conflict,
                        combine_comments=combine_comments,
                        preserve_alias=preserve_alias,
                        fork_id=fork_id,
                        decide_with_evidence=decide_with_evidence,
                    )
                    entries.append(
                        {
                            "seq": op["seq"],
                            "op": op["op"],
                            "binary": op.get("binary", ""),
                            "target": outcome.target,
                            "status": outcome.status,
                            "detail": outcome.detail,
                        }
                    )
                    if not dry_run:
                        if outcome.status == "conflict":
                            conflicts[str(op["seq"])] = {
                                **op,
                                "seq": op["seq"],
                                "op": op["op"],
                                "primary_value": outcome.primary_value,
                                "fork_value": op.get("new"),
                                "target": outcome.target,
                                "created_at": _now_iso(),
                            }
                        elif outcome.status in RESOLVED_STATUSES:
                            resolved[str(op["seq"])] = outcome.status
                            conflicts.pop(str(op["seq"]), None)

            counts: dict[str, int] = {}
            for entry in entries:
                counts[entry["status"]] = counts.get(entry["status"], 0) + 1

            if not dry_run:
                if (
                    counts.get("applied")
                    or counts.get("overwritten")
                    or counts.get("combined")
                    or counts.get("resolved_by_evidence")
                ):
                    self.context.save()
                state["merges"] = [*state["merges"], {"at": _now_iso(), "counts": counts}][-20:]
                save_merge_state(fork_dir, state)

        pending_count = sum(1 for op in journal if str(op["seq"]) not in resolved)
        if auto_discard and not dry_run and pending_count == 0:
            try:
                discard_fork(self.context.pyghidra_mcp_dir, fork_id)
                logger.info("Auto-pruned merged fork %s post-merge.", fork_id)
            except ValueError as e:
                logger.debug("Could not auto-discard fork %s post-merge: %s", fork_id, e)
        return {
            "fork_id": fork_id,
            "dry_run": dry_run,
            "on_conflict": on_conflict,
            "counts": counts,
            "entries": entries,
            "pending_ops": pending_count,
        }

    def resolve_conflict(
        self,
        fork_id: str,
        seq: int,
        keep: str = "primary",
    ) -> dict[str, Any]:
        """Resolve an active conflict using this merger's context and tools."""
        return resolve_conflict(
            self.context.pyghidra_mcp_dir,
            fork_id,
            seq,
            keep=keep,
            merger=self,
        )

    def _merge_one(
        self,
        op: dict[str, Any],
        *,
        dry_run: bool,
        on_conflict: str,
        combine_comments: bool = False,
        preserve_alias: bool = False,
        fork_id: str = "",
        decide_with_evidence: bool = False,
    ) -> _Outcome:
        kind = op.get("op")
        if kind == "delete_project_binary":
            return _Outcome(
                "ignored",
                op.get("binary", ""),
                "deletions are never merged automatically; delete on the primary if intended",
            )
        if kind == "import_binary":
            return self._merge_import(op, dry_run=dry_run)

        handler = _PROGRAM_EDIT_HANDLERS.get(str(kind))
        if handler is None:
            return _Outcome("ignored", op.get("binary", ""), f"unsupported journal op '{kind}'")

        try:
            program_info = self.context.get_program_info(op["binary"])
        except Exception as e:
            # Typically a binary the fork imported that is not (yet) analyzed here.
            return _Outcome("skipped", op["binary"], f"binary unavailable on primary: {e}")

        tools = self.tools_factory(program_info)
        try:
            return self.run(
                lambda: handler(
                    tools,
                    op,
                    dry_run,
                    on_conflict,
                    combine_comments=combine_comments,
                    preserve_alias=preserve_alias,
                    fork_id=fork_id,
                    decide_with_evidence=decide_with_evidence,
                )
            )
        except Exception as e:
            return _Outcome("failed", op.get("address") or op.get("function_address") or "", str(e))

    def _merge_import(self, op: dict[str, Any], *, dry_run: bool) -> _Outcome:
        path = Path(op["path"])
        if not path.exists():
            return _Outcome("failed", str(path), "source path no longer exists")
        if path.is_file():
            from pyghidra_mcp.context import PyGhidraContext

            program_name = PyGhidraContext._gen_unique_bin_name(path)
            if any(Path(name).name == program_name for name in self.context.list_binaries()):
                return _Outcome("already_applied", str(path))
        if dry_run:
            return _Outcome("would_apply", str(path), "would import into the primary project")
        result = self.context.import_binary_backgrounded(path)
        return _Outcome("queued", str(path), result.message)


def session_info(context: Any) -> dict[str, Any] | None:
    """Describe whether ``context`` is a fork or the primary, for tool responses."""
    fork = getattr(context, "fork_session", None)
    if isinstance(fork, ForkSession):
        fork_dir = fork.fork_dir
        merge_state = load_merge_state(fork_dir)
        journal = read_journal(fork_dir)
        resolved_count = sum(1 for entry in journal if str(entry.get("seq")) in merge_state.get("resolved", {}))
        conflicts_val = merge_state.get("conflicts", {})
        conflicts = list(conflicts_val.values()) if isinstance(conflicts_val, dict) else list(conflicts_val)
        hint = (
            "Another session holds the main project, so this one works on a private "
            "fork. Edits are journaled for the primary session to merge with merge_fork; "
            "changes made there after the fork are not visible here."
        )
        res = {
            "role": "fork",
            "project": str(fork.project_spec.gpr_path),
            "fork_id": fork.fork_id,
            "parent_project": str(fork.parent_project),
            "journal_ops": fork.op_count,
            "resolved_ops": resolved_count,
            "conflicts": conflicts,
            "hint": hint,
        }
        if conflicts:
            advice = (
                f"This fork has {len(conflicts)} unresolved conflicts from merge_fork. "
                "Call resolve_conflict() from the primary or sync_fork() to refresh."
            )
            res["advice"] = advice
            res["hint"] = f"{hint} {advice}"
        return res

    pyghidra_mcp_dir = getattr(context, "pyghidra_mcp_dir", None)
    if not isinstance(pyghidra_mcp_dir, Path):
        return None
    pending = sum(info["pending_ops"] for info in list_forks(pyghidra_mcp_dir))
    project_path = getattr(context, "project_path", None)
    project_name = getattr(context, "project_name", None)
    project = (
        str(Path(project_path) / f"{project_name}.gpr")
        if isinstance(project_path, (str, Path)) and isinstance(project_name, str)
        else ""
    )
    return {
        "role": "primary",
        "project": project,
        "pending_fork_ops": pending,
        "hint": (
            f"{pending} edit(s) from other sessions' forks await merging: see list_forks, then merge_fork."
            if pending
            else None
        ),
    }


def server_instructions(context: Any) -> str:
    info = session_info(context)
    base = (
        "pyghidra-mcp exposes a Ghidra project. Several agents can share one project: "
        "the session that opens it first is the primary; later sessions get a private "
        "fork whose edits are journaled and merged back by the primary with merge_fork."
    )
    if info and info["role"] == "fork":
        return f"{base}\n\nTHIS SESSION IS FORK {info['fork_id']}. {info['hint']}"
    return base


def resolve_conflict(
    target_or_dir: Path | Any,
    fork_id: str,
    seq: int,
    keep: str = "primary",
    *,
    context: Any = None,
    merger: ForkMerger | None = None,
    tools: Any = None,
) -> dict[str, Any]:
    """Resolve an edit conflict between primary and fork.

    Args:
        target_or_dir: pyghidra_mcp_dir (Path) or a context object possessing it.
        fork_id: ID of the fork holding the conflict.
        seq: Sequence number of the conflicting edit.
        keep: 'primary' (keep primary value, discard fork edit),
              'fork' (replay and apply fork edit to primary), or
              'both' (combine comments or set alternative name alias comment).
        context: Optional primary context for mutating the Ghidra project.
        merger: Optional ForkMerger instance.
        tools: Optional tools instance or factory.

    Returns:
        Outcome dict with resolution details.
    """
    if keep not in {"primary", "fork", "both", "evidence"}:
        raise ValueError(f"keep must be 'primary', 'fork', 'both', or 'evidence', got {keep!r}")

    mcp_dir_attr = getattr(target_or_dir, "pyghidra_mcp_dir", None)
    if mcp_dir_attr is not None:
        context = context or target_or_dir
        pyghidra_mcp_dir = Path(mcp_dir_attr)
    else:
        pyghidra_mcp_dir = Path(target_or_dir)

    fork_dir = resolve_fork_dir(pyghidra_mcp_dir, fork_id)
    with _merge_lock:
        state = load_merge_state(fork_dir)
        resolved = state["resolved"]
        conflicts = state.setdefault("conflicts", {})
        journal = read_journal(fork_dir)

        op = next((entry for entry in journal if entry["seq"] == seq), None)
        if op is None:
            raise ValueError(f"Operation with seq={seq} not found in journal for fork '{fork_id}'")
        if str(seq) not in conflicts:
            raise ValueError(
                f"Operation seq={seq} is not an unresolved conflict in fork '{fork_id}' "
                f"(current status: {resolved.get(str(seq), 'pending')})"
            )

        status_val: str = "applied"
        target_val = op.get("address") or op.get("function_address") or op.get("binary") or ""
        detail_val: str | None = None
        active_tools: Any = None

        runner: Callable[[Any], Any] = _default_runner

        save_ctx: Any = None

        if keep == "primary":
            status_val = "discarded"
            detail_val = f"Discarded fork edit seq {seq}; kept primary value"
            resolved[str(seq)] = status_val
            conflicts.pop(str(seq), None)

        elif keep == "fork":
            if merger is not None:
                merger_outcome = merger._merge_one(op, dry_run=False, on_conflict="overwrite", fork_id=fork_id)
                status_val = merger_outcome.status if merger_outcome.status in RESOLVED_STATUSES else "applied"
                target_val = merger_outcome.target
                detail_val = merger_outcome.detail
                if hasattr(merger.context, "save"):
                    merger.context.save()
            elif context is not None:
                program_info = context.get_program_info(op["binary"])
                if tools is None:
                    try:
                        from pyghidra_mcp.tools import GhidraTools

                        active_tools = GhidraTools(program_info)
                    except Exception:
                        raise ValueError("Could not instantiate GhidraTools for context") from None
                else:
                    active_tools = tools(program_info) if callable(tools) else tools
                handler = _PROGRAM_EDIT_HANDLERS.get(str(op.get("op")))
                if handler is None:
                    raise ValueError(f"Unsupported journal op '{op.get('op')}'")
                h_out = handler(active_tools, op, False, "overwrite", fork_id=fork_id)
                status_val = h_out.status if h_out.status in RESOLVED_STATUSES else "applied"
                target_val = h_out.target
                detail_val = h_out.detail
                if hasattr(context, "save"):
                    context.save()
            elif tools is not None:
                handler = _PROGRAM_EDIT_HANDLERS.get(str(op.get("op")))
                if handler is None:
                    raise ValueError(f"Unsupported journal op '{op.get('op')}'")
                h_out = handler(tools, op, False, "overwrite", fork_id=fork_id)
                status_val = h_out.status if h_out.status in RESOLVED_STATUSES else "applied"
                target_val = h_out.target
                detail_val = h_out.detail
            else:
                raise ValueError("A context, merger, or tools instance is required to apply fork edit to primary")

            resolved[str(seq)] = status_val
            conflicts.pop(str(seq), None)

        elif keep == "evidence":
            fork_prov = op.get("provenance")
            fork_status = op.get("epistemic_status")
            fork_rank = _epistemic_rank(fork_prov, fork_status, symbol_name=str(op.get("new")))

            active_tools = None
            if merger is not None:
                program_info = merger.context.get_program_info(op["binary"])
                active_tools = merger.tools_factory(program_info)
                runner = merger.run
                save_ctx = merger.context
            elif context is not None:
                program_info = context.get_program_info(op["binary"])
                runner = getattr(context, "run", _default_runner)
                save_ctx = context
                if tools is None:
                    try:
                        from pyghidra_mcp.tools import GhidraTools

                        active_tools = GhidraTools(program_info)
                    except Exception:
                        active_tools = None
                else:
                    active_tools = tools(program_info) if callable(tools) else tools
            else:
                active_tools = tools

            current_val = None
            if active_tools is not None:
                try:
                    if op.get("op") == "rename_function":
                        fn = active_tools.find_function(op["address"])
                        current_val = str(fn.getName())
                    elif op.get("op") == "rename_variable":
                        _f, _k, var = active_tools.find_variable(op["function_address"], names=(op["old"], op["new"]))
                        current_val = str(var.getName())
                except Exception:
                    pass

            prim_prov = op.get("primary_provenance")
            prim_status = op.get("primary_epistemic_status")
            prim_rank = _epistemic_rank(prim_prov, prim_status, symbol_name=current_val)

            if fork_rank >= prim_rank and fork_rank > 0:
                if active_tools is None:
                    raise ValueError(
                        f"Cannot apply fork edit seq={seq} by evidence: "
                        "active Ghidra tools are not available for primary project"
                    )
                handler = _PROGRAM_EDIT_HANDLERS.get(str(op.get("op")))
                if handler is None:
                    raise ValueError(f"Unsupported journal op '{op.get('op')}'")
                h_out = runner(lambda: handler(active_tools, op, False, "overwrite", fork_id=fork_id))
                if save_ctx is not None and hasattr(save_ctx, "save"):
                    save_ctx.save()
                status_val = "resolved_by_evidence"
                target_val = h_out.target
                detail_val = f"Fork evidence rank {fork_rank} beat primary rank {prim_rank}"
            else:
                status_val = "discarded"
                detail_val = f"Discarded: primary evidence rank {prim_rank} beat fork rank {fork_rank}"

            resolved[str(seq)] = status_val
            conflicts.pop(str(seq), None)

        elif keep == "both":
            if merger is not None:
                program_info = merger.context.get_program_info(op["binary"])
                active_tools = merger.tools_factory(program_info)

                runner = merger.run

                save_ctx = merger.context
            elif context is not None:
                program_info = context.get_program_info(op["binary"])
                if tools is None:
                    try:
                        from pyghidra_mcp.tools import GhidraTools

                        active_tools = GhidraTools(program_info)
                    except Exception:
                        raise ValueError("Could not instantiate GhidraTools for context") from None
                else:
                    active_tools = tools(program_info) if callable(tools) else tools

                runner = _default_runner

                save_ctx = context
            elif tools is not None:
                active_tools = tools

                runner = _default_runner

                save_ctx = None
            else:
                raise ValueError("A context, merger, or tools instance is required for keep='both'")

            op_kind = op.get("op")
            if op_kind == "set_comment":
                addr = str(op["address"])
                c_type = str(op["comment_type"])
                current_comment = active_tools.get_comment(addr, c_type) if active_tools else None
                new_comment = op["new"]
                fork_tag = f"[{fork_id}]: {new_comment}"
                if current_comment:
                    if fork_tag in current_comment:
                        combined = current_comment
                    else:
                        combined = f"{current_comment}\n\n{fork_tag}"
                else:
                    combined = fork_tag
                if active_tools:
                    runner(lambda: active_tools.set_comment(addr, combined, c_type))
                target_val = f"{c_type} comment @ {addr}"
                detail_val = f"Combined comments: {current_comment!r} and {new_comment!r}"
            elif op_kind in ("rename_function", "rename_variable"):
                func_addr = str(
                    op.get("address")
                    if op_kind == "rename_function"
                    else (op.get("function_address") or op.get("address") or "")
                )
                new_name = op["new"]
                existing_plate = active_tools.get_comment(func_addr, "plate") if active_tools else None
                alias_text = f"[Alternative name from fork {fork_id}]: {new_name}"
                if existing_plate and alias_text in existing_plate:
                    combined_plate = existing_plate
                else:
                    combined_plate = f"{existing_plate}\n\n{alias_text}" if existing_plate else alias_text
                if active_tools:
                    runner(lambda: active_tools.set_comment(func_addr, combined_plate, "plate"))
                target_val = f"{op_kind} @ {func_addr}"
                detail_val = f"Kept primary name; preserved fork alias {new_name!r} in plate comment"
            else:
                raise ValueError(f"keep='both' is only supported for comments and renames, not '{op_kind}'")

            if save_ctx is not None and hasattr(save_ctx, "save"):
                save_ctx.save()

            status_val = "applied"
            resolved[str(seq)] = status_val
            conflicts.pop(str(seq), None)

        save_merge_state(fork_dir, state)

        return {
            "fork_id": fork_id,
            "seq": seq,
            "keep": keep,
            "status": status_val,
            "target": target_val,
            "detail": detail_val,
        }


def sync_fork(target_or_dir: Path | Any, fork_id: str) -> dict[str, Any]:
    """Reconcile and synchronize a fork by marking resolved entries and returning updated primary state."""
    mcp_dir_attr = getattr(target_or_dir, "pyghidra_mcp_dir", None)
    if mcp_dir_attr is not None:
        pyghidra_mcp_dir = Path(mcp_dir_attr)
    else:
        pyghidra_mcp_dir = Path(target_or_dir)

    fork_dir = resolve_fork_dir(pyghidra_mcp_dir, fork_id)
    with _merge_lock:
        state = load_merge_state(fork_dir)
        journal = read_journal(fork_dir)
        resolved = state.get("resolved", {})
        conflicts = state.get("conflicts", {})

        resolved_entries = []
        pending_entries = []
        for op in journal:
            s_seq = str(op["seq"])
            if s_seq in resolved:
                resolved_entries.append(
                    {
                        "seq": op["seq"],
                        "op": op["op"],
                        "status": resolved[s_seq],
                        "binary": op.get("binary", ""),
                        "target": op.get("address") or op.get("function_address") or "",
                    }
                )
            else:
                pending_entries.append(
                    {
                        "seq": op["seq"],
                        "op": op["op"],
                        "binary": op.get("binary", ""),
                        "target": op.get("address") or op.get("function_address") or "",
                        "in_conflict": s_seq in conflicts,
                        "conflict_detail": conflicts.get(s_seq),
                    }
                )

        return {
            "fork_id": fork_id,
            "synced_at": _now_iso(),
            "total_ops": len(journal),
            "resolved_ops": len(resolved_entries),
            "pending_ops": len(pending_entries),
            "resolved": resolved,
            "conflicts": list(conflicts.values()),
            "merges": state.get("merges", []),
            "resolved_entries": resolved_entries,
            "pending_entries": pending_entries,
        }


def merge_fork(
    target_or_context: Any,
    fork_id: str,
    *,
    tools_factory: Callable[[Any], Any] | None = None,
    dry_run: bool = False,
    on_conflict: str = "skip",
    auto_discard: bool = True,
    combine_comments: bool = False,
    preserve_alias: bool = False,
    atomic_by_function: bool = False,
    decide_with_evidence: bool = False,
    run: Callable[[Callable[[], Any]], Any] = lambda fn: fn(),
) -> dict[str, Any]:
    """Top-level helper to replay a fork's edits into the primary project."""
    if hasattr(target_or_context, "pyghidra_mcp_dir") and hasattr(target_or_context, "get_program_info"):
        context = target_or_context
        active_tools_factory: Callable[[Any], Any]
        if tools_factory is None:
            try:
                from pyghidra_mcp.tools import GhidraTools

                active_tools_factory = GhidraTools
            except Exception:
                active_tools_factory = _null_tools_factory
        else:
            active_tools_factory = tools_factory

        merger = ForkMerger(context, tools_factory=active_tools_factory, run=run)
        return merger.merge(
            fork_id,
            dry_run=dry_run,
            on_conflict=on_conflict,
            auto_discard=auto_discard,
            combine_comments=combine_comments,
            preserve_alias=preserve_alias,
            atomic_by_function=atomic_by_function,
            decide_with_evidence=decide_with_evidence,
        )
    else:
        mcp_dir = Path(getattr(target_or_context, "pyghidra_mcp_dir", target_or_context))
        from types import SimpleNamespace

        dummy_context = SimpleNamespace(pyghidra_mcp_dir=mcp_dir, save=lambda: None)
        fallback_factory = tools_factory if tools_factory is not None else _null_tools_factory
        merger = ForkMerger(dummy_context, tools_factory=fallback_factory, run=run)
        return merger.merge(
            fork_id,
            dry_run=dry_run,
            on_conflict=on_conflict,
            auto_discard=auto_discard,
            combine_comments=combine_comments,
            preserve_alias=preserve_alias,
            atomic_by_function=atomic_by_function,
            decide_with_evidence=decide_with_evidence,
        )
