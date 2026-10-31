# Changelog

All notable changes to SuperghidraMCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-10-31

### Fixed
- **Orphan Prune Data Loss Protection**: In `prune_forks`, inspect `journal.jsonl` in directories lacking `fork.json`. Preserve directories with unmerged edits under default GC (`include_unmerged=False`), and quarantine expired unmerged directories to `quarantined_orphans/<fork_id>` rather than recursively deleting them.
- **Stale Lock Cleanup & Failed Session Marking**: Automatically clean up stale Ghidra lock files on fork resume, and mark failed fork sessions explicitly.
- **Release CI Gatekeeper Hardening**: Enforced `--required-workflows` parameter in `scripts/wait_for_ci.py`, treated non-required cancelled workflows as non-blocking skips, and calibrated minimum expected workflow count to match declared required patterns.


### Added
- **Chroma Index Isolation in Forks**: Replaced writable directory junctions and symlinks with client-level read-only querying of parent collections via `parent_chroma_client`. Fork modifications (e.g. `import_binary`) and local collection indexes write exclusively to the fork's local `chromadb` directory, preventing fork writes from leaking into the primary project or colliding on SQLite WAL locks. Incomplete parent collections are never deleted or rebuilt by forks.
- **Copy-On-Write Project Cloning**: Implemented `_reflink_copy` (`clonefile` on macOS APFS, `FICLONE` ioctl on Linux Btrfs/XFS) in `shutil.copytree` for `.rep` project cloning, enabling instantaneous 0-byte COW forks on supported filesystems while falling back cleanly on ext4 and NTFS.
- **Read-Only Session Fork Suppression**: Prompted informative error when `--read-only` is requested on a locked project rather than duplicating 150+ MB into a fork.
- **Hardened Release CI Gatekeeper (`wait_for_ci.py`)**: Enforced minimum expected workflow counts, continuous dynamic discovery of late-starting peer workflows, fail-fast non-zero exit (code 1) on discovery timeout or persistent `gh` API failures (preventing premature PyPI publishing), and immediate abort on workflow failures.

## [1.0.3] - 2026-10-29

### Added
- **Multi-Platform CI Release Gating**: Configured multi-platform verification matrix (`ubuntu-latest`, `macos-latest`) in `release.yml` and `release-cli.yml` enforcing that Ruff linting, Pyright type checking, and unit/fork test suites must pass before packages are built or uploaded to PyPI.

### Fixed
- **CLI MCP v2 Error Handling**: Added support for snake_case and camelCase attributes (`isError`/`is_error` and `structuredContent`/`structured_content`) returned by modern MCP v2 call results.

## [1.0.2] - 2026-10-29

### Fixed
- **GZFS Empty String Sanitization**: Suppressed GZFS export when `--gzfs-path ""` is provided, preventing archive pollution in the current working directory.
- **Fork Quota Enforcement**: Pre-checked estimated clone size against `max_fork_disk_mb` before cloning, and added post-copy disk measurement with rollback to strictly enforce storage quotas.
- **Function-Scoped Comment Grouping**: Associated listing instruction comments with their enclosing function entry point so `atomic_by_function` merges apply or hold back atomically with other function mutations.
- **Test Suite Environment Hardening**: Decorated GUI launcher tests with a Ghidra availability check to cleanly skip on headless test runners lacking a local Ghidra installation.
- **Release Workflow Assets**: Added automatic asset upload (`action-gh-release@v2`) to GitHub Release workflows for wheels and sdists.

## [0.5.0] - 2026-10-27

### Added
- **Project Folder Rename & Legacy Fallback**: Default project directory aligned to `superghidra_mcp_projects/`. Added transparent backward-compatibility fallback that automatically discovers and opens existing projects in legacy `pyghidra_mcp_projects/` folders without requiring manual migration.
- **Compatibility Preservation**: Retained the `pyghidra_mcp` Python package name, `pyghidra-mcp` console script entrypoint, and `pyghidra-mcp` Docker container entrypoint intentionally to preserve zero-friction backwards compatibility across existing MCP client registrations (Claude Desktop, Cursor, AGY CLI, and Hermes Agent).
- **Core Dependency Compatibility**: Relaxed `superghidra` core dependency requirement to `superghidra[smt,storage]>=0.4.0` to permit installation prior to the public `superghidra` 0.5.0 PyPI release.

## [0.4.0] - 2026-10-26

### Added
- **42 Automated RE Tools**: Full suite of Model Context Protocol tools exposing binary triage, decompilation, cross-references, disassembly, RTTI recovery, and formal equivalence proofs.
- **L2 WAL Cache Integration**: Sub-millisecond query response bypass using SQLite WAL caching.
- **Multi-Tier Resource Governor**: Runtime resource profile switching (`eco`, `balanced`, `turbo`, `auto`).
- **Zero-Copy Shared Memory IPC**: POSIX and Win32 shared-memory ring buffer support for microsecond binary data access.
