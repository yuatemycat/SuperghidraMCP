# Changelog

All notable changes to SuperghidraMCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
