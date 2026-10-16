"""
MCP Tool handlers for pyghidra-mcp.

This module contains all MCP tool implementations with centralized error handling.
"""

import asyncio
import functools
import logging
from pathlib import Path
from typing import Any, Literal, cast

from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError

from pyghidra_mcp import forks
from pyghidra_mcp.context_protocol import MCPContext
from pyghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CodeSearchResults,
    CommentResponse,
    CrossReferenceInfos,
    DecompiledFunction,
    DisassembleResult,
    ExportInfos,
    ForkInfo,
    ForkList,
    ForkMergeResult,
    FunctionPrototypeResponse,
    GotoResponse,
    GuiContextResponse,
    ImportInfos,
    ImportRequestResult,
    OpenProgramInfo,
    OpenProgramInfos,
    ProgramInfos,
    RenameResponse,
    SaveRequestResult,
    SearchMode,
    SessionInfo,
    StringSearchResults,
    SymbolSearchResults,
    VariableRenameResponse,
    VariableTypeResponse,
)
from pyghidra_mcp.tools import GhidraTools

logger = logging.getLogger(__name__)
DECOMPILE_TIMEOUT_GRACE_SECONDS = 1.0
CALLGRAPH_TIMEOUT_GRACE_SECONDS = 15.0


def _get_pyghidra_context(ctx: Context) -> MCPContext:
    """Narrow the SDK's default dictionary lifespan type to our shared context."""
    return cast(MCPContext, ctx.request_context.lifespan_context)


def _require_gui_context(ctx: Context):
    from pyghidra_mcp.gui_context import GuiPyGhidraContext

    pyghidra_context = ctx.request_context.lifespan_context
    if not isinstance(pyghidra_context, GuiPyGhidraContext):
        raise ValueError("This tool requires pyghidra-mcp to be running with --gui")
    return pyghidra_context


def _run_for_context(pyghidra_context: MCPContext, fn):
    from pyghidra_mcp.gui_context import GuiPyGhidraContext

    if isinstance(pyghidra_context, GuiPyGhidraContext):
        return pyghidra_context.run_on_swing(fn)
    return fn()


def _fork_session(pyghidra_context: MCPContext) -> forks.ForkSession | None:
    fork = getattr(pyghidra_context, "fork_session", None)
    return fork if isinstance(fork, forks.ForkSession) else None


def _journal(pyghidra_context: MCPContext, program_info: Any, op: str, **fields: Any) -> None:
    """Record a successful edit when this session works on a fork; never fail the edit."""
    fork = _fork_session(pyghidra_context)
    if fork is None:
        return
    try:
        binary = str(program_info.program.getDomainFile().getPathname()) if program_info else ""
        fork.record(op, binary, **fields)
    except Exception:
        logger.error("Failed to journal %s on fork %s", op, fork.fork_id, exc_info=True)


def _session_info(pyghidra_context: MCPContext) -> SessionInfo | None:
    info = forks.session_info(pyghidra_context)
    return SessionInfo(**info) if info else None


def _get_action_name(func_name: str) -> str:
    """Derives a gerund action name from a function name."""
    action = func_name.replace("_", " ")
    words = action.split()
    if words and not words[0].endswith("ing"):
        first = words[0]
        if first.endswith("e"):
            words[0] = first[:-1] + "ing"
        else:
            words[0] = first + "ing"
    return " ".join(words)


def mcp_error_handler(func):
    """
    Decorator that provides centralized error handling for MCP tools.
    """
    action = _get_action_name(func.__name__)

    def handle_error(e: Exception) -> ToolError:
        # MCPServer returns ToolError text to the client as CallToolResult(isError=True).
        # Since MCP 2.2 any other exception is treated as a crash and the client sees
        # only "Error executing tool <name>", hiding the actionable message.
        # MCPError is intentionally reserved for JSON-RPC protocol failures.
        if isinstance(e, ToolError):
            return e
        if isinstance(e, ValueError):
            return ToolError(str(e))
        return ToolError(f"Error {action}: {e!s}")

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise handle_error(e) from e

    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


# MCP Tool Implementations
# ---------------------------------------------------------------------------------


@mcp_error_handler
async def decompile_function(
    binary_name: str,
    name_or_address: str | list[str],
    ctx: Context,
    include_callees: bool = False,
    include_strings: bool = False,
    include_xrefs: bool = False,
    timeout_sec: int = 30,
) -> list[DecompiledFunction]:
    """Decompile function(s) to pseudo-C by name or address.

    Accepts a single target or a list for batch decompilation.
    Rich response flags attach callees, strings, and/or xrefs to each result.
    `timeout_sec` applies per target.
    """
    if timeout_sec <= 0:
        raise ValueError("timeout_sec must be greater than zero")

    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    results: list[DecompiledFunction] = []

    def _decompile_target(target: str) -> DecompiledFunction:
        result = tools.decompile_function_by_name_or_addr(target, timeout=timeout_sec)
        if include_callees:
            result.callees = tools.get_callees(target)
        if include_strings:
            result.referenced_strings = tools.get_referenced_strings(target)
        if include_xrefs:
            result.xrefs = tools.list_xrefs(target)
        return result

    for target in targets:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(_decompile_target, target),
                timeout=timeout_sec + DECOMPILE_TIMEOUT_GRACE_SECONDS,
            )
            results.append(result)
        except asyncio.TimeoutError:
            results.append(
                DecompiledFunction(
                    name=target,
                    code="",
                    error=f"Decompilation timed out after {timeout_sec:g} seconds",
                )
            )
        except Exception as e:
            results.append(DecompiledFunction(name=target, code="", error=str(e)))
    return results


@mcp_error_handler
def search_symbols_by_name(
    binary_name: str,
    query: str,
    ctx: Context,
    functions_only: bool = False,
    offset: int = 0,
    limit: int = 25,
) -> SymbolSearchResults:
    """Search symbols by regex pattern (case-insensitive).

    Supports full regex (e.g. ``^main$``, ``func.*init``). Plain substrings
    still work since they are valid regex.

    Set ``functions_only=True`` to search only function symbols
    (excludes labels, variables, classes, namespaces).
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    symbols = tools.search_symbols_by_name(
        query, functions_only=functions_only, offset=offset, limit=limit
    )
    return SymbolSearchResults(symbols=symbols)


@mcp_error_handler
def search_code(
    binary_name: str,
    query: str,
    ctx: Context,
    limit: int = 5,
    offset: int = 0,
    search_mode: Literal["semantic", "literal"] = "semantic",
    include_full_code: bool = True,
    preview_length: int = 500,
    similarity_threshold: float = 0.0,
) -> CodeSearchResults:
    """Search decompiled pseudo-C code.

    Modes: semantic (vector similarity, default) or literal (exact match).
    Results include both mode counts.
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.search_code(
        query=query,
        limit=limit,
        offset=offset,
        search_mode=SearchMode(search_mode),
        include_full_code=include_full_code,
        preview_length=preview_length,
        similarity_threshold=similarity_threshold,
    )


@mcp_error_handler
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """List all binaries in the project with their status.

    `session` says whether this server is the primary or a fork of a shared project.
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    return ProgramInfos(
        programs=pyghidra_context.list_project_binary_infos(),
        session=_session_info(pyghidra_context),
    )


@mcp_error_handler
def list_project_binary_metadata(binary_name: str, ctx: Context) -> dict:
    """Get binary metadata: architecture, compiler, endianness, hashes, analysis counts."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    return program_info.metadata


@mcp_error_handler
def list_open_programs(ctx: Context) -> OpenProgramInfos:
    """List programs currently open in the Ghidra GUI."""
    gui_context = _require_gui_context(ctx)
    programs = [OpenProgramInfo(**info) for info in gui_context.list_open_programs()]
    return OpenProgramInfos(programs=programs)


@mcp_error_handler
def open_program_in_gui(
    binary_name: str,
    new_window: bool = True,
    *,
    ctx: Context,
) -> OpenProgramInfo:
    """Open a project binary in the Ghidra GUI CodeBrowser.

    Defaults to a new CodeBrowser unless the binary is already open.
    """
    gui_context = _require_gui_context(ctx)
    return OpenProgramInfo(**gui_context.open_program_in_gui(binary_name, new_window=new_window))


@mcp_error_handler
def set_current_program(binary_name: str, ctx: Context) -> OpenProgramInfo:
    """Set the active/current program in the Ghidra GUI CodeBrowser."""
    gui_context = _require_gui_context(ctx)
    return OpenProgramInfo(**gui_context.set_current_program(binary_name))


@mcp_error_handler
def goto(
    binary_name: str,
    target: str,
    target_type: Literal["address", "function"],
    ctx: Context,
) -> GotoResponse:
    """Navigate the Ghidra GUI CodeBrowser to an address or function."""
    gui_context = _require_gui_context(ctx)
    return GotoResponse(**gui_context.goto(binary_name, target, target_type))


@mcp_error_handler
def get_gui_context(ctx: Context) -> GuiContextResponse:
    """Get the current active user's location and metadata in the Ghidra GUI.

    Assume this is volatile and has changed since last call.
    """
    gui_context = _require_gui_context(ctx)
    return GuiContextResponse(**gui_context.get_active_gui_context())


@mcp_error_handler
def rename_function(
    binary_name: str,
    name_or_address: str,
    new_name: str,
    ctx: Context,
) -> RenameResponse:
    """Rename a function."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.rename_function(name_or_address, new_name),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "rename_function",
        address=result["address"],
        old=result["old_name"],
        new=result["new_name"],
    )
    return RenameResponse(binary_name=binary_name, **result)


@mcp_error_handler
def rename_variable(
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    new_name: str,
    ctx: Context,
) -> VariableRenameResponse:
    """Rename a parameter or local by exact name."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.rename_variable(function_name_or_address, variable_name, new_name),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "rename_variable",
        function_address=result["function_address"],
        storage=result.get("storage"),
        old=result["old_name"],
        new=result["new_name"],
    )
    return VariableRenameResponse(binary_name=binary_name, **result)


@mcp_error_handler
def set_variable_type(
    binary_name: str,
    function_name_or_address: str,
    variable_name: str,
    type_name: str,
    ctx: Context,
) -> VariableTypeResponse:
    """Set a parameter or local type by exact name."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.set_variable_type(function_name_or_address, variable_name, type_name),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "set_variable_type",
        function_address=result["function_address"],
        storage=result.get("storage"),
        variable_name=result["variable_name"],
        type_name=type_name,
        old=result["old_type"],
        new=result["new_type"],
    )
    return VariableTypeResponse(binary_name=binary_name, **result)


@mcp_error_handler
def set_function_prototype(
    binary_name: str,
    function_name_or_address: str,
    prototype: str,
    ctx: Context,
) -> FunctionPrototypeResponse:
    """Set a function prototype. Invalid input returns Ghidra's error."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.set_function_prototype(function_name_or_address, prototype),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "set_function_prototype",
        address=result["function_address"],
        prototype=prototype,
        old=result["old_prototype"],
        new=result["new_prototype"],
    )
    return FunctionPrototypeResponse(binary_name=binary_name, **result)


@mcp_error_handler
def set_comment(
    binary_name: str,
    target: str,
    comment: str,
    comment_type: Literal["decompiler", "plate", "pre", "eol", "post", "repeatable"],
    ctx: Context,
) -> CommentResponse:
    """Set a decompiler or listing comment."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    result = _run_for_context(
        pyghidra_context,
        lambda: tools.set_comment(target, comment, comment_type),
    )
    result = cast(dict, result)
    _journal(
        pyghidra_context,
        program_info,
        "set_comment",
        address=result["address"],
        comment_type=result["comment_type"],
        old=result.get("old_comment"),
        new=result["comment"],
    )
    return CommentResponse(binary_name=binary_name, **result)


@mcp_error_handler
def delete_project_binary(binary_name: str, ctx: Context) -> str:
    """Delete a binary from the project."""
    pyghidra_context = _get_pyghidra_context(ctx)
    if pyghidra_context.delete_program(binary_name):
        fork = _fork_session(pyghidra_context)
        if fork is not None:
            fork.record("delete_project_binary", binary_name)
        return f"Successfully deleted binary: {binary_name}"
    else:
        raise ValueError(f"Binary '{binary_name}' not found or could not be deleted.")


@mcp_error_handler
def list_exports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    """List exported symbols, optionally filtered by regex query."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    exports = tools.list_exports(query=query, offset=offset, limit=limit)
    return ExportInfos(exports=exports)


@mcp_error_handler
def list_imports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ImportInfos:
    """List imported symbols, optionally filtered by regex query."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    imports = tools.list_imports(query=query, offset=offset, limit=limit)
    return ImportInfos(imports=imports)


@mcp_error_handler
def list_xrefs(
    binary_name: str, name_or_address: str | list[str], ctx: Context
) -> list[CrossReferenceInfos]:
    """List cross-references to function(s), symbol(s), or address(es).

    Accepts a single target or a list for batch lookup.
    Suggests close matches on no exact hit.
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    targets = [name_or_address] if isinstance(name_or_address, str) else name_or_address
    results: list[CrossReferenceInfos] = []
    for target in targets:
        try:
            cross_references = tools.list_xrefs(target)
            results.append(CrossReferenceInfos(target=target, cross_references=cross_references))
        except Exception as e:
            results.append(CrossReferenceInfos(target=target, cross_references=[], error=str(e)))
    return results


@mcp_error_handler
def search_strings(
    binary_name: str,
    ctx: Context,
    query: str,
    limit: int = 100,
) -> StringSearchResults:
    """Search for strings within a binary."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    strings = tools.search_strings(query=query, limit=limit)
    return StringSearchResults(strings=strings)


@mcp_error_handler
def read_bytes(binary_name: str, ctx: Context, address: str, size: int = 32) -> BytesReadResult:
    """Read raw bytes at an address. Hex format supported (0x prefix optional)."""
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.read_bytes(address=address, size=size)


@mcp_error_handler
def disassemble(
    binary_name: str,
    ctx: Context,
    address: str,
    count: int = 20,
    include_bytes: bool = False,
) -> DisassembleResult:
    """Disassemble raw instructions at any address, like objdump.

    `listing` is one instruction per line: address, mnemonic, operands, plus a hex
    bytes column if `include_bytes=True`. Returns up to `count` instructions (max 200).
    """
    if count <= 0:
        raise ValueError("count must be > 0")
    if count > 200:
        raise ValueError("count must be <= 200")
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)
    return tools.disassemble(address=address, count=count, include_bytes=include_bytes)


@mcp_error_handler
async def gen_callgraph(
    binary_name: str,
    function_name: str,
    ctx: Context,
    direction: Literal["calling", "called"] = "calling",
    display_type: Literal["flow", "flow_ends"] = "flow",
    condense_threshold: int = 50,
    top_layers: int = 3,
    bottom_layers: int = 3,
    max_run_time: int = 120,
) -> CallGraphResult:
    """Generate a MermaidJS call graph for a function."""
    if max_run_time <= 0:
        raise ValueError("max_run_time must be greater than zero")
    pyghidra_context = _get_pyghidra_context(ctx)
    program_info = pyghidra_context.get_program_info(binary_name)
    tools = GhidraTools(program_info)

    def _generate() -> CallGraphResult:
        return tools.gen_callgraph(
            function_name_or_address=function_name,
            cg_direction=CallGraphDirection(direction),
            cg_display_type=CallGraphDisplayType(display_type),
            include_refs=True,
            max_depth=None,
            max_run_time=max_run_time,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
        )

    # ghidrecomp only checks max_run_time between expansions and can overrun it by
    # minutes on dense "called" graphs (#122); bound how long the client waits.
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_generate),
            timeout=max_run_time + CALLGRAPH_TIMEOUT_GRACE_SECONDS,
        )
    except asyncio.TimeoutError:
        raise ValueError(
            f"Call graph for '{function_name}' did not finish within {max_run_time}s. "
            "Retry with a smaller max_run_time or direction='calling'."
        ) from None


@mcp_error_handler
def import_binary(binary_path: str, ctx: Context) -> ImportRequestResult:
    """Import a binary into the project from a file path."""
    pyghidra_context = _get_pyghidra_context(ctx)
    result = pyghidra_context.import_binary_backgrounded(binary_path)
    fork = _fork_session(pyghidra_context)
    if fork is not None and result.queued_count:
        fork.record("import_binary", "", path=str(Path(binary_path).absolute()))
    return result


@mcp_error_handler
def save(ctx: Context) -> SaveRequestResult:
    """Save all programs."""
    pyghidra_context = _get_pyghidra_context(ctx)
    pyghidra_context.save()
    return SaveRequestResult()


# Multi-agent forks
# ---------------------------------------------------------------------------------


def _forks_dir(pyghidra_context: MCPContext) -> Path:
    fork = _fork_session(pyghidra_context)
    if fork is not None:
        return fork.parent_pyghidra_mcp_dir
    return cast(Path, cast(Any, pyghidra_context).pyghidra_mcp_dir)


@mcp_error_handler
def list_forks(ctx: Context) -> ForkList:
    """List forks of this project and this session's role.

    A fork is created when a server finds the project locked by another session.
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    return ForkList(
        session=_session_info(pyghidra_context),
        forks=[ForkInfo(**info) for info in forks.list_forks(_forks_dir(pyghidra_context))],
    )


@mcp_error_handler
def merge_fork(
    fork_id: str,
    ctx: Context,
    dry_run: bool = False,
    on_conflict: Literal["skip", "overwrite"] = "skip",
) -> ForkMergeResult:
    """Replay a fork's journaled edits into this (primary) project.

    Edits whose target also changed here since the fork are conflicts: skipped,
    or forced with on_conflict="overwrite". Re-running only retries unresolved edits.
    """
    pyghidra_context = _get_pyghidra_context(ctx)
    if _fork_session(pyghidra_context) is not None:
        raise ValueError(
            "This session is itself a fork; merge_fork must run on the primary session "
            "that holds the main project."
        )
    merger = forks.ForkMerger(
        pyghidra_context,
        GhidraTools,
        run=lambda fn: _run_for_context(pyghidra_context, fn),
    )
    return ForkMergeResult(**merger.merge(fork_id, dry_run=dry_run, on_conflict=on_conflict))


@mcp_error_handler
def discard_fork(fork_id: str, ctx: Context) -> str:
    """Delete a stopped fork and its journal. Unmerged edits are lost."""
    pyghidra_context = _get_pyghidra_context(ctx)
    fork = _fork_session(pyghidra_context)
    if fork is not None and fork.fork_id == fork_id:
        raise ValueError("A session cannot discard the fork it is running on.")
    info = forks.discard_fork(_forks_dir(pyghidra_context), fork_id)
    return f"Discarded fork {fork_id} ({info.get('pending_ops', 0)} unmerged edit(s) dropped)."
