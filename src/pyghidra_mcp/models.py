from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class DecompiledFunction(BaseModel):
    name: str
    code: str
    signature: str | None = None
    error: str | None = None
    # Rich response fields (populated when include_* flags are set)
    callees: list[str] | None = None
    referenced_strings: list[str] | None = None
    xrefs: list["CrossReferenceInfo"] | None = None


class ProgramBasicInfo(BaseModel):
    name: str
    analysis_complete: bool


class ProgramBasicInfos(BaseModel):
    programs: list[ProgramBasicInfo]


class ProgramInfo(BaseModel):
    name: str
    file_path: str | None = None
    load_time: float | None = None
    analysis_complete: bool
    metadata: dict
    code_indexed: bool
    strings_indexed: bool


class SessionInfo(BaseModel):
    role: Literal["primary", "fork"]
    project: str
    fork_id: str | None = None
    parent_project: str | None = None
    journal_ops: int | None = Field(None, description="edits journaled by this fork")
    pending_fork_ops: int | None = Field(None, description="unmerged edits across all forks")
    hint: str | None = None


class ProgramInfos(BaseModel):
    programs: list[ProgramInfo]
    session: SessionInfo | None = None


class OpenProgramInfo(BaseModel):
    name: str
    path: str
    current: bool
    analysis_complete: bool


class OpenProgramInfos(BaseModel):
    programs: list[OpenProgramInfo]


class SkippedImport(BaseModel):
    path: str
    reason: str


class ImportRequestResult(BaseModel):
    requested_path: str
    queued_count: int
    queued_paths: list[str]
    skipped_count: int
    skipped: list[SkippedImport]
    message: str


class SaveRequestResult(BaseModel):
    pass


class GotoResponse(BaseModel):
    binary_name: str
    address: str
    success: bool


class GuiContextResponse(BaseModel):
    active_program: str | None = None
    active_provider: str | None = None
    active_address: str | None = None
    active_function: str | None = None
    selection: str | None = None
    location_type: str | None = None


class RenameResponse(BaseModel):
    binary_name: str
    address: str
    old_name: str
    new_name: str


class VariableRenameResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    variable_kind: str
    old_name: str
    new_name: str


class VariableTypeResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    variable_kind: str
    variable_name: str
    old_type: str
    new_type: str


class FunctionPrototypeResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    old_prototype: str
    new_prototype: str


class CommentResponse(BaseModel):
    binary_name: str
    address: str
    comment: str
    comment_type: str


class ExportInfo(BaseModel):
    name: str
    address: str


class ExportInfos(BaseModel):
    exports: list[ExportInfo]


class ImportInfo(BaseModel):
    name: str
    library: str


class ImportInfos(BaseModel):
    imports: list[ImportInfo]


class CrossReferenceInfo(BaseModel):
    function_name: str | None = None
    from_address: str
    to_address: str
    type: str


class CrossReferenceInfos(BaseModel):
    target: str | None = None
    cross_references: list[CrossReferenceInfo]
    error: str | None = None


# Resolve forward reference for DecompiledFunction.xrefs
DecompiledFunction.model_rebuild()


class SymbolInfo(BaseModel):
    name: str
    address: str
    type: str
    namespace: str
    source: str
    refcount: int
    external: bool
    is_thunk: bool = False
    thunk_target: str | None = None


class SymbolSearchResults(BaseModel):
    symbols: list[SymbolInfo]


class SearchMode(str, Enum):
    """Search mode for code search."""

    SEMANTIC = "semantic"  # Vector similarity search
    LITERAL = "literal"  # Exact string match ($contains)


class CodeSearchResult(BaseModel):
    function_name: str
    code: str
    similarity: float
    search_mode: SearchMode
    preview: str | None = None


class CodeSearchResults(BaseModel):
    results: list[CodeSearchResult]
    query: str
    search_mode: SearchMode
    returned_count: int
    offset: int
    limit: int
    literal_total: int = Field(..., description="total literal matches")
    semantic_total: int = Field(..., description="estimated semantic matches")
    total_functions: int


class StringInfo(BaseModel):
    value: str
    address: str


class StringSearchResult(StringInfo):
    similarity: float


class StringSearchResults(BaseModel):
    strings: list[StringSearchResult]


class BytesReadResult(BaseModel):
    address: str
    size: int
    data: str = Field(..., description="hex string")


class DisassembleResult(BaseModel):
    address: str
    count: int
    listing: str = Field(
        ...,
        description=(
            "Newline-delimited disassembly listing. Each line is single-space separated: "
            "address, optional raw bytes (hex, when include_bytes=True), mnemonic, operands."
        ),
    )


class CallGraphDirection(str, Enum):
    """Represents the direction of the call graph."""

    CALLING = "calling"
    CALLED = "called"


class CallGraphDisplayType(str, Enum):
    """Represents the display type of the call graph."""

    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"


class CallGraphResult(BaseModel):
    function_name: str
    direction: CallGraphDirection
    display_type: CallGraphDisplayType
    graph: str = Field(..., description="MermaidJS graph string")
    mermaid_url: str


class ForkInfo(BaseModel):
    fork_id: str
    label: str | None = None
    status: str
    alive: bool | None = Field(None, description="fork server running; null if on another host")
    pid: int | None = None
    created_at: str
    journal_ops: int
    resolved_ops: int
    pending_ops: int
    path: str


class ForkList(BaseModel):
    session: SessionInfo | None = None
    forks: list[ForkInfo]


class ForkMergeEntry(BaseModel):
    seq: int
    op: str
    binary: str
    target: str
    status: str = Field(
        ...,
        description=(
            "applied, already_applied, overwritten, queued, ignored (final); "
            "conflict, skipped, failed (retried by the next merge); "
            "would_apply, would_overwrite (dry run)"
        ),
    )
    detail: str | None = None


class ForkMergeResult(BaseModel):
    fork_id: str
    dry_run: bool
    on_conflict: str
    counts: dict[str, int]
    entries: list[ForkMergeEntry]
    pending_ops: int
