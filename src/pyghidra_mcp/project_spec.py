from dataclasses import dataclass
from pathlib import Path

DEFAULT_PROJECT_NAME = "my_project"


@dataclass(frozen=True)
class ProjectSpec:
    """Normalized Ghidra project paths for headless and GUI launch modes."""

    project_directory: Path
    project_name: str
    gpr_path: Path
    pyghidra_mcp_dir: Path
    was_gpr_path: bool

    @classmethod
    def from_cli(
        cls,
        project_path: Path,
        project_name: str,
        *,
        default_project_name: str = DEFAULT_PROJECT_NAME,
    ) -> "ProjectSpec":
        """Normalize CLI project options without depending on click."""
        project_path = Path(project_path)

        def _resolve_state_dir(base: Path, name: str) -> Path:
            legacy = base / f"{name}-pyghidra-mcp"
            canonical = base / f"{name}-superghidra-mcp"
            if legacy.exists() and not canonical.exists():
                return legacy
            return canonical

        if project_path.suffix.lower() == ".gpr":
            if project_name != default_project_name:
                raise ValueError("Cannot use --project-name when specifying a .gpr file")

            resolved_project_name = project_path.stem
            project_directory = project_path.parent
            return cls(
                project_directory=project_directory,
                project_name=resolved_project_name,
                gpr_path=project_path,
                pyghidra_mcp_dir=_resolve_state_dir(project_directory, resolved_project_name),
                was_gpr_path=True,
            )

        return cls(
            project_directory=project_path,
            project_name=project_name,
            gpr_path=project_path / f"{project_name}.gpr",
            pyghidra_mcp_dir=_resolve_state_dir(project_path, project_name),
            was_gpr_path=False,
        )
