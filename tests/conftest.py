import os
import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

_SUPERGHIDRA = r"E:\02_Projects\SuperGhidra"
if os.path.exists(_SUPERGHIDRA) and _SUPERGHIDRA not in sys.path:
    sys.path.insert(0, _SUPERGHIDRA)
