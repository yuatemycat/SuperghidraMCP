import sys
from pathlib import Path

cli_src = Path(__file__).resolve().parent.parent / "src"
if str(cli_src) not in sys.path:
    sys.path.insert(0, str(cli_src))
