import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
DATA = Path(__file__).resolve().parent / "data"
sys.path.insert(0, str(SCRIPTS))
