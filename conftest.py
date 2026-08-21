from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
PATHS = [
    ROOT / "src",
    ROOT / "tests",
    ROOT.parent / "dwlabbasicpy" / "src",
]

for path in PATHS:
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)
