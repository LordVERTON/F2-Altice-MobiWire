"""Compatibility entry point; current tools and logs live in f2_runtime/."""
import runpy
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3] / 'f2_runtime'
sys.path.insert(0, str(root))
if __name__ == '__main__':
    runpy.run_path(str(root / Path(__file__).name), run_name='__main__')
