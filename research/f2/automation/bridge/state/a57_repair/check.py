import ast
import json
from pathlib import Path
import sys
from types import SimpleNamespace

root = Path(r'C:\Users\verto\F2-Altice-MobiWire')
sys.path.insert(0, str(root / 'research/f2/automation/bridge'))
from notion_worker import Mutex, static_check

state = Path(__file__).resolve().parent
raw = (state / 'corrected/script.py').read_bytes()
tree = static_check(raw)
function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'closure_profile')
fa = SimpleNamespace(calls=[(1, 0x1235)], literals=[(1, 2, 0xF0001234), (3, 4, 0xEFFFFFFF), (5, 6, 0xF0200000)])
module = SimpleNamespace(callgraph=lambda *a, **kw: ({1: fa}, [], [], []))
namespace = {'m': module}
exec(compile(ast.Module(body=[function], type_ignores=[]), '<closure_profile fixture>', 'exec'), namespace)
profile = namespace['closure_profile'](SimpleNamespace(normalized_target=lambda v: (v & ~1, '')), 0x1001)
assert profile['globals'] == {0xF0001234}
assert profile['calls'] == {0x1234}
with Mutex():
    print('Worker stopped / exclusive mutex: PASS')
print('Worker static policy + isolated triple-tuple fixture: PASS')
