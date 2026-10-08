import json
from pathlib import Path
import sys

root = Path(r'C:\Users\verto\F2-Altice-MobiWire').resolve()
state = Path(__file__).resolve().parent
sys.path.insert(0, str(root / 'research/f2/automation/bridge'))
from notion_worker import Mutex

job = 's13_5a57_86c0_8928_mapper_owner_differential'
expected = [f'research/f2/automation/jobs/{job}.py', f'research/f2/automation/manifests/{job}.job.json',
            f'research/f2/automation/results/{job}.result.json', f'research/f2/work/reports/{job}.txt']
assert json.loads((state / 'repair.json').read_text())['paths'] == expected
dest = state / 'released'
with Mutex():
    assert (root / 'research/f2/automation/bridge/STOP').is_file()
    assert (root / expected[0]).read_bytes() == (state / 'corrected/script.py').read_bytes()
    assert (root / expected[1]).read_bytes() == (state / 'corrected/job.json').read_bytes()
    for rel in expected:
        path = (root / rel).resolve()
        assert path.is_relative_to(root) and path.is_file()
        assert (state / 'original' / path.name).is_file()
    assert dest.resolve().is_relative_to(root)
    dest.mkdir(exist_ok=False)
    for rel in expected:
        path = (root / rel).resolve()
        path.rename(dest / path.name)
print('Only four A57 paths released; original and corrected bytes preserved in ignored runtime state')
