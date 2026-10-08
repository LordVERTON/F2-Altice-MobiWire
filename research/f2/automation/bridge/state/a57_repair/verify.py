import hashlib
import json
from pathlib import Path
import sys

root = Path(r'C:\Users\verto\F2-Altice-MobiWire')
sys.path.insert(0, str(root / 'research/f2/automation/bridge'))
from notion_queue import NotionQueue, environment, prop
from notion_worker import Git, validate

state = Path(__file__).resolve().parent
repair = json.loads((state / 'repair.json').read_text())
secret = environment('F2_NOTION_TOKEN')
q = NotionQueue(secret, '1bcea051-574f-40f5-ab62-d98debf41cb4')
p = q.page('3f2173c5-7e04-8153-ac83-e14ec5522ace')
script, manifest, result, report = [root / path for path in repair['paths']]
assert script.read_bytes() == (state / 'corrected/script.py').read_bytes()
assert script.read_bytes() == (state / 'original' / script.name).read_bytes().replace(b'for _, value in fa.literals:', b'for _, _, value in fa.literals:')
assert manifest.read_bytes() == (state / 'corrected/job.json').read_bytes()
assert hashlib.sha256(script.read_bytes()).hexdigest() == repair['script_sha256']
validate(p, manifest.read_bytes(), script.read_bytes(), root)
receipt = json.loads(result.read_text())
assert receipt['status'] == 'completed' and receipt['exit_code'] == 0
assert receipt['script_sha256'] == repair['script_sha256']
assert prop(p, 'Status', 'select') == 'COMPLETED'
assert prop(p, 'Review Status', 'select') == 'PENDING'
assert prop(p, 'Exit Code', 'number') == 0
assert prop(p, 'Next Job ID') == ''
commit = prop(p, 'Result Commit')
assert commit != '495c6e0db2b539cd989a46aed629396cd5f49953'
git = Git(root, secret)
git.branch()
git.confirm_pushed(commit)
assert git.clean()
changed = set(git.run('diff', '--name-only', '39d21c2', 'HEAD').splitlines())
assert changed == set(repair['paths']) | {'research/f2/automation/bridge/review_prompt.txt'}
assert (root / 'research/f2/automation/bridge/ORCHESTRATOR_STOP').exists()
print('A57 FIXED/PASS')
print('SHA256:', repair['script_sha256'])
print('Result commit:', commit)
print('Notion: COMPLETED / PENDING')
print('Git: clean; canonical branch; result pushed')
