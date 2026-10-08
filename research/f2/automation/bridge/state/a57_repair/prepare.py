from pathlib import Path
import ast
import hashlib
import json
import shutil

root = Path(r'C:\Users\verto\F2-Altice-MobiWire')
state = Path(__file__).resolve().parent
job = 's13_5a57_86c0_8928_mapper_owner_differential'
paths = [f'research/f2/automation/jobs/{job}.py',
         f'research/f2/automation/manifests/{job}.job.json',
         f'research/f2/automation/results/{job}.result.json',
         f'research/f2/work/reports/{job}.txt']
backup = state / 'original'
backup.mkdir(exist_ok=False)
for rel in paths:
    shutil.copyfile(root / rel, backup / Path(rel).name)
script = root / paths[0]
before = script.read_bytes()
old, new = b'for _, value in fa.literals:', b'for _, _, value in fa.literals:'
assert before.count(old) == 1
after = before.replace(old, new)
tree = ast.parse(after)
for node in ast.walk(tree):
    if isinstance(node, (ast.For, ast.comprehension)) and isinstance(node.iter, ast.Attribute) and node.iter.attr == 'literals':
        assert isinstance(node.target, (ast.Tuple, ast.List)) and len(node.target.elts) == 3
script.write_bytes(after)
digest = hashlib.sha256(after).hexdigest()
manifest_path = root / paths[1]
raw = manifest_path.read_bytes()
manifest = json.loads(raw)
manifest_path.write_bytes(raw.replace(manifest['script_sha256'].encode(), digest.encode()))
corrected = state / 'corrected'
corrected.mkdir(exist_ok=False)
shutil.copyfile(script, corrected / 'script.py')
shutil.copyfile(manifest_path, corrected / 'job.json')
prompt = root / 'research/f2/automation/bridge/review_prompt.txt'
note = b'StaticAudit FuncAudit.literals tuples are: (site, literal_addr, literal_value)'
content = prompt.read_bytes()
if note not in content:
    prompt.write_bytes(content.rstrip(b'\r\n') + b'\n' + note + b'\n')
(state / 'repair.json').write_text(json.dumps({'job_id': job, 'script_sha256': digest, 'paths': paths}, indent=2))
print('A57 tuple arity: PASS; SHA256:', digest)
