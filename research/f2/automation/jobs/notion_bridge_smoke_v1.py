import os
from pathlib import Path

print('NOTION BRIDGE SMOKE TEST')
print('cwd:', Path.cwd())
print('offline:', os.environ.get('F2_AUTOMATION_OFFLINE'))
assert os.environ.get('F2_AUTOMATION_OFFLINE') == '1'
assert Path('research/f2').is_dir()
assert 'F2_NOTION_TOKEN' not in os.environ
print('NOTION BRIDGE SMOKE = PASS')
