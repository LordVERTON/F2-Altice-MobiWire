import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import GHIDRA_REPORTS

ROOT = GHIDRA_REPORTS

def load(build):
    with (ROOT / (build + '_details.jsonl')).open(encoding='utf-8') as src:
        return {f['entry']: f for f in map(json.loads, src)}

if __name__ == '__main__':
    fs = load(sys.argv[1])
    for entry in sys.argv[2:]:
        f = fs.get(entry)
        if f is None:
            print(entry, 'NOT A KNOWN FUNCTION'); continue
        print('\nFUNCTION', entry, 'bytes=', f['bytes'], 'ins=', len(f['instructions']))
        print('INCOMING', f['incoming'])
        print(f.get('decompiled', '(no decompilation)'))
        for i in f['instructions']:
            print(i['address'], i['text'], (' refs=' + str(i['refs'])) if i['refs'] else '')
