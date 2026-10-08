import hashlib
import json
from pathlib import Path
import sys
import uuid

root = Path(r'C:\Users\verto\F2-Altice-MobiWire')
sys.path.insert(0, str(root / 'research/f2/automation/bridge'))
from notion_queue import NotionQueue, environment, identifier, prop, rich, BridgeError, safe_text
from notion_worker import validate, Mutex

state = Path(__file__).resolve().parent
secret = environment('F2_NOTION_TOKEN')
try:
    q = NotionQueue(secret, '1bcea051-574f-40f5-ab62-d98debf41cb4')
    page_id = '3f2173c5-7e04-8153-ac83-e14ec5522ace'
    job = 's13_5a57_86c0_8928_mapper_owner_differential'
    script = (state / 'corrected/script.py').read_bytes()
    raw = (state / 'corrected/job.json').read_bytes()
    digest = hashlib.sha256(script).hexdigest()
    assert json.loads(raw)['script_sha256'] == digest
    with Mutex():
        assert (root / 'research/f2/automation/bridge/STOP').exists()
        assert (root / 'research/f2/automation/bridge/ORCHESTRATOR_STOP').exists()
        page = q.page(page_id)
        assert prop(page, 'Job ID') == job and prop(page, 'Status', 'select') == 'FAILED'
        assert prop(page, 'Next Job ID') == ''
        assert not any(b['type'] == 'file' for b in q.blocks(page_id))
        page['properties']['Script SHA256'] = rich(digest)
        validate(page, raw, script, root)
        # Notion stores Python source as text/plain (.txt), exposed as script.py.
        upload = q.request('POST', 'file_uploads', {'mode': 'single_part', 'filename': 'script.txt', 'content_type': 'text/plain'})
        file_id = identifier(upload['id'])
        boundary = 'F2A57Repair' + uuid.uuid4().hex
        content = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="script.txt"\r\nContent-Type: text/plain\r\n\r\n'.encode()
                   + script + f'\r\n--{boundary}--\r\n'.encode())
        q.request('POST', f'file_uploads/{file_id}/send', raw=content, content_type='multipart/form-data; boundary=' + boundary)
        files = [{'name': 'script.py', 'type': 'file_upload', 'file_upload': {'id': file_id}}, q.upload('job.json', raw)]
        updates = {'Files': {'files': files}, 'Script SHA256': rich(digest),
                   'Status': {'select': {'name': 'QUEUED'}}, 'Review Status': {'select': {'name': 'PENDING'}},
                   'Error': rich(''), 'Claim Token': rich(''), 'Worker Host': rich(''),
                   'Result Commit': rich(''), 'Exit Code': {'number': None}}
        q.request('PATCH', 'pages/' + page_id, {'properties': updates})
        page = q.page(page_id)
        assert prop(page, 'Status', 'select') == 'QUEUED'
        assert prop(page, 'Review Status', 'select') == 'PENDING'
        attachments = q.attachments(page)
        downloaded_script = q.download(attachments['script.py'], 100000)
        downloaded_manifest = q.download(attachments['job.json'], 20000)
        assert downloaded_script == script and downloaded_manifest == raw
        validate(page, downloaded_manifest, downloaded_script, root)
        print('Existing A57 page: QUEUED/PENDING; corrected attachments and safety verified')
        print('SHA256:', digest)
except BridgeError as exc:
    print(safe_text(exc, secret))
    raise SystemExit(1)
