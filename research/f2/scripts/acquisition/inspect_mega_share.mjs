// Fetch and decrypt a public MEGA file share for offline inspection.
// Does not extract archives or execute downloaded contents.
import { createDecipheriv, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const shareUrl = process.argv[2];
if (!shareUrl) throw new Error('Usage: node inspect_mega_share.mjs <MEGA-file-URL>');
const parsed = new URL(shareUrl);
const id = parsed.pathname.split('/').filter(Boolean).at(-1);
const keyText = parsed.hash.slice(1);
if (parsed.hostname !== 'mega.nz' || !id || !keyText) throw new Error('Expected a complete https://mega.nz/file/<id>#<key> link');

const b64url = (s) => Buffer.from(s.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - s.length % 4) % 4), 'base64');
const linkKey = b64url(keyText);
if (linkKey.length !== 32) throw new Error(`Unexpected share-key length: ${linkKey.length}`);
const xor4 = (a, b) => Buffer.from(a.map((v, i) => v ^ b[i]));
const aesKey = xor4(linkKey.subarray(0, 16), linkKey.subarray(16, 32));
// MEGA file CTR IV is the two IV words (key words 4 and 5), then zero words.
const iv = Buffer.concat([linkKey.subarray(16, 24), Buffer.alloc(8)]);

const apiUrl = `https://g.api.mega.co.nz/cs?id=${randomBytes(6).readUIntBE(0, 6)}`;
const apiResponse = await fetch(apiUrl, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify([{ a: 'g', g: 1, p: id }]),
});
if (!apiResponse.ok) throw new Error(`MEGA API returned HTTP ${apiResponse.status}`);
const [meta] = await apiResponse.json();
if (!meta || typeof meta.g !== 'string' || !Number.isSafeInteger(meta.s)) throw new Error(`Unexpected MEGA response: ${JSON.stringify(meta)}`);
const downloadResponse = await fetch(meta.g);
if (!downloadResponse.ok) throw new Error(`Download returned HTTP ${downloadResponse.status}`);
const encrypted = Buffer.from(await downloadResponse.arrayBuffer());
if (encrypted.length !== meta.s) throw new Error(`Size mismatch: expected ${meta.s}, got ${encrypted.length}`);
const decipher = createDecipheriv('aes-128-ctr', aesKey, iv);
const clear = Buffer.concat([decipher.update(encrypted), decipher.final()]);

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(scriptDir, '../../data/firmware-packages/unverified');
await mkdir(outDir, { recursive: true });
const prefix = clear.subarray(0, 8).toString('hex');
const sig = clear.subarray(0, 7).toString('binary');
const ext = sig.startsWith('Rar!\x1a\x07') ? 'rar' : clear.subarray(0, 4).toString('ascii') === 'PK\x03\x04' ? 'zip' : 'bin';
const output = path.join(outDir, `dzgsm_share_${id}.${ext}`);
await writeFile(output, clear);
console.log(JSON.stringify({ id, encrypted_bytes: encrypted.length, decrypted_bytes: clear.length, header_hex: prefix, output }, null, 2));
