import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, relative, sep } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const manifestPath = resolve(root, 'manifest.txt');
const expected = (await readFile(manifestPath, 'utf8'))
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith('#'));
const seen = new Set();
for (const entry of expected) {
  if (entry.startsWith('/') || entry.split('/').some((part) => part === '..' || part === '.')) {
    throw new Error(`Unsafe manifest path: ${entry}`);
  }
  if (seen.has(entry)) throw new Error(`Duplicate manifest entry: ${entry}`);
  seen.add(entry);
  const file = resolve(root, entry);
  const rel = relative(root, file);
  if (rel.startsWith(`..${sep}`) || rel === '..') throw new Error(`Manifest path escapes repository: ${entry}`);
  const info = await stat(file).catch(() => null);
  if (!info?.isFile() || info.size === 0) throw new Error(`Missing or empty manifest file: ${entry}`);
}
console.log(`PASS: ${expected.length} manifest files exist and are non-empty.`);
