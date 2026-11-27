import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
async function freePort() {
  const probe = createServer();
  await new Promise((resolvePromise, reject) => { probe.once('error', reject); probe.listen(0, '127.0.0.1', resolvePromise); });
  const address = probe.address();
  if (!address || typeof address === 'string') throw new Error('Unable to allocate an ephemeral port.');
  await new Promise((resolvePromise, reject) => probe.close((error) => error ? reject(error) : resolvePromise()));
  return address.port;
}
async function waitForHealth(url, child) {
  const deadline = Date.now() + 8000;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`API process exited early: ${child.exitCode}`);
    try { const response = await fetch(`${url}/healthz`); if (response.ok) return; lastError = new Error(`health status ${response.status}`); }
    catch (error) { lastError = error; }
    await delay(80);
  }
  throw new Error(`API did not become healthy: ${lastError}`);
}
test('HTTP API exposes health, enforces exact schema keys and rejects oversized/invalid input', async () => {
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const projectRoot = resolve(new URL('..', import.meta.url).pathname);
  const child = spawn(process.execPath, ['--experimental-strip-types', 'src/server.ts'], { cwd: projectRoot, env: { ...process.env, HOST: '127.0.0.1', PORT: String(port) }, stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  try {
    await waitForHealth(baseUrl, child);
    const health = await fetch(`${baseUrl}/healthz`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).status, 'ok');
    const ready = await fetch(`${baseUrl}/readyz`);
    assert.equal(ready.status, 200);
    assert.equal((await ready.json()).externalDependenciesChecked, false);
    const example = JSON.parse(await readFile(new URL('../examples/release-evaluation-pass.json', import.meta.url), 'utf8'));
    const valid = await fetch(`${baseUrl}/v1/release/evaluate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(example) });
    assert.equal(valid.status, 200);
    assert.equal((await valid.json()).decision, 'ALLOW');
    const extraTopLevel = { ...example, unrecognizedField: true };
    const rejectedTop = await fetch(`${baseUrl}/v1/release/evaluate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(extraTopLevel) });
    assert.equal(rejectedTop.status, 400);
    const extraNested = structuredClone(example);
    extraNested.build.unrecognizedField = true;
    const rejectedNested = await fetch(`${baseUrl}/v1/release/evaluate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(extraNested) });
    assert.equal(rejectedNested.status, 400);
    const unknownSignal = await fetch(`${baseUrl}/v1/changes/classify`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ unknownFlag: true }) });
    assert.equal(unknownSignal.status, 400);
    const malformed = await fetch(`${baseUrl}/v1/release/evaluate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{invalid' });
    assert.equal(malformed.status, 400);
    const oversized = await fetch(`${baseUrl}/v1/release/evaluate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ padding: 'x'.repeat(70_000) }) });
    assert.equal(oversized.status, 413);
  } finally {
    child.kill('SIGTERM');
    await Promise.race([new Promise((resolvePromise) => child.once('exit', resolvePromise)), delay(2000)]);
    if (child.exitCode === null) child.kill('SIGKILL');
  }
  assert.doesNotMatch(stderr, /uncaughtException|UnhandledPromiseRejection/);
});
