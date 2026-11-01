import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { getReportingWindow } from '../src/reportingWindow.js';

test('reporting window ends at the most recent 09:00 UTC cutoff', () => {
  assert.deepEqual(
    getReportingWindow(new Date('2026-10-28T10:00:00.000Z')),
    { start: '2026-10-27T09:00:00.000Z', end: '2026-10-28T09:00:00.000Z' },
  );
});

test('pre-cutoff run uses the previous completed 24-hour window', () => {
  assert.deepEqual(
    getReportingWindow(new Date('2026-10-28T08:59:59.000Z')),
    { start: '2026-10-26T09:00:00.000Z', end: '2026-10-27T09:00:00.000Z' },
  );
});

test('every seeded risk row is explicitly synthetic and not operationally assessed', async () => {
  const source = await readFile(new URL('../src/data.ts', import.meta.url), 'utf8');
  const start = source.indexOf('export const riskIndices: RiskIndex[] = [');
  const end = source.indexOf('\n];', start);
  assert.ok(start >= 0 && end > start, 'riskIndices block exists');
  const block = source.slice(start, end);
  const rows = block.split('\n').filter(line => /^\s*\{ id:/.test(line));
  assert.equal(rows.length, 12, 'expected all 12 GIEN indices');
  for (const row of rows) {
    assert.match(row, /sourceKind: 'synthetic'/);
    assert.match(row, /assessmentStatus: 'NOT_ASSESSED'/);
    assert.match(row, /evidenceRefs: \[\]/);
    assert.match(row, /observedAt: null/);
  }
});

test('framework coverage and scanner outputs remain unassessed without evidence', async () => {
  const source = await readFile(new URL('../src/data.ts', import.meta.url), 'utf8');
  const start = source.indexOf('export const frameworks: Framework[] = [');
  const end = source.indexOf('\n];', start);
  assert.ok(start >= 0 && end > start, 'frameworks block exists');
  const block = source.slice(start, end);
  const rows = block.split('\n').filter(line => /^\s*\{ id:/.test(line));
  assert.equal(rows.length, 18, 'expected 18 framework records');
  for (const row of rows) {
    assert.match(row, /status: 'NOT ASSESSED'/);
    assert.match(row, /controls: null, total: null/);
    assert.match(row, /oscalSsp: null, oscalAr: null/);
    assert.match(row, /opaViolations: null, opaWarnings: null/);
    assert.match(row, /sourceKind: 'synthetic'/);
    assert.match(row, /evidenceRefs: \[\]/);
    assert.match(row, /applicability: 'PENDING_REVIEW'/);
  }
});

test('frontend evidence adapter verifies digest and audit receipt binding', async () => {
  const source = await readFile(new URL('../src/services/evidenceApi.ts', import.meta.url), 'utf8');
  assert.match(source, /audit\.eventId !== payload\.requestId/);
  assert.match(source, /audit\.snapshotDigest !== payload\.snapshotDigest/);
  assert.match(source, /crypto\.subtle\.digest\('SHA-384'/);
  assert.match(source, /calculatedDigest !== payload\.snapshotDigest/);
});
