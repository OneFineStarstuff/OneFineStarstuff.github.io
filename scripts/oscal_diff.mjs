#!/usr/bin/env node
// A7 (WP-114): Delta_OSCAL diff between two operational-catalog snapshots.
// Usage: node scripts/oscal_diff.mjs prev.json next.json [--allow]
// Snapshot shape: { rev: '1165', regimes: { 'EU AI Act': ['EUAI-01'], 'DORA': ['DORA-01'] } }
// Exit codes: 0 no drift; 2 drift without --allow; 3 usage error.
import { readFileSync } from 'node:fs';

const [prevPath, nextPath] = process.argv.slice(2, 4);
const allow = process.argv.includes('--allow');
if (!prevPath || !nextPath) {
  console.error('usage: node scripts/oscal_diff.mjs <prev.json> <next.json> [--allow]');
  process.exit(3);
}
const prev = JSON.parse(readFileSync(prevPath, 'utf-8'));
const next = JSON.parse(readFileSync(nextPath, 'utf-8'));
const focus = ['EU AI Act', 'DORA'];
let drift = 0;
for (const regime of focus) {
  const a = new Set(prev.regimes?.[regime] ?? []);
  const b = new Set(next.regimes?.[regime] ?? []);
  const added = [...b].filter((x) => !a.has(x));
  const removed = [...a].filter((x) => !b.has(x));
  if (added.length || removed.length) drift++;
  console.log('Delta_OSCAL ' + regime + ': +' + added.length + ' / -' + removed.length);
  added.forEach((c) => console.log('  + ' + c));
  removed.forEach((c) => console.log('  - ' + c));
}
console.log('Delta_OSCAL: rev ' + prev.rev + ' -> ' + next.rev + ' (' + (prev.rev !== next.rev ? 'changed' : 'unchanged') + '), drift regimes: ' + drift);
process.exit(drift && !allow ? 2 : 0);
