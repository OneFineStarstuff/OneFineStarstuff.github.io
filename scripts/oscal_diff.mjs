#!/usr/bin/env node
// A7 (WP-114): Delta_OSCAL diff between two crosswalk snapshots.
// Usage: node scripts/oscal_diff.mjs prev.yaml next.yaml [--allow]
// Supports the current YAML crosswalk shape and legacy JSON snapshots.
import { readFileSync } from 'node:fs';
import YAML from 'yaml';

const [prevPath, nextPath] = process.argv.slice(2, 4);
const allow = process.argv.includes('--allow');

if (!prevPath || !nextPath) {
  console.error('usage: node scripts/oscal_diff.mjs <prev.yaml|json> <next.yaml|json> [--allow]');
  process.exit(3);
}

function parseSnapshot(path) {
  const raw = readFileSync(path, 'utf-8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = YAML.parse(raw);
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.regimes) {
    throw new Error('Invalid crosswalk snapshot: ' + path);
  }
  if (Array.isArray(parsed.regimes)) {
    const regimes = Object.fromEntries(parsed.regimes.map((regime) => [
      regime.name,
      (regime.controls ?? []).map((control) => control.oscal),
    ]));
    return { rev: String(parsed.catalog_rev ?? parsed.version ?? 'unknown'), regimes };
  }
  return { rev: String(parsed.rev ?? parsed.catalog_rev ?? 'unknown'), regimes: parsed.regimes };
}

const prev = parseSnapshot(prevPath);
const next = parseSnapshot(nextPath);
const names = [...new Set([...Object.keys(prev.regimes), ...Object.keys(next.regimes)])]
  .sort((a, b) => a.localeCompare(b));
let drift = 0;

for (const regime of names) {
  const before = new Set(prev.regimes[regime] ?? []);
  const after = new Set(next.regimes[regime] ?? []);
  const added = [...after].filter((control) => !before.has(control)).sort();
  const removed = [...before].filter((control) => !after.has(control)).sort();
  if (added.length || removed.length) drift++;
  console.log('Delta_OSCAL ' + regime + ': +' + added.length + ' / -' + removed.length);
  added.forEach((control) => console.log('  + ' + control));
  removed.forEach((control) => console.log('  - ' + control));
}

console.log('Delta_OSCAL: rev ' + prev.rev + ' -> ' + next.rev + ', drift regimes: ' + drift);
process.exit(drift && !allow ? 2 : 0);
