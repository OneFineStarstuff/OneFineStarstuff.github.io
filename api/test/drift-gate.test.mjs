/**
 * Drift-gate drill tests (WP-087 rollout phase P1 acceptance criterion:
 * the gate must block an unapproved breaking change in a drill).
 * Fictional governance-simulation artefact.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { classifyDrift } from '../src/drift-gate.mjs';

function baseFixture() {
  return {
    paths: {
      '/healthz': {
        get: {
          operationId: 'getHealth',
          responses: { '200': { description: 'ok' } },
        },
      },
    },
    components: {
      schemas: {
        HealthStatus: {
          type: 'object',
          required: ['status'],
          properties: {
            status: { type: 'string' },
            note: { type: 'string' },
          },
        },
      },
    },
  };
}

test('identical spec vs baseline is GREEN with no changes', () => {
  const result = classifyDrift(baseFixture(), baseFixture());
  assert.equal(result.verdict, 'GREEN');
  assert.equal(result.breaking.length, 0);
  assert.equal(result.nonBreaking.length, 0);
});

test('added path and added optional property are NON-BREAKING', () => {
  const candidate = baseFixture();
  candidate.paths['/v1/compliance'] = {
    get: { operationId: 'getCompliance', responses: { '200': { description: 'ok' } } },
  };
  candidate.components.schemas.HealthStatus.properties.uptimeSeconds = { type: 'number' };
  const result = classifyDrift(baseFixture(), candidate);
  assert.equal(result.verdict, 'GREEN');
  assert.equal(result.breaking.length, 0);
  assert.ok(result.nonBreaking.some((n) => n.includes('added path /v1/compliance')));
  assert.ok(result.nonBreaking.some((n) => n.includes('added optional property HealthStatus.uptimeSeconds')));
});

test('added schema is NON-BREAKING', () => {
  const candidate = baseFixture();
  candidate.components.schemas.ComplianceSummary = {
    type: 'object',
    required: ['regimes'],
    properties: { regimes: { type: 'array' } },
  };
  const result = classifyDrift(baseFixture(), candidate);
  assert.equal(result.verdict, 'GREEN');
  assert.ok(result.nonBreaking.some((n) => n.includes('added schema ComplianceSummary')));
});

test('drill: removed path BLOCKS', () => {
  const candidate = baseFixture();
  delete candidate.paths['/healthz'];
  const result = classifyDrift(baseFixture(), candidate);
  assert.equal(result.verdict, 'BLOCK');
  assert.ok(result.breaking.some((n) => n.includes('removed path /healthz')));
});

test('drill: removed operation BLOCKS', () => {
  const candidate = baseFixture();
  delete candidate.paths['/healthz'].get;
  const result = classifyDrift(baseFixture(), candidate);
  assert.equal(result.verdict, 'BLOCK');
  assert.ok(result.breaking.some((n) => n.includes('removed operation GET /healthz')));
});

test('drill: removed required property BLOCKS', () => {
  const candidate = baseFixture();
  delete candidate.components.schemas.HealthStatus.properties.status;
  const result = classifyDrift(baseFixture(), candidate);
  assert.equal(result.verdict, 'BLOCK');
  assert.ok(result.breaking.some((n) => n.includes('removed required property HealthStatus.status')));
});

test('removed optional property is NON-BREAKING', () => {
  const candidate = baseFixture();
  delete candidate.components.schemas.HealthStatus.properties.note;
  const result = classifyDrift(baseFixture(), candidate);
  assert.equal(result.verdict, 'GREEN');
  assert.ok(result.nonBreaking.some((n) => n.includes('removed optional property HealthStatus.note')));
});

test('drill: changed property type BLOCKS', () => {
  const candidate = baseFixture();
  candidate.components.schemas.HealthStatus.properties.status = { type: 'number' };
  const result = classifyDrift(baseFixture(), candidate);
  assert.equal(result.verdict, 'BLOCK');
  assert.ok(result.breaking.some((n) => n.includes('changed type of HealthStatus.status')));
});

test('drill: added required property BLOCKS', () => {
  const candidate = baseFixture();
  candidate.components.schemas.HealthStatus.properties.mandatoryNote = { type: 'string' };
  candidate.components.schemas.HealthStatus.required.push('mandatoryNote');
  const result = classifyDrift(baseFixture(), candidate);
  assert.equal(result.verdict, 'BLOCK');
  assert.ok(result.breaking.some((n) => n.includes('added required property HealthStatus.mandatoryNote')));
});

test('drill: removed schema BLOCKS', () => {
  const candidate = baseFixture();
  delete candidate.components.schemas.HealthStatus;
  const result = classifyDrift(baseFixture(), candidate);
  assert.equal(result.verdict, 'BLOCK');
  assert.ok(result.breaking.some((n) => n.includes('removed schema HealthStatus')));
});

test('repo sanity: shipped spec matches its baseline snapshot (GREEN)', () => {
  const baseline = JSON.parse(readFileSync('snapshots/openapi.baseline.json', 'utf8'));
  const candidate = JSON.parse(readFileSync('openapi.json', 'utf8'));
  const result = classifyDrift(baseline, candidate);
  assert.equal(result.verdict, 'GREEN');
});
