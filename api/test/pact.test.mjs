/**
 * WP-091 (WP-087 phase P2) contract-testing and promotion-gate drills.
 *
 * Covers: pact file structure, verification against golden provider
 * responses, failure detection (status mismatch, missing required
 * property, wrong type, unobserved interaction), the can-i-deploy
 * promotion decision (missing / stale verification records, drift-gate
 * interaction, four-eyes approval), deployment-record idempotence, and
 * the P2 acceptance criterion: an unverified consumer blocks promotion.
 *
 * Fictional governance-simulation artefact.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  stableStringify,
  computeSpecDigest,
  verifyPact,
  verifyInteraction,
  recordVerification,
  loadVerifications,
} from '../src/pact-verifier.mjs';
import { evaluatePromotion, recordDeployment, loadDeploymentRecords } from '../src/can-i-deploy.mjs';

const spec = JSON.parse(readFileSync('openapi.json', 'utf8'));
const pact = JSON.parse(readFileSync('pacts/gien-dashboard.pact.json', 'utf8'));

const sealedWindow = {
  windowId: '2026-308',
  windowCloseUtc: '2026-11-04T09:00:00Z',
  simulation: true,
  telemetry: {
    s_sys: 0.185,
    g_sri: 26.8,
    c_sri: 17.2,
    g_sri_vii: 29.4,
    a_sri: 20.4,
    p_sri: 15.7,
    cgr_i: 20.2,
    ccr_i: 18.8,
    p_doom: 0.0021,
    p_doom_kernel: 0.0006,
    delta_drift: 0.0,
    delta_oscal: 0,
  },
  evidence: {
    merkleRoot: '0xa3f6c81d9b4e27505fae3c19d86b0742ef5a9c31b8d04f2c7e6a95d3f8b21c04',
    artefactsSealed: 26,
  },
};

function goldenResponses() {
  return {
    'GET /healthz': {
      status: 200,
      body: { status: 'ok', service: 'gien-governance-telemetry-api', simulation: true, uptimeSeconds: 12 },
    },
    'GET /v1/window/latest': { status: 200, body: sealedWindow },
    'GET /v1/window/2026-308': { status: 200, body: sealedWindow },
    'GET /v1/window/2026-999': {
      status: 404,
      body: { error: 'unknown window', windowId: '2026-999' },
    },
    'GET /v1/compliance': {
      status: 200,
      body: {
        catalogRevision: 1164,
        simulation: true,
        regimes: [
          { framework: 'EU AI Act', result: 'PASS' },
          { framework: 'GDPR', result: 'PASS' },
        ],
      },
    },
    'GET /v1/incidents': {
      status: 200,
      body: [
        {
          incidentId: 'GIEN-INC-2026-308-01',
          openedUtc: '2026-11-03T14:02:00Z',
          classification: 'asa-drift-contained',
          status: 'contained',
          wormSealed: true,
        },
      ],
    },
    'GET /v1/not-a-route': { status: 404, body: { error: 'not found', path: '/v1/not-a-route' } },
    'POST /healthz': { status: 405, body: { error: 'method not allowed', method: 'POST' } },
  };
}

test('pact file structure: consumer, provider, and well-formed interactions', () => {
  assert.ok(pact.consumer && pact.consumer.name, 'pact needs a consumer name');
  assert.ok(pact.provider && pact.provider.name, 'pact needs a provider name');
  assert.ok(Array.isArray(pact.interactions) && pact.interactions.length > 0, 'pact needs interactions');
  for (const interaction of pact.interactions) {
    assert.ok(interaction.description, 'each interaction needs a description');
    assert.ok(interaction.request && interaction.request.method && interaction.request.path, 'each interaction needs a method and path');
    assert.ok(interaction.response && typeof interaction.response.status === 'number', 'each interaction needs a response status');
    assert.ok(interaction.response.schema, 'each interaction needs a response schema');
  }
});

test('verification PASSes all interactions against golden provider responses', () => {
  const result = verifyPact(pact, goldenResponses(), spec);
  assert.equal(result.verdict, 'PASS');
  assert.equal(result.results.length, pact.interactions.length);
});

test('verification FAILs on status mismatch', () => {
  const responses = goldenResponses();
  responses['GET /healthz'] = { status: 500, body: { status: 'ok' } };
  const result = verifyPact(pact, responses, spec);
  assert.equal(result.verdict, 'FAIL');
  const health = result.results.find((r) => r.description === 'a health probe');
  assert.ok(health.failures.some((f) => f.includes('expected status 200')));
});

test('verification FAILs when a required property is missing from the payload', () => {
  const responses = goldenResponses();
  responses['GET /v1/window/latest'] = { status: 200, body: { windowId: '2026-308' } };
  const result = verifyPact(pact, responses, spec);
  assert.equal(result.verdict, 'FAIL');
  const window = result.results.find((r) => r.description === 'the latest supervisory window');
  assert.ok(window.failures.some((f) => f.includes('required by the contract')));
});

test('verification FAILs on wrong primitive type', () => {
  const responses = goldenResponses();
  const tampered = { status: 200, body: { ...sealedWindow, telemetry: { ...sealedWindow.telemetry, s_sys: '0.185' } } };
  responses['GET /v1/window/latest'] = tampered;
  const result = verifyPact(pact, responses, spec);
  assert.equal(result.verdict, 'FAIL');
  const window = result.results.find((r) => r.description === 'the latest supervisory window');
  assert.ok(window.failures.some((f) => f.includes('must be a number')));
});

test('verification FAILs when an interaction has no observed provider response', () => {
  const responses = goldenResponses();
  delete responses['GET /v1/compliance'];
  const result = verifyPact(pact, responses, spec);
  assert.equal(result.verdict, 'FAIL');
  const compliance = result.results.find((r) => r.description === 'the compliance summary across the 16-regime crosswalk');
  assert.ok(compliance.failures.some((f) => f.includes('no observed provider response')));
});

test('verifyInteraction handles array payloads with $ref items (positive and negative)', () => {
  const interaction = pact.interactions.find((i) => i.description === 'the incident register');
  const observed = goldenResponses()['GET /v1/incidents'];
  assert.equal(verifyInteraction(interaction, observed, spec).ok, true);
  const tampered = {
    status: 200,
    body: [
      {
        incidentId: 'GIEN-INC-2026-308-01',
        openedUtc: '2026-11-03T14:02:00Z',
        classification: 'asa-drift-contained',
        status: 42,
        wormSealed: true,
      },
    ],
  };
  const failed = verifyInteraction(interaction, tampered, spec);
  assert.equal(failed.ok, false);
  assert.ok(failed.failures.some((f) => f.includes('must be a string')));
});

test('can-i-deploy BLOCKs when no verification record exists for the current digest', () => {
  const specDigest = computeSpecDigest(spec);
  const decision = evaluatePromotion({
    driftVerdict: 'GREEN',
    consumers: ['gien-platform-dashboard'],
    verifications: { records: [] },
    specDigest,
  });
  assert.equal(decision.verdict, 'BLOCK');
  assert.ok(decision.reasons.some((r) => r.includes('no passing contract verification')));
});

test('P2 acceptance criterion: an unverified consumer blocks promotion even with drift GREEN', () => {
  const specDigest = computeSpecDigest(spec);
  const decision = evaluatePromotion({
    driftVerdict: 'GREEN',
    consumers: ['gien-platform-dashboard', 'gien-regulator-export'],
    verifications: {
      records: [
        { consumer: 'gien-platform-dashboard', specDigest, result: 'PASS' },
      ],
    },
    specDigest,
  });
  assert.equal(decision.verdict, 'BLOCK');
  assert.ok(decision.reasons.some((r) => r.includes('gien-regulator-export')));
});

test('a stale verification record (different digest) BLOCKs promotion', () => {
  const specDigest = computeSpecDigest(spec);
  const decision = evaluatePromotion({
    driftVerdict: 'GREEN',
    consumers: ['gien-platform-dashboard'],
    verifications: {
      records: [
        { consumer: 'gien-platform-dashboard', specDigest: 'f'.repeat(64), result: 'PASS' },
      ],
    },
    specDigest,
  });
  assert.equal(decision.verdict, 'BLOCK');
  assert.ok(decision.reasons.some((r) => r.includes('stale or missing')));
});

test('a failed verification record does not count as passing', () => {
  const specDigest = computeSpecDigest(spec);
  const decision = evaluatePromotion({
    driftVerdict: 'GREEN',
    consumers: ['gien-platform-dashboard'],
    verifications: {
      records: [
        { consumer: 'gien-platform-dashboard', specDigest, result: 'FAIL' },
      ],
    },
    specDigest,
  });
  assert.equal(decision.verdict, 'BLOCK');
});

test('drift-gate BLOCK propagates to the promotion decision', () => {
  const specDigest = computeSpecDigest(spec);
  const decision = evaluatePromotion({
    driftVerdict: 'BLOCK',
    consumers: ['gien-platform-dashboard'],
    verifications: {
      records: [
        { consumer: 'gien-platform-dashboard', specDigest, result: 'PASS' },
      ],
    },
    specDigest,
  });
  assert.equal(decision.verdict, 'BLOCK');
  assert.ok(decision.reasons.some((r) => r.includes('drift gate is BLOCK')));
});

test('can-i-deploy PASSes with drift GREEN and fresh verifications for all consumers', () => {
  const specDigest = computeSpecDigest(spec);
  const decision = evaluatePromotion({
    driftVerdict: 'GREEN',
    consumers: ['gien-platform-dashboard'],
    verifications: {
      records: [
        { consumer: 'gien-platform-dashboard', specDigest, result: 'PASS' },
      ],
    },
    specDigest,
  });
  assert.equal(decision.verdict, 'PASS');
  assert.equal(decision.reasons.length, 0);
});

test('four-eyes APPROVED drift still requires fresh consumer verifications', () => {
  const specDigest = computeSpecDigest(spec);
  const decision = evaluatePromotion({
    driftVerdict: 'APPROVED',
    consumers: ['gien-platform-dashboard'],
    verifications: { records: [] },
    specDigest,
  });
  assert.equal(decision.verdict, 'BLOCK');
  assert.ok(decision.reasons.every((r) => !r.includes('drift gate')));
});

test('recordVerification is idempotent per consumer and readable back', () => {
  const dir = mkdtempSync(join(tmpdir(), 'gien-pact-'));
  recordVerification(dir, { consumer: 'a', specDigest: 'd1', result: 'PASS', verifiedAt: '2026-11-05T09:00:00Z' });
  recordVerification(dir, { consumer: 'b', specDigest: 'd2', result: 'PASS', verifiedAt: '2026-11-05T09:01:00Z' });
  recordVerification(dir, { consumer: 'a', specDigest: 'd3', result: 'PASS', verifiedAt: '2026-11-05T09:02:00Z' });
  const ledger = loadVerifications(dir);
  assert.equal(ledger.records.length, 2);
  const a = ledger.records.find((r) => r.consumer === 'a');
  assert.equal(a.specDigest, 'd3');
});

test('recordDeployment is idempotent per environment + digest', () => {
  const dir = mkdtempSync(join(tmpdir(), 'gien-deploy-'));
  recordDeployment(dir, { environment: 'production', specDigest: 'd1', deployedAt: '2026-11-05T09:00:00Z', actor: 'ci' });
  recordDeployment(dir, { environment: 'production', specDigest: 'd2', deployedAt: '2026-11-05T10:00:00Z', actor: 'ci' });
  recordDeployment(dir, { environment: 'production', specDigest: 'd2', deployedAt: '2026-11-05T11:00:00Z', actor: 'ci-2' });
  const ledger = loadDeploymentRecords(dir);
  assert.equal(ledger.records.length, 2);
  const latest = ledger.records.find((r) => r.specDigest === 'd2');
  assert.equal(latest.actor, 'ci-2');
});

test('computeSpecDigest is stable under key reordering', () => {
  const a = { x: 1, y: { b: 2, a: 3 }, z: [1, { q: 4, p: 5 }] };
  const b = JSON.parse(stableStringify({ z: [1, { p: 5, q: 4 }], y: { a: 3, b: 2 }, x: 1 }));
  assert.equal(computeSpecDigest(a), computeSpecDigest(b));
});
