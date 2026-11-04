/**
 * Schema-first consistency tests: sample server payloads must satisfy the
 * OpenAPI schema of record (required properties present, primitive types
 * matching). This is the WP-087 C1 discipline that keeps src/types.ts and
 * the seeded server data honest against api/openapi.json.
 * Fictional governance-simulation artefact.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const spec = JSON.parse(readFileSync('openapi.json', 'utf8'));
const schemas = spec.components.schemas;

const samples = {
  health: {
    status: 'ok',
    service: 'gien-governance-telemetry-api',
    simulation: true,
    uptimeSeconds: 12,
  },
  window: {
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
  },
  compliance: {
    catalogRevision: 1164,
    simulation: true,
    regimes: [
      { framework: 'EU AI Act', result: 'PASS' },
      { framework: 'GDPR', result: 'PASS' },
    ],
  },
  incident: {
    incidentId: 'GIEN-INC-2026-308-01',
    openedUtc: '2026-11-03T14:02:00Z',
    classification: 'asa-drift-contained',
    status: 'contained',
    wormSealed: true,
  },
};

function assertRequiredPresent(container, schema, label) {
  for (const name of schema.required ?? []) {
    assert.ok(name in container, `${label}.${name} is required by the spec but missing from the payload`);
  }
}

function assertTypesMatch(container, schema, label) {
  for (const [name, property] of Object.entries(schema.properties ?? {})) {
    if (!(name in container)) {
      continue;
    }
    const value = container[name];
    if (property.type === 'string') {
      assert.equal(typeof value, 'string', `${label}.${name} must be a string`);
    } else if (property.type === 'number') {
      assert.equal(typeof value, 'number', `${label}.${name} must be a number`);
    } else if (property.type === 'boolean') {
      assert.equal(typeof value, 'boolean', `${label}.${name} must be a boolean`);
    } else if (property.type === 'object') {
      assert.equal(typeof value, 'object', `${label}.${name} must be an object`);
      assert.ok(!Array.isArray(value), `${label}.${name} must not be an array`);
    } else if (property.type === 'array') {
      assert.ok(Array.isArray(value), `${label}.${name} must be an array`);
    }
    if (property.enum) {
      assert.ok(property.enum.includes(value), `${label}.${name} must be one of ${property.enum.join(', ')}`);
    }
  }
}

test('spec structure: every operation has an operationId and responses', () => {
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(item)) {
      if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) {
        continue;
      }
      assert.ok(op.operationId, `${method.toUpperCase()} ${path} needs an operationId`);
      assert.ok(op.responses, `${method.toUpperCase()} ${path} needs responses`);
    }
  }
});

test('HealthStatus payload satisfies the schema of record', () => {
  assertRequiredPresent(samples.health, schemas.HealthStatus, 'HealthStatus');
  assertTypesMatch(samples.health, schemas.HealthStatus, 'HealthStatus');
});

test('SupervisoryWindow payload satisfies the schema of record (including nested telemetry/evidence)', () => {
  assertRequiredPresent(samples.window, schemas.SupervisoryWindow, 'SupervisoryWindow');
  assertTypesMatch(samples.window, schemas.SupervisoryWindow, 'SupervisoryWindow');
  const telemetrySchema = schemas.SupervisoryWindow.properties.telemetry;
  const evidenceSchema = schemas.SupervisoryWindow.properties.evidence;
  assertRequiredPresent(samples.window.telemetry, telemetrySchema, 'SupervisoryWindow.telemetry');
  assertTypesMatch(samples.window.telemetry, telemetrySchema, 'SupervisoryWindow.telemetry');
  assertRequiredPresent(samples.window.evidence, evidenceSchema, 'SupervisoryWindow.evidence');
  assertTypesMatch(samples.window.evidence, evidenceSchema, 'SupervisoryWindow.evidence');
  assert.match(samples.window.windowId, new RegExp(schemas.SupervisoryWindow.properties.windowId.pattern));
  assert.match(samples.window.evidence.merkleRoot, /^0x[0-9a-f]{64}$/);
});

test('ComplianceSummary payload satisfies the schema of record', () => {
  assertRequiredPresent(samples.compliance, schemas.ComplianceSummary, 'ComplianceSummary');
  assertTypesMatch(samples.compliance, schemas.ComplianceSummary, 'ComplianceSummary');
  const regimeSchema = schemas.ComplianceSummary.properties.regimes.items;
  for (const regime of samples.compliance.regimes) {
    assertRequiredPresent(regime, regimeSchema, 'regimes[]');
    assertTypesMatch(regime, regimeSchema, 'regimes[]');
  }
});

test('IncidentRecord payload satisfies the schema of record', () => {
  assertRequiredPresent(samples.incident, schemas.IncidentRecord, 'IncidentRecord');
  assertTypesMatch(samples.incident, schemas.IncidentRecord, 'IncidentRecord');
});
