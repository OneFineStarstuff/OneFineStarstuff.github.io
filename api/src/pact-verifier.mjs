/**
 * Consumer-driven contract verifier (WP-087 control C2, phase P2 — WP-091).
 *
 * Replays every interaction declared in the consumer pacts
 * (api/pacts/*.pact.json) against the built provider server
 * (api/dist/server.js) and validates both the response status and the
 * payload shape against the OpenAPI 3.1 schema of record
 * (api/openapi.json). On success a verification record is written to the
 * deployment ledger (api/deployments/verifications.json) so the
 * can-i-deploy promotion gate (src/can-i-deploy.mjs) can check it.
 *
 * Broker-less by design (phase P2 constraint): the pact files, the
 * verification records, and the deployment records are the checked-in
 * broker. The record is keyed by a stable SHA-256 digest of the spec so
 * a promotion is only permitted when a fresh verification exists for
 * exactly the spec being promoted.
 *
 * Fictional governance-simulation artefact: all data is simulated.
 */

import { readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

/** Stable JSON canonicalization: object keys sorted recursively. */
export function stableStringify(value) {
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

/** SHA-256 digest of the spec under its canonical (stable) form. */
export function computeSpecDigest(spec) {
  return createHash('sha256').update(stableStringify(spec)).digest('hex');
}

export function loadOpenApiSpec(specPath = 'openapi.json') {
  return JSON.parse(readFileSync(specPath, 'utf8'));
}

/** Resolve a local $ref like #/components/schemas/HealthStatus. */
export function resolveRef(ref, spec) {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) {
    throw new Error('only local references are supported, got: ' + String(ref));
  }
  let node = spec;
  for (const segment of ref.slice(2).split('/')) {
    node = node[segment];
    if (node === undefined) {
      throw new Error('unresolvable reference: ' + ref);
    }
  }
  return node;
}

export function assertRequiredPresent(container, schema, label) {
  for (const name of schema.required ?? []) {
    if (!(name in container)) {
      throw new Error(label + '.' + name + ' is required by the contract but missing from the payload');
    }
  }
}

export function assertTypesMatch(container, schema, label, resolve) {
  if (schema && schema.$ref) {
    if (!resolve) {
      throw new Error('reference encountered but no resolver provided at ' + label);
    }
    schema = resolve(schema.$ref);
  }
  if (schema.type === 'array') {
    if (!Array.isArray(container)) {
      throw new Error(label + ' must be an array');
    }
    container.forEach((item, index) =>
      assertTypesMatch(item, schema.items ?? {}, label + '[' + index + ']', resolve)
    );
    return;
  }
  if (schema.type === 'object') {
    if (typeof container !== 'object' || container === null || Array.isArray(container)) {
      throw new Error(label + ' must be an object');
    }
    assertRequiredPresent(container, schema, label);
    for (const [name, property] of Object.entries(schema.properties ?? {})) {
      if (!(name in container)) {
        continue;
      }
      assertTypesMatch(container[name], property, label + '.' + name, resolve);
    }
    return;
  }
  const value = container;
  if (schema.type === 'string' && typeof value !== 'string') {
    throw new Error(label + ' must be a string');
  }
  if (schema.type === 'number' && typeof value !== 'number') {
    throw new Error(label + ' must be a number');
  }
  if (schema.type === 'boolean' && typeof value !== 'boolean') {
    throw new Error(label + ' must be a boolean');
  }
  if (schema.enum && !schema.enum.includes(value)) {
    throw new Error(label + ' must be one of ' + schema.enum.join(', '));
  }
}

/**
 * Validate one response body against the declared schema of the
 * interaction (a local $ref or an inline schema).
 */
export function validateBody(body, responseSchema, spec, label) {
  const schema = responseSchema && responseSchema.$ref ? resolveRef(responseSchema.$ref, spec) : responseSchema;
  assertTypesMatch(body, schema, label, (ref) => resolveRef(ref, spec));
}

/**
 * Verify one interaction against one observed provider response.
 * Pure: no I/O, throws nothing (collects failures).
 */
export function verifyInteraction(interaction, observed, spec) {
  const failures = [];
  if (observed.status !== interaction.response.status) {
    failures.push(
      'expected status ' + interaction.response.status + ' but provider returned ' + observed.status
    );
  }
  if (interaction.response.schema) {
    try {
      validateBody(observed.body, interaction.response.schema, spec, interaction.description);
    } catch (err) {
      failures.push(err.message);
    }
  }
  return { description: interaction.description, ok: failures.length === 0, failures };
}

/**
 * Verify a whole pact against a response map keyed by 'METHOD path'.
 * Pure: returns a verdict object.
 */
export function verifyPact(pact, responses, spec) {
  const results = [];
  for (const interaction of pact.interactions) {
    const key = interaction.request.method + ' ' + interaction.request.path;
    const observed = responses[key];
    if (!observed) {
      results.push({
        description: interaction.description,
        ok: false,
        failures: ['no observed provider response for ' + key],
      });
      continue;
    }
    results.push(verifyInteraction(interaction, observed, spec));
  }
  return {
    consumer: pact.consumer.name,
    provider: pact.provider.name,
    verdict: results.every((r) => r.ok) ? 'PASS' : 'FAIL',
    results,
  };
}

export function loadPacts(pactsDir = 'pacts') {
  return readdirSync(pactsDir)
    .filter((name) => name.endsWith('.pact.json'))
    .map((name) => JSON.parse(readFileSync(pactsDir + '/' + name, 'utf8')));
}

export function deployDir() {
  return process.env.GIEN_DEPLOY_DIR ?? 'deployments';
}

export function loadVerifications(dir) {
  const path = dir + '/verifications.json';
  if (!existsSync(path)) {
    return { records: [] };
  }
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Persist the verification record for one consumer (idempotent per consumer). */
export function recordVerification(dir, record) {
  mkdirSync(dir, { recursive: true });
  const ledger = loadVerifications(dir);
  const others = ledger.records.filter((r) => r.consumer !== record.consumer);
  const records = [...others, record].sort((a, b) => a.consumer.localeCompare(b.consumer));
  writeFileSync(dir + '/verifications.json', JSON.stringify({ records }, null, 2) + '\n');
}

/** Fetch every pact interaction from a live provider. */
export async function fetchResponses(interactions, baseUrl) {
  const responses = {};
  for (const interaction of interactions) {
    const url = baseUrl + interaction.request.path;
    const res = await fetch(url, { method: interaction.request.method });
    let body = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    responses[interaction.request.method + ' ' + interaction.request.path] = { status: res.status, body };
  }
  return responses;
}

async function waitForServer(baseUrl) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const res = await fetch(baseUrl + '/healthz');
      if (res.ok) {
        return true;
      }
    } catch {
      // server not up yet
    }
    await delay(1000);
  }
  return false;
}

export async function main() {
  const spec = loadOpenApiSpec();
  const specDigest = computeSpecDigest(spec);
  const pacts = loadPacts('pacts');
  if (pacts.length === 0) {
    console.error('No consumer pacts found under api/pacts/ — nothing to verify.');
    process.exit(1);
  }

  const port = Number(process.env.GIEN_PACT_PORT ?? 4193);
  const server = spawn('node', ['dist/server.js'], {
    env: { ...process.env, PORT: String(port) },
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  const baseUrl = 'http://127.0.0.1:' + port;

  let overall = 'PASS';
  try {
    if (!(await waitForServer(baseUrl))) {
      console.error('Provider server did not become healthy at ' + baseUrl + '/healthz');
      process.exitCode = 1;
      return;
    }
    for (const pact of pacts) {
      const responses = await fetchResponses(pact.interactions, baseUrl);
      const result = verifyPact(pact, responses, spec);
      for (const r of result.results) {
        if (r.ok) {
          console.log('PASS: ' + pact.consumer.name + ' — ' + r.description);
        } else {
          for (const failure of r.failures) {
            console.error('FAIL: ' + pact.consumer.name + ' — ' + r.description + ': ' + failure);
          }
        }
      }
      if (result.verdict === 'PASS') {
        recordVerification(deployDir(), {
          consumer: pact.consumer.name,
          provider: pact.provider.name,
          specDigest,
          result: 'PASS',
          verifiedAt: new Date().toISOString(),
          interactionsPassed: result.results.length,
          interactionsTotal: pact.interactions.length,
        });
        console.log('Contract verification PASS for consumer ' + pact.consumer.name + ' (record written for digest ' + specDigest.slice(0, 12) + '...)');
      } else {
        overall = 'FAIL';
        console.error('Contract verification FAIL for consumer ' + pact.consumer.name);
      }
    }
  } finally {
    server.kill('SIGTERM');
  }

  if (overall !== 'PASS') {
    console.error('One or more consumer pacts failed against the provider. Promotion is blocked.');
    process.exitCode = 1;
    return;
  }
  console.log('All consumer pacts verified against spec digest ' + specDigest.slice(0, 12) + '... — safe to consult can-i-deploy.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
