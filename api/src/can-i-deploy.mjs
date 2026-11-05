/**
 * can-i-deploy promotion gate (WP-087 control C2, phase P2 — WP-091).
 *
 * Broker-less analogue of `pact-broker can-i-deploy`: answers "is it safe
 * to deploy the current candidate spec to environment E?" by checking
 * that
 *
 *   (a) the schema drift gate (WP-087 C1, src/drift-gate.mjs) is GREEN
 *       against the approved baseline snapshot — or APPROVED via the
 *       GIEN_APPROVE_BREAKING=1 four-eyes override — and
 *   (b) every registered consumer pact has a PASS verification record
 *       (api/deployments/verifications.json) whose spec digest matches
 *       exactly the spec being promoted. A verification recorded against
 *       an older digest is stale and blocks promotion.
 *
 * With --record-deployment, a passing gate appends an idempotent
 * deployment record to api/deployments/records.json (the WORM-committed
 * promotion ledger in enterprise mode).
 *
 * Fictional governance-simulation artefact: all data is simulated.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { classifyDrift } from './drift-gate.mjs';
import { computeSpecDigest, loadOpenApiSpec, loadPacts, deployDir, loadVerifications } from './pact-verifier.mjs';

/**
 * Pure promotion decision. Inputs are plain data so the gate logic is
 * fully unit-testable.
 */
export function evaluatePromotion({ driftVerdict, consumers, verifications, specDigest }) {
  const reasons = [];
  if (driftVerdict === 'BLOCK') {
    reasons.push('schema drift gate is BLOCK: unapproved breaking change against the baseline snapshot');
  }
  for (const consumer of consumers) {
    const fresh = verifications.records.find(
      (r) => r.consumer === consumer && r.specDigest === specDigest && r.result === 'PASS'
    );
    if (!fresh) {
      reasons.push(
        'no passing contract verification for consumer ' +
          consumer +
          ' against spec digest ' +
          specDigest.slice(0, 12) +
          '... (stale or missing record blocks promotion)'
      );
    }
  }
  return { verdict: reasons.length === 0 ? 'PASS' : 'BLOCK', reasons };
}

export function loadDeploymentRecords(dir) {
  const path = dir + '/records.json';
  if (!existsSync(path)) {
    return { records: [] };
  }
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Append (idempotently, per environment + digest) a deployment record. */
export function recordDeployment(dir, record) {
  mkdirSync(dir, { recursive: true });
  const ledger = loadDeploymentRecords(dir);
  const others = ledger.records.filter(
    (r) => !(r.environment === record.environment && r.specDigest === record.specDigest)
  );
  const records = [...others, record].sort(
    (a, b) => String(a.deployedAt).localeCompare(String(b.deployedAt))
  );
  writeFileSync(dir + '/records.json', JSON.stringify({ records }, null, 2) + '\n');
}

function parseArgs(argv) {
  const args = { environment: null, recordDeployment: false, actor: process.env.GIEN_ACTOR ?? 'ci' };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--environment' && i + 1 < argv.length) {
      args.environment = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--record-deployment') {
      args.recordDeployment = true;
    } else if (argv[i] === '--actor' && i + 1 < argv.length) {
      args.actor = argv[i + 1];
      i += 1;
    }
  }
  return args;
}

export async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.environment) {
    console.error('Usage: node src/can-i-deploy.mjs --environment <env> [--record-deployment] [--actor <name>]');
    process.exit(1);
  }

  const spec = loadOpenApiSpec();
  const specDigest = computeSpecDigest(spec);
  const baseline = JSON.parse(readFileSync('snapshots/openapi.baseline.json', 'utf8'));
  const drift = classifyDrift(baseline, spec);
  const approved = drift.verdict === 'BLOCK' && process.env.GIEN_APPROVE_BREAKING === '1';
  const driftVerdict = drift.verdict === 'BLOCK' && approved ? 'APPROVED' : drift.verdict;

  for (const note of drift.nonBreaking) {
    console.log('NON-BREAKING: ' + note);
  }
  for (const note of drift.breaking) {
    console.log('BREAKING: ' + note);
  }
  if (driftVerdict === 'APPROVED') {
    console.log('APPROVED: breaking change approved via GIEN_APPROVE_BREAKING=1 (four-eyes sign-off per WP-087 C1/C7).');
  }

  const consumers = loadPacts('pacts').map((p) => p.consumer.name);
  const verifications = loadVerifications(deployDir());
  const decision = evaluatePromotion({ driftVerdict, consumers, verifications, specDigest });

  for (const reason of decision.reasons) {
    console.error('BLOCK: ' + reason);
  }

  if (decision.verdict === 'BLOCK') {
    console.error('can-i-deploy BLOCK for environment ' + args.environment + ': fix the reasons above and re-run.');
    process.exit(1);
  }

  console.log(
    'can-i-deploy PASS for environment ' +
      args.environment +
      ': drift gate ' +
      driftVerdict +
      ', all consumers verified against spec digest ' +
      specDigest.slice(0, 12) +
      '...'
  );

  if (args.recordDeployment) {
    const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
    recordDeployment(deployDir(), {
      environment: args.environment,
      version: pkg.version,
      specDigest,
      driftVerdict,
      deployedAt: new Date().toISOString(),
      actor: args.actor,
    });
    console.log('DEPLOYMENT RECORDED: ' + args.environment + ' at version ' + pkg.version + ' (idempotent per environment + digest).');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
