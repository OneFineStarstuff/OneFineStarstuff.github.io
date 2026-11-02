// WP-086 — Deployment orchestration & version-sync contract (GIEN platform, SPA mode).
// Pure evaluators implementing simultaneous multi-deployment dispatch (never wait for a
// queued build) and client/server version lockstep (auto-sync to prevent frontend-backend
// mismatches). Fictional-simulation artefact; enterprise mode asserts the same contract
// by CI fixture tests and commits every event with ML-DSA-87.

export const DEPLOY_CONTRACT_VERSION = '1.0.0';

export type DeployBand = 'GREEN' | 'AMBER' | 'RED';
export type EventSeverity = 'GREEN' | 'AMBER' | 'RED' | 'CRITICAL';

export type DeployEnvironment = 'dev' | 'staging' | 'canary' | 'prod-spa' | 'enterprise-console' | 'omni-sentinel-api';
export type BuildComponent = 'client' | 'server';

export interface BuildSpec {
  build_id: string;
  environment: DeployEnvironment;
  component: BuildComponent;
  version: string;
}

export interface DispatchedBuild {
  build_id: string;
  environment: DeployEnvironment;
  component: BuildComponent;
  slot: number;
  started_at_offset_s: number;
  queued: boolean;
}

export interface DispatchResult {
  builds: DispatchedBuild[];
  base_slots: number;
  slots_used: number;
  queue_depth: number;
  queue_wait_p99_s: number;
}

// Simultaneous dispatch: every build receives a slot immediately and starts at T+0.
// When demand exceeds the base fleet the orchestrator scales out horizontally instead
// of queueing (never wait for a queued build). scaleOut=false emulates legacy queueing so
// fixture tests can prove the discipline check detects the violation.
export function dispatchBuilds(specs: BuildSpec[], baseSlots = 8, scaleOut = true): DispatchResult {
  if (scaleOut || specs.length <= baseSlots) {
    const builds: DispatchedBuild[] = specs.map((s, i) => ({
      build_id: s.build_id,
      environment: s.environment,
      component: s.component,
      slot: i + 1,
      started_at_offset_s: 0,
      queued: false,
    }));
    return { builds, base_slots: baseSlots, slots_used: Math.max(baseSlots, specs.length), queue_depth: 0, queue_wait_p99_s: 0 };
  }
  const builds: DispatchedBuild[] = specs.map((s, i) => {
    const immediate = i < baseSlots;
    return {
      build_id: s.build_id,
      environment: s.environment,
      component: s.component,
      slot: immediate ? i + 1 : 0,
      started_at_offset_s: immediate ? 0 : (i - baseSlots + 1) * 90,
      queued: !immediate,
    };
  });
  const queued = builds.filter(b => b.queued).length;
  return { builds, base_slots: baseSlots, slots_used: baseSlots, queue_depth: queued, queue_wait_p99_s: queued * 90 };
}

export interface DisciplineEvaluation {
  band: DeployBand;
  verdict: 'PASS' | 'VIOLATION';
  detail: string;
}

// Never-wait discipline: queue depth and queue wait must both be zero and every build
// must have started at T+0.
export function evaluateDispatchDiscipline(result: DispatchResult): DisciplineEvaluation {
  const simultaneous = result.builds.every(b => b.started_at_offset_s === 0 && !b.queued);
  if (result.queue_depth === 0 && result.queue_wait_p99_s === 0 && simultaneous) {
    return { band: 'GREEN', verdict: 'PASS', detail: 'queue depth 0 · queue wait p99 0.0 s · ' + result.builds.length + ' builds dispatched simultaneously across ' + result.slots_used + ' slots' };
  }
  return { band: 'RED', verdict: 'VIOLATION', detail: result.queue_depth + ' builds queued · queue wait p99 ' + result.queue_wait_p99_s + ' s (never-wait discipline violated)' };
}

// ---- Client/server version lockstep (auto-sync to prevent mismatches) ----

export interface VersionPair {
  window_id: string;
  ts: string;
  environment: DeployEnvironment;
  client_version: string;
  server_version: string;
  client_contract_hash: string;
  server_contract_hash: string;
}

export function parseSemver(v: string): { major: number; minor: number; patch: number } {
  const parts = v.split('.').map(Number);
  return { major: parts[0] || 0, minor: parts[1] || 0, patch: parts[2] || 0 };
}

export type SyncAction = 'none' | 'auto-sync-align' | 'rollback-block';

export interface SyncEvaluation {
  band: DeployBand;
  lockstep: boolean;
  action: SyncAction;
  detail: string;
}

// Lockstep rules (enforced in evaluation order):
// 1. API contract hash mismatch -> RED rollback-block (deployment conflict, regardless of semver).
// 2. major.minor drift -> RED rollback-block (incompatible pair).
// 3. patch skew -> AMBER auto-sync-align (lockstep engine aligns within the window).
// 4. identical versions + matching contract hash -> GREEN lockstep.
export function evaluateVersionSync(pair: VersionPair): SyncEvaluation {
  if (pair.client_contract_hash !== pair.server_contract_hash) {
    return { band: 'RED', lockstep: false, action: 'rollback-block', detail: 'API contract hash mismatch — deployment conflict blocked, rolled back to the last sealed pair' };
  }
  const c = parseSemver(pair.client_version);
  const s = parseSemver(pair.server_version);
  if (c.major !== s.major || c.minor !== s.minor) {
    return { band: 'RED', lockstep: false, action: 'rollback-block', detail: 'major.minor drift (' + pair.client_version + ' client vs ' + pair.server_version + ' server) — incompatible pair, rollback-block' };
  }
  if (c.patch !== s.patch) {
    return { band: 'AMBER', lockstep: false, action: 'auto-sync-align', detail: 'patch skew (' + pair.client_version + ' client vs ' + pair.server_version + ' server) — auto-sync aligning the pair to lockstep within the window' };
  }
  return { band: 'GREEN', lockstep: true, action: 'none', detail: 'client/server in lockstep at ' + pair.client_version + ' with matching API contract hash' };
}

// ---- WORM audit event envelope (feature-5 minimum fields) ----

export interface DeployAuditEvent {
  event_id: string;
  ts: string;
  actor_role: string;
  feature: 'deployment_orchestrator';
  action: string;
  outcome: string;
  severity: EventSeverity;
  subject_ref: string;
  evidence_ref: string;
  prev_event_hash: string;
}

// Deterministic stand-in for the enterprise SHA-384 chain linkage (no crypto dependency in SPA mode).
function chainHash(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < input.length; i++) {
    h1 = Math.imul(h1 ^ input.charCodeAt(i), 16777619);
    h2 = Math.imul(h2 ^ input.charCodeAt(i), 2246822519);
  }
  const hex = (n: number) => (n >>> 0).toString(16).padStart(8, '0');
  return ('0x' + hex(h1) + hex(h2) + hex(h1 ^ h2) + hex(Math.imul(h1, h2))).slice(0, 18);
}

function buildEvent(windowId: string, ts: string, actorRole: string, action: string, outcome: string, severity: EventSeverity, subjectRef: string): DeployAuditEvent {
  return {
    event_id: 'evt_' + windowId + '_' + action.split('.').join('_'),
    ts,
    actor_role: actorRole,
    feature: 'deployment_orchestrator',
    action,
    outcome,
    severity,
    subject_ref: subjectRef,
    evidence_ref: 'merkle://dossier-306/' + windowId,
    prev_event_hash: chainHash(windowId + action + outcome + severity),
  };
}

export function buildDispatchedEvent(windowId: string, ts: string, buildCount: number, slots: number): DeployAuditEvent {
  return buildEvent(windowId, ts, 'release_manager', 'deploy.build.dispatched', buildCount + ' builds dispatched simultaneously across ' + slots + ' slots (queue depth 0)', 'GREEN', 'build_fleet');
}

export function buildAutoSyncEvent(windowId: string, ts: string, evaluation: SyncEvaluation): DeployAuditEvent {
  return buildEvent(windowId, ts, 'governance_engineer', 'deploy.version.auto_sync', evaluation.action + ' — ' + evaluation.detail, evaluation.band === 'GREEN' ? 'GREEN' : evaluation.band === 'AMBER' ? 'AMBER' : 'RED', 'version_lockstep');
}

export function buildMismatchBlockedEvent(windowId: string, ts: string, evaluation: SyncEvaluation): DeployAuditEvent {
  return buildEvent(windowId, ts, 'release_manager', 'deploy.mismatch.blocked', evaluation.detail, 'RED', 'version_lockstep');
}

// ---- Fixture replay (enterprise CI asserts the identical scenarios) ----

export interface DeployReplayRow {
  scenario: string;
  band: DeployBand;
  verdict: 'PASS' | 'VIOLATION' | 'ALIGN' | 'BLOCK';
  eventAction: string;
  eventSeverity: EventSeverity;
  expected: string;
  pass: boolean;
}

const T0 = '2026-11-02T09:00:00Z';
const WINDOW = 'W-2026-11-02-306';
export const API_CONTRACT_HASH = '0x7f3a9c2e6b8d1f4a7c2e5b9d3f6a8c1e4b7d2f5a9c3e6b1d8f4a2c7e5b3d9f1a';

export const BASE_BUILD_SPECS: BuildSpec[] = [
  { build_id: 'BLD-306-01', environment: 'dev', component: 'client', version: '3.0.7' },
  { build_id: 'BLD-306-02', environment: 'dev', component: 'server', version: '3.0.7' },
  { build_id: 'BLD-306-03', environment: 'staging', component: 'client', version: '3.0.6' },
  { build_id: 'BLD-306-04', environment: 'staging', component: 'server', version: '3.0.6' },
  { build_id: 'BLD-306-05', environment: 'canary', component: 'client', version: '3.0.6' },
  { build_id: 'BLD-306-06', environment: 'canary', component: 'server', version: '3.0.6' },
  { build_id: 'BLD-306-07', environment: 'prod-spa', component: 'client', version: '3.0.6' },
  { build_id: 'BLD-306-08', environment: 'omni-sentinel-api', component: 'server', version: '3.0.6' },
];

function burstSpecs(count: number): BuildSpec[] {
  const specs: BuildSpec[] = [];
  for (let i = 0; i < count; i++) {
    specs.push({ build_id: 'BLD-burst-' + (i + 1), environment: 'dev', component: 'client', version: '3.0.7' });
  }
  return specs;
}

export function replayDeployFixtures(): { allPass: boolean; rows: DeployReplayRow[] } {
  const rows: DeployReplayRow[] = [];

  // 1. Simultaneous multi-deployment dispatch — 8 builds, 8 base slots.
  const d1 = dispatchBuilds(BASE_BUILD_SPECS);
  const e1 = evaluateDispatchDiscipline(d1);
  const ev1 = buildDispatchedEvent(WINDOW, T0, d1.builds.length, d1.slots_used);
  rows.push({ scenario: 'Simultaneous dispatch — 8 builds, 8 base slots', band: e1.band, verdict: e1.verdict, eventAction: ev1.action, eventSeverity: ev1.severity, expected: 'queue depth 0 · all 8 builds start at T+0 s', pass: e1.band === 'GREEN' && e1.verdict === 'PASS' && d1.queue_depth === 0 && d1.queue_wait_p99_s === 0 && ev1.severity === 'GREEN' });

  // 2. Burst saturation — 12 builds against 8 base slots: horizontal scale-out, still no queue.
  const d2 = dispatchBuilds(burstSpecs(12));
  const e2 = evaluateDispatchDiscipline(d2);
  const ev2 = buildDispatchedEvent(WINDOW, T0, d2.builds.length, d2.slots_used);
  rows.push({ scenario: 'Burst saturation — 12 builds, fleet scales out', band: e2.band, verdict: e2.verdict, eventAction: ev2.action, eventSeverity: ev2.severity, expected: 'scale-out to 12 slots · queue depth 0 · never wait', pass: e2.band === 'GREEN' && e2.verdict === 'PASS' && d2.slots_used === 12 && d2.queue_depth === 0 });

  // 3. Legacy queueing contrast (scaleOut=false) — the discipline check must flag the violation.
  const d3 = dispatchBuilds(burstSpecs(12), 8, false);
  const e3 = evaluateDispatchDiscipline(d3);
  rows.push({ scenario: 'Legacy queueing contrast — 12 builds, no scale-out', band: e3.band, verdict: e3.verdict, eventAction: 'deploy.discipline.violation', eventSeverity: 'RED', expected: '4 builds queued · VIOLATION detected by the discipline check', pass: e3.band === 'RED' && e3.verdict === 'VIOLATION' && d3.queue_depth === 4 && d3.queue_wait_p99_s === 360 });

  // 4. Patch skew — auto-sync aligns the pair within the window.
  const p4: VersionPair = { window_id: WINDOW, ts: T0, environment: 'staging', client_version: '3.0.6', server_version: '3.0.1', client_contract_hash: API_CONTRACT_HASH, server_contract_hash: API_CONTRACT_HASH };
  const e4 = evaluateVersionSync(p4);
  const ev4 = buildAutoSyncEvent(WINDOW, T0, e4);
  rows.push({ scenario: 'Patch skew 3.0.6 client vs 3.0.1 server', band: e4.band, verdict: e4.action === 'auto-sync-align' ? 'ALIGN' : 'BLOCK', eventAction: ev4.action, eventSeverity: ev4.severity, expected: 'AMBER · auto-sync aligns patch to lockstep within the window', pass: e4.band === 'AMBER' && e4.action === 'auto-sync-align' && ev4.severity === 'AMBER' });

  // 5. Minor drift — incompatible pair blocked and rolled back.
  const p5: VersionPair = { window_id: WINDOW, ts: T0, environment: 'canary', client_version: '3.0.6', server_version: '3.1.0', client_contract_hash: API_CONTRACT_HASH, server_contract_hash: API_CONTRACT_HASH };
  const e5 = evaluateVersionSync(p5);
  const ev5 = buildMismatchBlockedEvent(WINDOW, T0, e5);
  rows.push({ scenario: 'Minor drift 3.0.6 client vs 3.1.0 server', band: e5.band, verdict: 'BLOCK', eventAction: ev5.action, eventSeverity: ev5.severity, expected: 'RED · rollback-block prevents the deployment conflict', pass: e5.band === 'RED' && e5.action === 'rollback-block' && ev5.severity === 'RED' });

  // 6. Contract-hash mismatch — blocked even with identical semver.
  const p6: VersionPair = { window_id: WINDOW, ts: T0, environment: 'prod-spa', client_version: '3.0.6', server_version: '3.0.6', client_contract_hash: API_CONTRACT_HASH, server_contract_hash: '0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b' };
  const e6 = evaluateVersionSync(p6);
  const ev6 = buildMismatchBlockedEvent(WINDOW, T0, e6);
  rows.push({ scenario: 'API contract-hash mismatch at identical versions', band: e6.band, verdict: 'BLOCK', eventAction: ev6.action, eventSeverity: ev6.severity, expected: 'RED · rollback-block on contract hash mismatch (semver alone is not enough)', pass: e6.band === 'RED' && e6.action === 'rollback-block' && ev6.severity === 'RED' });

  return { allPass: rows.every(r => r.pass), rows };
}