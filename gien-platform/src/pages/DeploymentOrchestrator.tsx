import { useState } from 'react';
import { Page, Card, StatusBadge, Disclosure, download } from '../components/ui';
import { DEPLOY_CONTRACT_VERSION, API_CONTRACT_HASH, BASE_BUILD_SPECS, dispatchBuilds, evaluateDispatchDiscipline, evaluateVersionSync, replayDeployFixtures, type BuildSpec, type DeployEnvironment, type VersionPair } from '../deploy/contract';

type Band = 'GREEN' | 'AMBER' | 'RED';

const WINDOW = '2026-11-01T09:00:00Z → 2026-11-02T09:00:00Z';
const BASELINE = 'GIEN-DOSSIER-2026-306';
const T0 = '2026-11-02T09:00:00Z';
const WINDOW_ID = 'W-2026-11-02-306';

const dispatch = dispatchBuilds(BASE_BUILD_SPECS);
const discipline = evaluateDispatchDiscipline(dispatch);
const replay = replayDeployFixtures();
const replayBand: Band = replay.allPass ? 'GREEN' : 'RED';

interface BuildRow {
  build_id: string;
  environment: DeployEnvironment;
  component: 'client' | 'server';
  version: string;
  slot: number;
  start: string;
  duration: string;
  seal: string;
}

const DURATIONS = ['3 m 12 s', '3 m 26 s', '3 m 08 s', '3 m 19 s', '4 m 41 s', '4 m 55 s', '3 m 33 s', '4 m 02 s'];

const buildRows: BuildRow[] = BASE_BUILD_SPECS.map((spec, i) => ({
  build_id: spec.build_id,
  environment: spec.environment,
  component: spec.component,
  version: spec.version,
  slot: dispatch.builds[i] ? dispatch.builds[i].slot : i + 1,
  start: 'T+0 s',
  duration: DURATIONS[i] || '—',
  seal: 'artifact://' + spec.build_id + '/sha384',
}));

const PAIR_DEFS: { environment: DeployEnvironment; label: string; client: string; server: string }[] = [
  { environment: 'dev', label: 'dev', client: '3.0.7', server: '3.0.7' },
  { environment: 'staging', label: 'staging', client: '3.0.6', server: '3.0.6' },
  { environment: 'canary', label: 'canary', client: '3.0.6', server: '3.0.6' },
  { environment: 'prod-spa', label: 'prod-spa client ↔ omni-sentinel-api server', client: '3.0.6', server: '3.0.6' },
  { environment: 'enterprise-console', label: 'enterprise-console', client: '3.0.6', server: '3.0.6' },
];

const syncPairs = PAIR_DEFS.map(p => {
  const pair: VersionPair = { window_id: WINDOW_ID, ts: T0, environment: p.environment, client_version: p.client, server_version: p.server, client_contract_hash: API_CONTRACT_HASH, server_contract_hash: API_CONTRACT_HASH };
  return { ...p, evaluation: evaluateVersionSync(pair) };
});

const fleetStats = [
  { label: 'Simultaneous builds dispatched', value: dispatch.builds.length + '/' + dispatch.builds.length, note: 'all started at T+0 s (never queued)' },
  { label: 'Build slots', value: dispatch.slots_used + ' active', note: dispatch.base_slots + ' base slots · horizontal scale-out on demand' },
  { label: 'Queue depth', value: '0', note: 'never wait for a queued build' },
  { label: 'Queue wait p99', value: '0.0 s', note: 'discipline check PASS' },
];

const auditCatalog = [
  { event: 'deploy.build.dispatched', emitter: 'Build fleet dispatcher', fields: 'build_ids, slots, queue_depth' },
  { event: 'deploy.version.auto_sync', emitter: 'Version lockstep engine', fields: 'environment, from_version, to_version, action' },
  { event: 'deploy.mismatch.blocked', emitter: 'Version lockstep engine', fields: 'environment, reason, rollback_ref' },
  { event: 'deploy.discipline.violation', emitter: 'Dispatch discipline check', fields: 'queue_depth, queue_wait_p99_s, queued_build_ids' },
  { event: 'deploy.window.sealed', emitter: 'Window batcher', fields: 'window_id, merkle_leaf' },
];

export default function DeploymentOrchestrator() {
  const [showCatalog, setShowCatalog] = useState(false);
  const snapshot = {
    window: WINDOW,
    baseline: BASELINE,
    contract_version: DEPLOY_CONTRACT_VERSION,
    fleet: { builds_dispatched: dispatch.builds.length, base_slots: dispatch.base_slots, slots_used: dispatch.slots_used, queue_depth: dispatch.queue_depth, queue_wait_p99_s: dispatch.queue_wait_p99_s, discipline: discipline.verdict },
    version_sync: syncPairs.map(p => ({ environment: p.environment, client_version: p.client, server_version: p.server, band: p.evaluation.band, lockstep: p.evaluation.lockstep, action: p.evaluation.action })),
    builds: buildRows,
  };
  const exportJson = () => download('deployment-orchestrator-snapshot.json', JSON.stringify(snapshot, null, 2), 'application/json');

  return (
    <Page title="Deployment Orchestrator" subtitle="Simultaneous multi-deployment builds & client/server version lockstep · window ending 2026-11-02 09:00 UTC · baseline GIEN-DOSSIER-2026-306">
      <div className="flex flex-wrap gap-2">
        <button onClick={exportJson} className="px-3 py-1.5 text-sm rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900">Export snapshot JSON</button>
        <button onClick={() => setShowCatalog(!showCatalog)} className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700">{showCatalog ? 'Hide audit event catalog' : 'Show audit event catalog'}</button>
      </div>

      <Card title="Parallel build fleet — never wait for a queued build">
        <div className="flex items-center gap-3 mb-3">
          <StatusBadge status={discipline.band} />
          <span className="text-xs text-slate-500">{discipline.detail}</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {fleetStats.map(s => (
            <div key={s.label} className="rounded-lg border border-slate-200 dark:border-slate-800 p-3">
              <div className="text-xs text-slate-500">{s.label}</div>
              <div className="font-mono text-lg mt-1">{s.value}</div>
              <div className="text-[10px] font-mono text-slate-500 mt-1">{s.note}</div>
            </div>
          ))}
        </div>
        <p className="text-xs text-slate-500 mt-3">Every deployment build dispatches to a fleet slot at T+0 and runs simultaneously. When demand exceeds the base fleet, the orchestrator scales out horizontally instead of queueing — the discipline check (queue depth 0, queue wait p99 0.0 s) is enforced per window and asserted by CI fixture replay. GitOps posture this window: 217/217 deployments reconciled, zero drift. Fictional simulation.</p>
      </Card>

      <Card title="Simultaneous deployment matrix — current window">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Build</th>
                <th className="py-2 pr-3">Environment</th>
                <th className="py-2 pr-3">Component</th>
                <th className="py-2 pr-3">Version</th>
                <th className="py-2 pr-3">Slot</th>
                <th className="py-2 pr-3">Start</th>
                <th className="py-2 pr-3">Duration</th>
                <th className="py-2 pr-3">Artifact seal</th>
                <th className="py-2 pr-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {buildRows.map(b => (
                <tr key={b.build_id} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3 font-mono text-xs">{b.build_id}</td>
                  <td className="py-2 pr-3">{b.environment}</td>
                  <td className="py-2 pr-3">{b.component}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{b.version}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{b.slot}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{b.start}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{b.duration}</td>
                  <td className="py-2 pr-3 font-mono text-[10px] text-slate-500">{b.seal}</td>
                  <td className="py-2 pr-3"><StatusBadge status="GREEN" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Client/server version sync — lockstep engine (prevents frontend-backend mismatches)">
        <div className="flex items-center gap-3 mb-3">
          <StatusBadge status="GREEN" />
          <span className="text-xs text-slate-500">Lockstep engine ACTIVE · API contract hash match on all pairs · 1 auto-sync alignment this window (staging server 3.0.1 → 3.0.6 at 06:14 UTC) · 0 rollback-blocks · 0 unsealed mismatches</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Environment pair</th>
                <th className="py-2 pr-3">Client</th>
                <th className="py-2 pr-3">Server</th>
                <th className="py-2 pr-3">Lockstep</th>
                <th className="py-2 pr-3">Action</th>
                <th className="py-2 pr-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {syncPairs.map(p => (
                <tr key={p.label} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3">{p.label}</td>
                  <td className="py-2 pr-3 font-mono text-xs">v{p.client}</td>
                  <td className="py-2 pr-3 font-mono text-xs">v{p.server}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{p.evaluation.lockstep ? 'YES' : 'NO'}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{p.evaluation.action}</td>
                  <td className="py-2 pr-3"><StatusBadge status={p.evaluation.band} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <ul className="text-sm list-disc pl-5 space-y-1 mt-3">
          <li>Major.minor lockstep is enforced: an incompatible client/server pair is rollback-blocked before it can reach any environment (deployment conflict prevented).</li>
          <li>Patch skew is auto-synced: the lockstep engine aligns the pair within the window and emits deploy.version.auto_sync.</li>
          <li>Semver alone is not trusted: a mismatched API contract hash is rollback-blocked even at identical versions.</li>
        </ul>
      </Card>

      <Card title="WP-086 — Dispatch & lockstep fixture replay">
        <div className="flex items-center gap-3 mb-3">
          <StatusBadge status={replayBand} />
          <span className="text-xs text-slate-500">Contract v{DEPLOY_CONTRACT_VERSION} · {replay.rows.length} fixtures · {replay.rows.filter(r => r.pass).length}/{replay.rows.length} PASS · events WORM-committed with ML-DSA-87 in enterprise mode</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Scenario</th>
                <th className="py-2 pr-3">Band</th>
                <th className="py-2 pr-3">Verdict</th>
                <th className="py-2 pr-3">Audit event</th>
                <th className="py-2 pr-3">Expected</th>
                <th className="py-2 pr-3">Result</th>
              </tr>
            </thead>
            <tbody>
              {replay.rows.map(r => (
                <tr key={r.scenario} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3">{r.scenario}</td>
                  <td className="py-2 pr-3"><StatusBadge status={r.band} /></td>
                  <td className="py-2 pr-3 font-mono text-xs">{r.verdict}</td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{r.eventAction} · {r.eventSeverity}</td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{r.expected}</td>
                  <td className={'py-2 pr-3 font-mono text-xs ' + (r.pass ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400')}>{r.pass ? 'PASS' : 'FAIL'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-slate-500 mt-3">Evaluators are pure functions in the schema-of-record module (gien-platform/src/deploy/contract.ts); this replay exercises the exact contract that enterprise CI asserts by fixture test. Every dispatch, auto-sync, and rollback-block emits exactly one WORM audit event. Fictional simulation.</p>
      </Card>

      {showCatalog && (
        <Card title="Audit event catalog (WORM-committed in enterprise mode)">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Event</th>
                <th className="py-2 pr-3">Emitter</th>
                <th className="py-2 pr-3">Fields</th>
              </tr>
            </thead>
            <tbody>
              {auditCatalog.map(a => (
                <tr key={a.event} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3 font-mono text-xs">{a.event}</td>
                  <td className="py-2 pr-3">{a.emitter}</td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{a.fields}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Disclosure min="crypto">
        <Card title="Sealing & chain-linkage notes">
          <ul className="text-sm list-disc pl-5 space-y-1">
            <li>Dispatch and lockstep events chain through the feature-5 WORM envelope with deterministic chain-hash stand-ins in SPA mode; enterprise mode commits ML-DSA-87 signatures into the PQC Merkle-DAG ledger.</li>
            <li>Build artifacts are sealed with SHA-384 digests and anchored to the window Merkle root (dossier-306: 0xe81d07eb37e0f562e84e01375e0fe93d3b2812dd54a184ddcf10919623a60c31).</li>
            <li>The discipline and lockstep checks run pre-deploy in CI in enterprise mode; the SPA renders their current-window verdicts for supervisory disclosure.</li>
          </ul>
        </Card>
      </Disclosure>
    </Page>
  );
}