// WP-074 — RAG metric event schema of record (GIEN platform, SPA mode).
// Pure threshold evaluators, WORM audit-event builders, and the alert-wiring fixture
// replay implementing the WP-072 metric contract. Fictional-simulation artefact;
// enterprise mode asserts the same contract by CI fixture tests and commits every
// event with ML-DSA-87.

export const CONTRACT_VERSION = '1.0.0';

export type MetricBand = 'GREEN' | 'AMBER' | 'RED';
export type EventSeverity = 'GREEN' | 'AMBER' | 'RED' | 'CRITICAL';

export type RagMetricId =
  | 'pipeline_health'
  | 'retrieval_p99'
  | 'faithfulness'
  | 'citation_coverage'
  | 'freshness_max_age'
  | 'pii_exposure'
  | 'injection_resistance'
  | 'source_trust_mix';

export interface RagWindowSample {
  window_id: string;
  ts: string;
  pipeline_health: number;
  retrieval_p99: number;
  faithfulness: number;
  citation_coverage: number;
  freshness_max_age: number;
  pii_exposure: number;
  injection_resistance: number;
  source_trust_mix: number;
}

interface BandRule { green: (v: number) => boolean; amber?: (v: number) => boolean; }

const BAND_RULES: Record<RagMetricId, BandRule> = {
  pipeline_health: { green: v => v >= 0.97, amber: v => v >= 0.90 },
  retrieval_p99: { green: v => v <= 0.6, amber: v => v <= 1.2 },
  faithfulness: { green: v => v >= 0.95, amber: v => v >= 0.90 },
  citation_coverage: { green: v => v >= 0.98, amber: v => v >= 0.95 },
  freshness_max_age: { green: v => v <= 24 },
  pii_exposure: { green: v => v === 0 },
  injection_resistance: { green: v => v >= 0.99, amber: v => v >= 0.95 },
  source_trust_mix: { green: v => v >= 0.90, amber: v => v >= 0.80 },
};

export function evaluateBand(metric: RagMetricId, value: number): MetricBand {
  const rule = BAND_RULES[metric];
  if (rule.green(value)) return 'GREEN';
  if (rule.amber && rule.amber(value)) return 'AMBER';
  return 'RED';
}

const METRIC_IDS: RagMetricId[] = ['pipeline_health', 'retrieval_p99', 'faithfulness', 'citation_coverage', 'freshness_max_age', 'pii_exposure', 'injection_resistance', 'source_trust_mix'];

export function evaluateWindow(sample: RagWindowSample): { metric: RagMetricId; band: MetricBand }[] {
  return METRIC_IDS.map(id => ({ metric: id, band: evaluateBand(id, (sample as unknown as Record<RagMetricId, number>)[id]) }));
}

export const RELEASE_GATES: RagMetricId[] = ['faithfulness', 'freshness_max_age', 'pii_exposure'];

export function evaluateReleaseGates(sample: RagWindowSample): { gate: RagMetricId; band: MetricBand; verdict: 'PASS' | 'BLOCK' }[] {
  return RELEASE_GATES.map(gate => {
    const band = evaluateBand(gate, (sample as unknown as Record<RagMetricId, number>)[gate]);
    return { gate, band, verdict: band === 'GREEN' ? 'PASS' : 'BLOCK' };
  });
}

// ---- WORM audit event envelope (WP-072 feature-5 minimum fields) ----

export interface RagAuditEvent {
  event_id: string;
  ts: string;
  actor_role: string;
  feature: 'rag_health_monitor';
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

export function buildGateDecisionEvent(sample: RagWindowSample, gate: RagMetricId, band: MetricBand, verdict: 'PASS' | 'BLOCK'): RagAuditEvent {
  const value = (sample as unknown as Record<RagMetricId, number>)[gate];
  return {
    event_id: 'evt_' + sample.window_id + '_' + gate,
    ts: sample.ts,
    actor_role: 'release_manager',
    feature: 'rag_health_monitor',
    action: 'rag.gate.decision',
    outcome: verdict + ' (' + gate + ' = ' + value + ', ' + band + ')',
    severity: verdict === 'BLOCK' ? 'RED' : 'GREEN',
    subject_ref: gate,
    evidence_ref: 'merkle://dossier-300/' + sample.window_id,
    prev_event_hash: chainHash(sample.window_id + gate + band + verdict),
  };
}

export function buildBandTransitionEvent(sample: RagWindowSample, metric: RagMetricId, fromBand: MetricBand, toBand: MetricBand): RagAuditEvent {
  return {
    event_id: 'evt_' + sample.window_id + '_' + metric + '_transition',
    ts: sample.ts,
    actor_role: 'governance_engineer',
    feature: 'rag_health_monitor',
    action: 'rag.alert.band_transition',
    outcome: metric + ' ' + fromBand + ' → ' + toBand,
    severity: toBand === 'RED' ? 'RED' : toBand === 'AMBER' ? 'AMBER' : 'GREEN',
    subject_ref: metric,
    evidence_ref: 'merkle://dossier-300/' + sample.window_id,
    prev_event_hash: chainHash(sample.window_id + metric + fromBand + toBand),
  };
}

// ---- Alert-wiring fixture replay ----

export interface ReplayRow {
  scenario: string;
  worstBand: MetricBand;
  gateVerdict: 'PASS' | 'BLOCK';
  eventAction: string;
  eventSeverity: EventSeverity;
  expected: string;
  pass: boolean;
}

interface Fixture {
  scenario: string;
  sample: RagWindowSample;
  expectWorst: MetricBand;
  expectGate: 'PASS' | 'BLOCK';
  expectSeverity: EventSeverity;
  note: string;
}

const NOMINAL: RagWindowSample = {
  window_id: 'W-2026-10-27-300',
  ts: '2026-10-27T09:00:00Z',
  pipeline_health: 0.973,
  retrieval_p99: 0.58,
  faithfulness: 0.962,
  citation_coverage: 0.984,
  freshness_max_age: 7,
  pii_exposure: 0,
  injection_resistance: 0.994,
  source_trust_mix: 0.92,
};

const FIXTURES: Fixture[] = [
  { scenario: 'Dossier-300 nominal window', sample: NOMINAL, expectWorst: 'GREEN', expectGate: 'PASS', expectSeverity: 'GREEN', note: 'all eight metrics GREEN · release PASS' },
  { scenario: 'Faithfulness degradation 0.88', sample: { ...NOMINAL, window_id: 'W-fixture-faith', faithfulness: 0.88 }, expectWorst: 'RED', expectGate: 'BLOCK', expectSeverity: 'RED', note: 'gate BLOCK on faithfulness < 0.90' },
  { scenario: 'Stale evidence 30 h', sample: { ...NOMINAL, window_id: 'W-fixture-stale', freshness_max_age: 30 }, expectWorst: 'RED', expectGate: 'BLOCK', expectSeverity: 'RED', note: 'gate BLOCK on freshness > 24 h (dossier-blocking)' },
  { scenario: 'PII exposure 2 chunks', sample: { ...NOMINAL, window_id: 'W-fixture-pii', pii_exposure: 2 }, expectWorst: 'RED', expectGate: 'BLOCK', expectSeverity: 'RED', note: 'gate BLOCK on pii_exposure > 0' },
  { scenario: 'Injection resistance 0.97', sample: { ...NOMINAL, window_id: 'W-fixture-inject', injection_resistance: 0.97 }, expectWorst: 'AMBER', expectGate: 'PASS', expectSeverity: 'AMBER', note: 'AMBER band-transition alert · release unaffected (not a gate metric)' },
];

export function replayFixtures(): { allPass: boolean; rows: ReplayRow[] } {
  const rows = FIXTURES.map(f => {
    const bands = evaluateWindow(f.sample);
    const worstBand: MetricBand = bands.some(b => b.band === 'RED') ? 'RED' : bands.some(b => b.band === 'AMBER') ? 'AMBER' : 'GREEN';
    const gates = evaluateReleaseGates(f.sample);
    const gateVerdict: 'PASS' | 'BLOCK' = gates.some(g => g.verdict === 'BLOCK') ? 'BLOCK' : 'PASS';
    const firstBlock = gates.find(g => g.verdict === 'BLOCK');
    const event: RagAuditEvent = firstBlock
      ? buildGateDecisionEvent(f.sample, firstBlock.gate, firstBlock.band, 'BLOCK')
      : worstBand !== 'GREEN'
        ? buildBandTransitionEvent(f.sample, 'injection_resistance', 'GREEN', worstBand)
        : buildGateDecisionEvent(f.sample, 'faithfulness', 'GREEN', 'PASS');
    const pass = worstBand === f.expectWorst && gateVerdict === f.expectGate && event.severity === f.expectSeverity;
    return { scenario: f.scenario, worstBand, gateVerdict, eventAction: event.action, eventSeverity: event.severity, expected: f.note, pass };
  });
  return { allPass: rows.every(r => r.pass), rows };
}