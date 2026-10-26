import { Page, Card, StatusBadge } from '../components/ui';

const panels = [
  { id: 13, name: 'Cross-jurisdictional kill-switch choreography', determinism: 'byte-identical', outcome: 'PASS', advisory: 0 },
  { id: 14, name: 'MoE collapse + attestation storm', determinism: 'byte-identical', outcome: 'PASS', advisory: 0 },
  { id: 15, name: 'Ω-GAR dissolution rehearsal', determinism: 'byte-identical', outcome: 'PASS with 2 advisories', advisory: 2 },
];

export default function SupervisoryDigitalTwin() {
  return (
    <Page title="Supervisory Digital Twin" subtitle="Panels 13–15 · deterministic replay bundles">
      <div className="grid md:grid-cols-3 gap-4">
        {panels.map(p => (
          <Card key={p.id} title={`Panel ${p.id}`}>
            <div className="space-y-2">
              <div className="text-sm">{p.name}</div>
              <div className="text-xs text-slate-500">Determinism: {p.determinism}</div>
              <div className="flex items-center gap-2">
                <StatusBadge status={p.outcome.startsWith('PASS') ? 'GREEN' : 'RED'} />
                {p.advisory > 0 && <span className="text-xs text-amber-600">{p.advisory} advisories</span>}
              </div>
            </div>
          </Card>
        ))}
      </div>
      <Card title="Replay Bundle export">
        <p className="text-sm text-slate-500 mb-3">Replay Bundles are Merkle-anchored and signed JSON + PDF. Full export available in <strong>Regulator Export</strong>.</p>
        <div className="flex gap-2">
          <button className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700" disabled>Download JSON (simulated)</button>
          <button className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700" disabled>Download PDF (simulated)</button>
        </div>
      </Card>
    </Page>
  );
}
