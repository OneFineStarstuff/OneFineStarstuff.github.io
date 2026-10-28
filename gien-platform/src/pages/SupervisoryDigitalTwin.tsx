import { Page, Card, StatusBadge } from '../components/ui';

const panels = [
  { id: 13, name: 'Cross-jurisdictional kill-switch choreography', determinism: 'byte-identical', outcome: 'PASS', advisory: 0 },
  { id: 14, name: 'MoE collapse + attestation storm', determinism: 'byte-identical', outcome: 'PASS', advisory: 0 },
  { id: 15, name: 'Ω-GAR dissolution rehearsal', determinism: 'byte-identical', outcome: 'PASS with 2 advisories', advisory: 2 },
];

interface SdtDrill {
  id: string;
  window: string;
  convergenceSec: number | null;
  contained: boolean;
  reference?: boolean;
  note: string;
}

const sdtDrills: SdtDrill[] = [
  { id: 'DRILL-048', window: '2026-10-13', convergenceSec: 221, contained: true, note: 'Ashen-Lantern — failover convergence 3 m 41 s' },
  { id: 'DRILL-049', window: '2026-10-15', convergenceSec: 258, contained: true, note: 'Pale-Harbor — AAR guidance: converge within 4 minutes' },
  { id: 'DRILL-050', window: '2026-10-19', convergenceSec: 227, contained: true, note: 'Iron-Vesper — first drill inside the sub-4-minute gate; prior reference mark 3 m 47 s' },
  { id: 'DRILL-051', window: '2026-10-26', convergenceSec: 209, contained: true, reference: true, note: 'Quartz-Vigil — AAR filed; 3 m 29 s adopted as the new reference mark; two-consecutive sub-4-minute condition satisfied' },
  { id: 'DRILL-052', window: 'week of 2026-11-02', convergenceSec: null, contained: false, note: 'Drafting OPENED (concept phase) · freeze vote target 2026-10-31 · design target ≤ 3 m 30 s' },
];

const mmss = (s: number | null): string =>
  s === null ? '—' : Math.floor(s / 60) + ' m ' + String(s % 60).padStart(2, '0') + ' s';

export default function SupervisoryDigitalTwin() {
  return (
    <Page title="Supervisory Digital Twin" subtitle="Panels 13–15 · deterministic replay bundles · DRILL-052 rehearsal view">
      <div className="grid md:grid-cols-3 gap-4">
        {panels.map(p => (
          <Card key={p.id} title={'Panel ' + p.id}>
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
      <Card title="SDT drill timeline — consensus attestation convergence gate">
        <p className="text-sm text-slate-500 mb-3">
          Reference mark adopted from the DRILL-051 after-action review: <strong>3 m 29 s</strong> (supersedes Iron-Vesper 3 m 47 s).
          Binding gate: sub-4-minute convergence across two consecutive drills — <strong>SATISFIED</strong> (DRILL-050 + DRILL-051).
          DRILL-052 design target: ≤ 3 m 30 s.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Drill</th>
                <th className="py-2 pr-3">Window</th>
                <th className="py-2 pr-3">Convergence</th>
                <th className="py-2 pr-3">Outcome</th>
                <th className="py-2 pr-3">Note</th>
              </tr>
            </thead>
            <tbody>
              {sdtDrills.map(d => (
                <tr key={d.id} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3 font-medium">{d.id}{d.reference ? ' ★' : ''}</td>
                  <td className="py-2 pr-3 text-slate-500">{d.window}</td>
                  <td className="py-2 pr-3 font-mono">{mmss(d.convergenceSec)}</td>
                  <td className="py-2 pr-3"><StatusBadge status={d.contained ? 'GREEN' : 'AMBER'} /></td>
                  <td className="py-2 pr-3 text-xs text-slate-500 max-w-md">{d.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-slate-500 mt-3">
          No live drill executed in the current window (Tuesday cadence); the DRILL-052 rehearsal choreography enters college drafting ahead of the 2026-10-31 freeze vote.
        </p>
      </Card>
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