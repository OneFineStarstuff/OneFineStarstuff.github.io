import { Page, Card, StatusBadge } from '../components/ui';

const stacks = [
  { name: 'Sentinel AI Governance Stack', version: 'v2.4', status: 'GREEN' as const, notes: 'Zero policy-eval failures' },
  { name: 'Omni-Sentinel Governance Mesh', version: 'v4.0', status: 'GREEN' as const, notes: 'Full mesh reconciliation across all regions' },
  { name: 'Unified Supervisory Control Plane', version: 'v3.0', status: 'AMBER' as const, notes: '09:00 bundle derivation ran 4 min over SLA' },
];

const cycle = [
  { time: '08:00', label: 'Archive transmission & college receipt', status: 'COMPLETE', hash: 'sha3-512:8c11…f03a', sig: 'VALID' },
  { time: '08:30', label: 'Merkle root validation & PQC verification', status: 'COMPLETE', hash: 'sha3-512:62af…d18c', sig: 'VALID' },
  { time: '09:00', label: 'Compliance bundle derivation', status: 'IN-PROGRESS', hash: 'pending', sig: 'PENDING' },
  { time: '12:00', label: 'SLA exception review', status: 'PENDING', hash: '—', sig: 'PENDING' },
  { time: '18:00', label: 'Panels 13–15 stress-test drill', status: 'PENDING', hash: '—', sig: 'PENDING' },
  { time: '23:59', label: 'Cycle closure & archive seal', status: 'PENDING', hash: '—', sig: 'PENDING' },
];

export default function GovernanceStacks() {
  return (
    <Page title="Governance Stacks" subtitle="Sentinel v2.4 · Omni-Sentinel v4.0 · Unified SCP v3.0">
      <div className="grid md:grid-cols-3 gap-4">
        {stacks.map(s => (
          <Card key={s.name} title={s.version}>
            <div className="space-y-2">
              <div className="text-sm font-medium">{s.name}</div>
              <StatusBadge status={s.status} />
              <p className="text-xs text-slate-500">{s.notes}</p>
            </div>
          </Card>
        ))}
      </div>
      <Card title="Daily SCP v3.0 cycle (2026-10-26)">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Time (UTC)</th>
                <th className="py-2 pr-3">Event</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Artefact hash</th>
                <th className="py-2 pr-3">PQC signature</th>
              </tr>
            </thead>
            <tbody>
              {cycle.map(c => (
                <tr key={c.time} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3 font-mono text-xs">{c.time}</td>
                  <td className="py-2 pr-3">{c.label}</td>
                  <td className="py-2 pr-3 text-xs">{c.status}</td>
                  <td className="py-2 pr-3 font-mono text-xs text-slate-500">{c.hash}</td>
                  <td className="py-2 pr-3 text-xs">{c.sig}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </Page>
  );
}
