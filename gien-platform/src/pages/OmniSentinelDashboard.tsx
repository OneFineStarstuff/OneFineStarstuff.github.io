import { Page, Card, StatusBadge } from '../components/ui';

export default function OmniSentinelDashboard() {
  const cards = [
    { name: 'Cognitive Execution Environment', status: 'GREEN' as const, stat: '4 workers / 0 stuck' },
    { name: 'StaR-MoE Router', status: 'GREEN' as const, stat: 'Entropy 0.93 · smoothing 1.4' },
    { name: 'Guardian Attestation', status: 'GREEN' as const, stat: '100% density · 0 mismatches' },
    { name: 'Infinity Pillar Readiness', status: 'AMBER' as const, stat: 'Level 3 of 5' },
    { name: 'IASOS CivilizationalReadinessMonitor', status: 'GREEN' as const, stat: 'Steady state' },
    { name: 'MaterialChangeTracker (PQC ledger)', status: 'GREEN' as const, stat: '0 unreviewed deltas' },
  ];
  return (
    <Page title="Omni-Sentinel Dashboard" subtitle="Mesh health, MoE routing, Guardian Attestation, Infinity Pillar">
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
        {cards.map(c => (
          <Card key={c.name}>
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="text-sm font-medium">{c.name}</div>
                <div className="text-xs text-slate-500 mt-1">{c.stat}</div>
              </div>
              <StatusBadge status={c.status} />
            </div>
          </Card>
        ))}
      </div>
    </Page>
  );
}
