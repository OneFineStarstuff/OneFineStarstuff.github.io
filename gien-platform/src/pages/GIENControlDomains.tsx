import { Page, Card, StatusBadge, ComplianceProgressBar } from '../components/ui';
import { domains } from '../data';

export default function GIENControlDomains() {
  return (
    <Page title="GIEN Control Domains 01–10" subtitle="Per-domain status, risk, and open remediations">
      <div className="grid md:grid-cols-2 gap-4">
        {domains.map(d => (
          <Card key={d.id}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-xs font-mono text-slate-500">Domain {d.id}</div>
                <div className="font-medium">{d.name}</div>
              </div>
              <StatusBadge status={d.status} />
            </div>
            <div className="mt-3 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-500">Risk score</span>
                <span className="font-mono">{d.risk.toFixed(2)}</span>
              </div>
              <ComplianceProgressBar value={10 - Math.round(d.risk * 10)} total={10} />
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-500">Open remediations</span>
                <span className="font-mono">{d.openRemediations}</span>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </Page>
  );
}
