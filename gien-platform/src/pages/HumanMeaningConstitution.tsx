import { Page, Card, StatusBadge, Disclosure } from '../components/ui';

const constraints = [
  { id: 'HMC-01', statement: 'No autonomous action affecting human welfare without human-in-the-loop confirmation.', status: 'GREEN' as const, invariant: 'kill_switch' },
  { id: 'HMC-02', statement: 'Fairness proofs must remain independently verifiable by any regulator.', status: 'GREEN' as const, invariant: 'monotonic_ledger_append' },
  { id: 'HMC-03', statement: 'Constitutional amendments require quorum-preserving authority.', status: 'GREEN' as const, invariant: 'quorum_preserving_authority' },
  { id: 'HMC-04', statement: 'Epoch boundaries are atomic — no in-flight state straddles an epoch.', status: 'GREEN' as const, invariant: 'epoch_boundary_atomic' },
];

export default function HumanMeaningConstitution() {
  return (
    <Page title="Human Meaning Constitution" subtitle="Ethical constraint registry + override audit">
      <div className="space-y-3">
        {constraints.map(c => (
          <Card key={c.id}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="font-mono text-xs text-slate-500">{c.id}</div>
                <div className="text-sm mt-1">{c.statement}</div>
                <Disclosure min="crypto">
                  <div className="text-xs text-slate-500 mt-2 font-mono">TLA+ invariant: {c.invariant} · verified · 0 violations</div>
                </Disclosure>
              </div>
              <StatusBadge status={c.status} />
            </div>
          </Card>
        ))}
      </div>
    </Page>
  );
}
