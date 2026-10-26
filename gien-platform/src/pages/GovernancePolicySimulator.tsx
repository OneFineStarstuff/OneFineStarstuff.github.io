import { useState } from 'react';
import { Page, Card } from '../components/ui';
import { useToast } from '../contexts';

const policyA = [
  'package gien.attest',
  '',
  'default allow = false',
  '',
  'allow {',
  '  input.node.valid == true',
  '  input.node.vtpm_present == true',
  '  input.node.quote_age_s < 300',
  '}',
];

const policyB = [
  'package gien.attest',
  '',
  'default allow = false',
  '',
  'allow {',
  '  input.node.valid == true',
  '  input.node.vtpm_present == true',
  '  input.node.quote_age_s < 180',
  '  input.node.pqc_signature == "valid"',
  '}',
];

function diffLines(a: string[], b: string[]) {
  const setA = new Set(a), setB = new Set(b);
  const left = a.map((l, i) => ({ kind: setB.has(l) ? 'same' : 'del', line: l, i }));
  const right = b.filter(l => !setA.has(l)).map(l => ({ kind: 'add', line: l, i: -1 }));
  return { left, right };
}

export default function GovernancePolicySimulator() {
  const { push } = useToast();
  const [ran, setRan] = useState(false);
  const { left, right } = diffLines(policyA, policyB);

  const simulate = () => {
    setRan(true);
    push({ severity: 'AMBER', title: 'Simulation complete', body: '2 new violations predicted under current input distribution (qtr-band reduction).' });
  };

  return (
    <Page title="Policy Simulator" subtitle="Diff and simulate proposed Rego changes (client-side, mock evaluation)">
      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Current policy">
          <pre className="text-xs font-mono overflow-x-auto">
            {left.map((l, i) => (
              <div key={i} className={l.kind === 'del' ? 'bg-red-50 dark:bg-red-950/40 text-red-800 dark:text-red-300' : ''}>
                {l.kind === 'del' ? '- ' : '  '}{l.line}
              </div>
            ))}
          </pre>
        </Card>
        <Card title="Proposed policy">
          <pre className="text-xs font-mono overflow-x-auto">
            {policyB.map((line, i) => {
              const isNew = right.some(r => r.line === line);
              return <div key={i} className={isNew ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-300' : ''}>{isNew ? '+ ' : '  '}{line}</div>;
            })}
          </pre>
        </Card>
      </div>
      <Card>
        <button onClick={simulate} className="px-3 py-1.5 text-sm rounded bg-sky-600 text-white">Run simulation</button>
        {ran && (
          <div className="mt-3 text-sm space-y-1">
            <div className="flex justify-between"><span>Violations (before → after)</span><span className="font-mono">0 → 2</span></div>
            <div className="flex justify-between"><span>Warnings (before → after)</span><span className="font-mono">0 → 0</span></div>
            <div className="text-xs text-slate-500 mt-2">Predicted impact: attestation window shrinks to 180s; requirement for PQC signature adds 2 policy violations under current telemetry. Recommend staged rollout.</div>
          </div>
        )}
      </Card>
    </Page>
  );
}
