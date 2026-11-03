import { useMemo, useState } from 'react';
import { Play, RotateCcw } from 'lucide-react';
import CodeBlock from '../components/CodeBlock';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import { POLICY_PACKS } from '../data/extendedData';
import { FICTIONAL_NOTICE } from '../data/extendedData';
import { fakeHash } from '../data/helpers';

interface DiffLine {
  type: 'same' | 'add' | 'remove';
  text: string;
}

// Plain-React LCS line diff (no external diff library).
function diffLines(before: string, after: string): DiffLine[] {
  const a = before.split('\n');
  const b = after.split('\n');
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ type: 'same', text: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ type: 'remove', text: a[i] });
      i++;
    } else {
      out.push({ type: 'add', text: b[j] });
      j++;
    }
  }
  while (i < n) out.push({ type: 'remove', text: a[i++] });
  while (j < m) out.push({ type: 'add', text: b[j++] });
  return out;
}

const CHECKS = [
  { id: 'suite', label: 'PQC signature suite approved (ML-DSA-65/87, SLH-DSA)' },
  { id: 'anchor', label: 'Transfer anchored to WORM Merkle-DAG ledger' },
  { id: 'attest', label: 'RTEE attestation fresher than 300 s' },
  { id: 'depth', label: 'Agent recursion depth ≤ 5' },
  { id: 'hitl', label: 'Human-in-the-loop confirmation present' },
  { id: 'ipv', label: 'Intervention Proof Verifier attestation' },
  { id: 'dpia', label: 'DPIA validates against OSCAL 1.1.2 profile' },
  { id: 'zk', label: 'zk attestation of DPIA execution verified' },
  { id: 'art22', label: 'Art. 22 human-review path present' },
];

export default function PolicySimulator() {
  const [packId, setPackId] = useState(POLICY_PACKS[0].id);
  const [checks, setChecks] = useState<Record<string, boolean>>({ suite: true, anchor: true, attest: false, depth: true, hitl: true, ipv: false, dpia: true, zk: false, art22: true });
  const [runId, setRunId] = useState<string | null>(null);

  const pack = POLICY_PACKS.find((p) => p.id === packId) ?? POLICY_PACKS[0];
  const diff = useMemo(() => diffLines(pack.baseline, pack.proposed), [pack]);

  const decision = useMemo(() => {
    // Each rule maps to one or more scenario checks.
    const mapping: Record<string, string[]> = {
      'PQC-01': ['suite'],
      'PQC-02': ['anchor'],
      'PQC-03': ['attest'],
      'AGT-01': ['depth'],
      'AGT-02': ['hitl'],
      'AGT-03': ['ipv'],
      'DPIA-01': ['dpia'],
      'DPIA-02': ['zk'],
      'DPIA-03': ['art22'],
    };
    return pack.rules.map((r) => {
      const needed = mapping[r.id] ?? [];
      const passed = needed.every((k) => checks[k]);
      return { ...r, passed };
    });
  }, [pack, checks]);

  const allowed = decision.every((d) => d.passed);

  const run = () => setRunId(fakeHash(`sim-${packId}-${Date.now()}`).slice(0, 22));

  return (
    <div>
      <PageHeader
        title="Governance Policy Simulator"
        subtitle="Simulated OPA/Rego evaluation with baseline-to-proposed policy diffing"
        crumbs={[{ label: 'Home', to: '/dashboard' }, { label: 'Policy Simulator' }]}
        actions={
          <button
            type="button"
            onClick={run}
            className="inline-flex items-center gap-1.5 rounded-md bg-indigo-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-400"
          >
            <Play size={13} /> Run simulation
          </button>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="rounded-lg border border-gray-700 bg-gray-800/50 p-4 lg:col-span-1">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400">Policy pack</h2>
          <div className="mt-2 space-y-2">
            {POLICY_PACKS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => {
                  setPackId(p.id);
                  setRunId(null);
                }}
                aria-pressed={p.id === packId}
                className={`w-full rounded-md border px-3 py-2 text-left text-xs transition-colors ${
                  p.id === packId ? 'border-indigo-500 bg-indigo-500/10 text-gray-100' : 'border-gray-700 bg-gray-900/40 text-gray-300 hover:border-gray-600'
                }`}
              >
                <p className="font-mono text-[10px] text-indigo-300">{p.id}</p>
                <p className="mt-0.5 font-medium">{p.name}</p>
                <p className="mt-0.5 text-[11px] text-gray-500">{p.domain}</p>
              </button>
            ))}
          </div>

          <h2 className="mt-4 text-xs font-semibold uppercase tracking-wider text-gray-400">Scenario inputs</h2>
          <div className="mt-2 space-y-1.5">
            {CHECKS.map((c) => (
              <label key={c.id} className="flex items-start gap-2 rounded px-1 py-0.5 text-[11px] text-gray-300 hover:bg-gray-800">
                <input
                  type="checkbox"
                  checked={Boolean(checks[c.id])}
                  onChange={(e) => {
                    setChecks((prev) => ({ ...prev, [c.id]: e.target.checked }));
                    setRunId(null);
                  }}
                  className="mt-0.5 h-3 w-3 accent-indigo-500"
                />
                <span>{c.label}</span>
              </label>
            ))}
          </div>

          <button
            type="button"
            onClick={() => setChecks({})}
            className="mt-3 inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-400 hover:bg-gray-800"
          >
            <RotateCcw size={11} /> Clear inputs
          </button>
        </section>

        <section className="space-y-4 lg:col-span-2">
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400">Decision</h2>
              <StatusBadge variant={allowed ? 'COMPLIANT' : 'NON_COMPLIANT'} label={runId ? (allowed ? 'ALLOW' : 'DENY') : 'NOT RUN'} />
            </div>
            <p className="mt-2 text-xs text-gray-400">
              {runId
                ? allowed
                  ? 'All rules satisfied under the simulated inputs. The request would be admitted.'
                  : `${decision.filter((d) => !d.passed).length} rule(s) failed; the request would be denied at admission.`
                : 'Adjust the scenario inputs and run the simulation.'}
            </p>
            {runId && (
              <p className="mt-2 font-mono text-[11px] text-gray-500">
                simulation_id {runId} · inputs {Object.values(checks).filter(Boolean).length}/{CHECKS.length} satisfied
              </p>
            )}

            <table className="mt-3 w-full text-left text-[11px]">
              <thead className="text-gray-500">
                <tr>
                  <th className="py-1 pr-2 font-medium">Rule</th>
                  <th className="py-1 pr-2 font-medium">Description</th>
                  <th className="py-1 font-medium">Result</th>
                </tr>
              </thead>
              <tbody className="text-gray-300">
                {decision.map((d) => (
                  <tr key={d.id} className="border-t border-gray-700/60">
                    <td className="py-1.5 pr-2 font-mono text-gray-400">{d.id}</td>
                    <td className="py-1.5 pr-2">{d.description}</td>
                    <td className="py-1.5">
                      <StatusBadge variant={d.passed ? 'COMPLIANT' : 'NON_COMPLIANT'} label={d.passed ? 'PASS' : 'FAIL'} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-4">
            <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-400">Policy diff — baseline → proposed</h2>
            <div className="overflow-hidden rounded-md border border-gray-700">
              <div className="max-h-64 overflow-y-auto bg-gray-950 font-mono text-[11px] leading-relaxed">
                {diff.map((line, i) => (
                  <div
                    key={i}
                    className={
                      line.type === 'add'
                        ? 'bg-emerald-500/10 px-3 text-emerald-300'
                        : line.type === 'remove'
                          ? 'bg-red-500/10 px-3 text-red-300'
                          : 'px-3 text-gray-400'
                    }
                  >
                    <span className="mr-2 inline-block w-3 select-none text-gray-600">
                      {line.type === 'add' ? '+' : line.type === 'remove' ? '−' : ' '}
                    </span>
                    {line.text || ' '}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div>
            <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-400">Proposed Rego</h2>
            <CodeBlock code={pack.proposed} language="rego" />
          </div>
        </section>
      </div>

      <p className="mt-4 text-[11px] text-gray-500">{FICTIONAL_NOTICE} Policy evaluation is simulated in the browser; no OPA engine is contacted.</p>
    </div>
  );
}
