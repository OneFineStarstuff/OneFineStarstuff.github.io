import { Page, Card, StatusBadge } from '../components/ui';

const sources = [
  { uri: 's3://gien-corpus/regulatory/eu-ai-act-annex-iv.md', license: 'CC-BY-4.0', age: '3h', pii: false, freshness: 'GREEN' as const },
  { uri: 's3://gien-corpus/regulatory/nist-ai-rmf-1.0.md', license: 'Public domain', age: '12h', pii: false, freshness: 'GREEN' as const },
  { uri: 's3://gien-corpus/internal/board-minutes-2026-09.pdf', license: 'Internal', age: '5d', pii: true, freshness: 'AMBER' as const },
  { uri: 's3://gien-corpus/regulatory/hkma-ai2-guidelines.md', license: 'Public domain', age: '30d', pii: false, freshness: 'AMBER' as const },
  { uri: 's3://gien-corpus/internal/incident-2026-10-24.md', license: 'Internal', age: '2d', pii: false, freshness: 'GREEN' as const },
];

export default function RAGDataAudit() {
  return (
    <Page title="RAG Data Audit" subtitle="Provenance, freshness, bias flags, and lineage">
      <Card title="Sources">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">URI</th>
                <th className="py-2 pr-3">License</th>
                <th className="py-2 pr-3">Age</th>
                <th className="py-2 pr-3">PII</th>
                <th className="py-2 pr-3">Freshness</th>
              </tr>
            </thead>
            <tbody>
              {sources.map(s => (
                <tr key={s.uri} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3 font-mono text-xs">{s.uri}</td>
                  <td className="py-2 pr-3 text-xs">{s.license}</td>
                  <td className="py-2 pr-3 text-xs">{s.age}</td>
                  <td className="py-2 pr-3 text-xs">{s.pii ? 'yes' : 'no'}</td>
                  <td className="py-2 pr-3"><StatusBadge status={s.freshness} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Bias flags">
        <div className="text-sm text-slate-500">1 cluster flagged: the "internal incidents" embedding cluster shows distributional skew against non-English documents. Flagged for review — no operational impact.</div>
      </Card>
    </Page>
  );
}
