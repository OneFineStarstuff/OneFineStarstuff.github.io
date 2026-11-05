import { Page, Card } from '../components/ui';
import { useRole } from '../contexts';

type Cell = '✓' | 'RO' | '—';

const ROLES = [
  'Platform Operator',
  'Governance Engineer',
  'Security Engineer',
  'Release Manager',
  'Supervisory Regulator',
  'Supervisory College Member',
  'G-SIFI Supervisor',
  'Evidence Auditor',
  'Executive Leadership',
  'Educational',
];

const ROLE_MAP: Record<string, string> = {
  regulator: 'Supervisory Regulator',
  'g-sifi': 'G-SIFI Supervisor',
  engineer: 'Governance Engineer',
  executive: 'Executive Leadership',
  college: 'Supervisory College Member',
  educational: 'Educational',
};

const LINES: { line: string; roles: string }[] = [
  { line: 'First line (operations)', roles: 'Platform Operator, Governance Engineer, Security Engineer, Release Manager — build, run, and harden the mesh; evidence everything to the second line.' },
  { line: 'Second line (supervisory & audit)', roles: 'Supervisory Regulator, Supervisory College Member, G-SIFI Supervisor, Evidence Auditor — challenge, verify, and attest on sealed evidence.' },
  { line: 'Third line (governance)', roles: 'Executive Leadership — owns risk appetite, constitutional invariants, and escalation authority.' },
  { line: 'External (educational)', roles: 'Educational — read-only disclosure of published dashboards for teaching and research.' },
];

const CAPABILITIES: { capability: string; cells: Cell[] }[] = [
  { capability: 'RAG health telemetry', cells: ['✓', '✓', '✓', '✓', 'RO', 'RO', 'RO', 'RO', 'RO', 'RO'] },
  { capability: 'Systemic-risk evidence drawers', cells: ['✓', '✓', '✓', '—', 'RO', 'RO', 'RO', 'RO', 'RO', 'RO'] },
  { capability: 'Compliance scanners & validation', cells: ['✓', '✓', '✓', '✓', 'RO', 'RO', '—', 'RO', '—', 'RO'] },
  { capability: 'Audit log queries', cells: ['✓', 'RO', '✓', '—', 'RO', 'RO', 'RO', '✓', 'RO', 'RO'] },
  { capability: 'Dossier & report exports', cells: ['—', '✓', '—', '—', '✓', '✓', '✓', '✓', '✓', 'RO'] },
  { capability: 'Policy simulation & drill tooling', cells: ['—', '✓', '✓', '✓', 'RO', 'RO', 'RO', '—', 'RO', 'RO'] },
  { capability: 'Sealing authority (PQC)', cells: ['—', '—', '✓', '—', 'RO', 'RO', 'RO', 'RO', '—', '—'] },
  { capability: 'Emergency stop trigger', cells: ['✓', '✓', '✓', '—', '✓', '—', '—', '—', '✓', '—'] },
  { capability: 'Role administration', cells: ['—', '—', '✓', '—', '—', '—', '—', '—', '—', '—'] },
];

const cellClass = (c: Cell, active: boolean) => {
  const base = 'py-2 px-2 text-center font-mono text-xs border-b border-slate-100 dark:border-slate-900';
  const tone = c === '✓' ? 'text-emerald-600 dark:text-emerald-400' : c === 'RO' ? 'text-slate-500' : 'text-slate-300 dark:text-slate-600';
  const hl = active ? ' bg-sky-50 dark:bg-sky-950/40' : '';
  return base + ' ' + tone + hl;
};

export default function AccessMatrix() {
  const { role } = useRole();
  const current = ROLE_MAP[role];
  const activeIndex = ROLES.indexOf(current);

  return (
    <Page title="Access Matrix (RBAC)" subtitle="Three-lines-of-defence capability model · highlighted column follows the active role selector">
      <Card title="Three lines of defence">
        <ul className="text-sm list-disc pl-5 space-y-1">
          {LINES.map(l => (
            <li key={l.line}><strong>{l.line}:</strong> {l.roles}</li>
          ))}
        </ul>
      </Card>

      <Card title="Capability matrix (SPA disclosure view)">
        <p className="text-xs text-slate-500 mb-3">✓ full access · RO read-only disclosure · — no access. This SPA renders the intended authorization posture only; in enterprise mode the authoritative enforcement point is the OPA/Rego policy bundle, deny-by-default, keyed to authenticated principal + capability — never this table.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[860px]">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Capability</th>
                {ROLES.map((r, i) => (
                  <th key={r} className={'py-2 px-2 text-center text-[10px] leading-tight' + (i === activeIndex ? ' bg-sky-50 dark:bg-sky-950/40 text-sky-900 dark:text-sky-200 rounded-t' : '')}>{r}{i === activeIndex ? ' ●' : ''}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {CAPABILITIES.map(c => (
                <tr key={c.capability} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3">{c.capability}</td>
                  {c.cells.map((cell, i) => (
                    <td key={i} className={cellClass(cell, i === activeIndex)}>{cell}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-slate-500 mt-3">Active role: <span className="font-mono">{role}</span> → column <strong>{current}</strong>. Sealing authority and role administration are restricted to the Security Engineer persona in this simulation; emergency-stop is additionally granted to the Supervisory Regulator and Executive Leadership per the escalation protocol.</p>
      </Card>
    </Page>
  );
}