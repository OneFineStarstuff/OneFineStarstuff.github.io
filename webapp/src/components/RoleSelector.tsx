import { Role } from '../types/gien';

interface Props { role: Role; onChange: (r: Role) => void; }

const ROLES: { id: Role; label: string }[] = [
  { id: 'supervisor', label: 'Supervisor / Regulator' },
  { id: 'engineer', label: 'Governance Engineer' },
  { id: 'educational', label: 'Educational' }
];

export default function RoleSelector({ role, onChange }: Props) {
  return (
    <div role="tablist" aria-label="Audience role" className="flex gap-2">
      {ROLES.map((r) => (
        <button
          key={r.id}
          role="tab"
          aria-selected={role === r.id}
          onClick={() => onChange(r.id)}
          className={
            'px-3 py-1.5 text-sm rounded-md border transition ' +
            (role === r.id
              ? 'bg-slate-900 text-white border-slate-900 dark:bg-white dark:text-slate-900'
              : 'border-slate-300 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800')
          }
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}
