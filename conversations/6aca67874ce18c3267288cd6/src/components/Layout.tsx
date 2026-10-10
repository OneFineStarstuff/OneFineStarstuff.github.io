import {
  Activity,
  BellAlert,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  FileCheck2,
  FileText,
  GitBranch,
  Landmark,
  LayoutDashboard,
  Lock,
  Scale,
  Shield,
  Sigma,
  Workflow,
} from 'lucide-react';
import { useState, type ComponentType } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useGovernance } from '../context/GovernanceContext';
import type { Role } from '../types';

interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<{ size?: number | string; className?: string }>;
}

const NAV: NavItem[] = [
  { to: '/dashboard', label: 'Daily Supervisory Brief', icon: LayoutDashboard },
  { to: '/risk-indices', label: 'Risk Indices', icon: Sigma },
  { to: '/compliance', label: 'Compliance Matrix', icon: Scale },
  { to: '/governance-stacks', label: 'Governance Stacks', icon: Shield },
  { to: '/control-domains', label: 'Control Domains', icon: GitBranch },
  { to: '/cryptographic-integrity', label: 'Cryptographic Integrity', icon: Lock },
  { to: '/digital-twin', label: 'Digital Twin Panels', icon: Activity },
  { to: '/scenario-planner', label: 'Scenario Planner', icon: Workflow },
  { to: '/constitutional', label: 'Constitutional Framework', icon: Landmark },
  { to: '/submission-packages', label: 'Submission Packages', icon: FileCheck2 },
  { to: '/long-horizon', label: 'Long-Horizon Architecture', icon: BookOpen },
];

const ROLE_LABELS: Record<Role, string> = {
  REGULATOR: 'Regulator / Supervisory Authority',
  INSTITUTION: 'Institution / Governance Engineer',
  EXECUTIVE: 'Executive Leadership',
  EDUCATION: 'Educational / Research',
};

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const { role, setRole, phase, evaluationWindow, alerts, alertCount } = useGovernance();

  return (
    <div className="flex min-h-screen bg-gray-950">
      {/* Sidebar */}
      <aside
        className={`no-print sticky top-0 hidden h-screen shrink-0 flex-col border-r border-gray-800 bg-gray-900/80 transition-all md:flex ${
          collapsed ? 'w-16' : 'w-64'
        }`}
      >
        <div className="flex items-center gap-2 border-b border-gray-800 px-4 py-4">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-indigo-600 font-bold text-white">
            G
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-gray-100">GIEN Supervisory</p>
              <p className="truncate text-[10px] uppercase tracking-wider text-indigo-400">Omni-Sentinel v4.0</p>
            </div>
          )}
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3" aria-label="Primary">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? 'bg-indigo-600/15 text-indigo-300'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                }`
              }
              title={item.label}
            >
              <item.icon size={17} className="shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </NavLink>
          ))}
        </nav>
        <button
          type="button"
          onClick={() => setCollapsed((c) => !c)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className="flex items-center justify-center border-t border-gray-800 py-2.5 text-gray-500 hover:text-gray-300"
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Header */}
        <header className="no-print sticky top-0 z-40 border-b border-gray-800 bg-gray-900/95 backdrop-blur">
          <div className="flex flex-wrap items-center gap-3 px-4 py-2.5 md:px-6">
            <label htmlFor="role-select" className="text-[11px] font-medium uppercase tracking-wider text-gray-500">
              Role
            </label>
            <select
              id="role-select"
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              aria-label="Select viewing role"
              className="rounded-md border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-gray-200 focus:border-indigo-500 focus:outline-none"
            >
              {(Object.keys(ROLE_LABELS) as Role[]).map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </select>
            <span className="rounded-full border border-violet-500/30 bg-violet-500/10 px-2.5 py-0.5 text-[11px] font-semibold text-violet-300">
              {phase}
            </span>
            <span className="hidden font-mono text-[11px] text-gray-500 lg:inline">
              Window: {evaluationWindow}
            </span>
            <span
              className="ml-auto inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-[11px] font-semibold text-amber-300"
              title={alerts.map((a) => a.message).join('\n')}
            >
              <BellAlert size={12} />
              {alertCount} active {alertCount === 1 ? 'alert' : 'alerts'}
            </span>
          </div>
          {alertCount > 0 && (
            <div className="border-t border-amber-500/20 bg-amber-500/5 px-4 py-1.5 md:px-6">
              {alerts.map((a) => (
                <p key={a.id} className="truncate text-[11px] text-amber-300/90">
                  <span className="font-mono">{a.id}</span> · {a.message}
                </p>
              ))}
            </div>
          )}
        </header>

        {/* Mobile nav */}
        <nav className="no-print flex gap-1 overflow-x-auto border-b border-gray-800 bg-gray-900/60 px-2 py-2 md:hidden" aria-label="Primary mobile">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex shrink-0 items-center gap-1.5 rounded-md px-3 py-1.5 text-xs ${
                  isActive ? 'bg-indigo-600/20 text-indigo-300' : 'text-gray-400 hover:text-gray-200'
                }`
              }
            >
              <item.icon size={14} />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <main className="flex-1 px-4 py-5 md:px-6">
          <Outlet />
        </main>

        <footer className="no-print border-t border-gray-800 px-4 py-3 text-[11px] text-gray-600 md:px-6">
          <FileText size={10} className="mr-1 inline" />
          Fictional/simulated data for the GIEN governance universe · Filing SGR-028-CFE-2026-07-001 · Phase VI-δ
        </footer>
      </div>
    </div>
  );
}
