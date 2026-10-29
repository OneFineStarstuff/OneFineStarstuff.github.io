import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity, AlertTriangle, BarChart3, BookOpen, ChevronRight, FileText, Gauge, GitBranch,
  Globe, HeartPulse, Layers, Layout as LayoutIcon, Lock, MessageSquare, Moon, Radar, Shield, Sparkles, Sun,
  KeyRound, Mic, Terminal, TestTube, Users,
} from 'lucide-react';
import { useRole, useTheme, useToast } from '../contexts';
import type { Role, Layer } from '../types';

const NAV = [
  { to: '/', label: 'Executive Summary', icon: LayoutIcon },
  { to: '/stacks', label: 'Governance Stacks', icon: Layers },
  { to: '/domains', label: 'Control Domains 01–10', icon: Shield },
  { to: '/telemetry', label: 'Systemic Risk Telemetry', icon: Activity },
  { to: '/compliance', label: 'Compliance Matrix', icon: FileText },
  { to: '/omni-sentinel', label: 'Omni-Sentinel', icon: Sparkles },
  { to: '/digital-twin', label: 'Supervisory Digital Twin', icon: TestTube },
  { to: '/zero-trust', label: 'Zero Trust & Attestation', icon: Lock },
  { to: '/vulnerabilities', label: 'Vulnerability Tracker', icon: AlertTriangle },
  { to: '/roadmap', label: 'Regulatory Roadmap', icon: GitBranch },
  { to: '/simulator', label: 'Policy Simulator', icon: Terminal },
  { to: '/prompt-architect', label: 'Prompt Architect', icon: MessageSquare },
  { to: '/rag-audit', label: 'RAG Data Audit', icon: Radar },
  { to: '/rag-health', label: 'RAG Health Monitor', icon: HeartPulse },
  { to: '/voice-commander', label: 'Voice Commander', icon: Mic },
  { to: '/access-matrix', label: 'Access Matrix (RBAC)', icon: KeyRound },
  { to: '/constitution', label: 'Human Meaning Constitution', icon: BookOpen },
  { to: '/parity', label: 'Parity Dashboard', icon: BarChart3 },
  { to: '/frameworks', label: 'Global Frameworks', icon: Globe },
  { to: '/long-horizon', label: 'Long-Horizon Governance', icon: Gauge },
  { to: '/export', label: 'Regulator Export', icon: FileText },
  { to: '/walkthrough', label: 'App Walkthrough', icon: Users },
  { to: '/alerts', label: 'Alert History', icon: AlertTriangle },
];

const ROLES: { id: Role; label: string }[] = [
  { id: 'regulator', label: 'Regulator' },
  { id: 'g-sifi', label: 'G-SIFI / LFI' },
  { id: 'engineer', label: 'Governance Engineer' },
  { id: 'executive', label: 'Executive' },
  { id: 'college', label: 'Supervisory College' },
  { id: 'educational', label: 'Educational' },
];

const LAYERS: { id: Layer; label: string }[] = [
  { id: 'executive', label: 'Executive' },
  { id: 'engineering', label: 'Engineering' },
  { id: 'crypto', label: 'Cryptographic' },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const { role, setRole, layer, setLayer } = useRole();
  const { theme, toggle } = useTheme();
  const { push } = useToast();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [stopConfirm, setStopConfirm] = useState(false);

  const triggerStop = () => {
    push({ severity: 'CRITICAL', title: 'Emergency stop requested', body: 'Simulation only — no real systems were affected. Log entry recorded.' });
    setStopConfirm(false);
  };

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-slate-950">
      <aside className={`${sidebarOpen ? 'block' : 'hidden'} lg:block w-64 shrink-0 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-y-auto`}>
        <div className="p-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-sky-600" />
            <div>
              <div className="text-sm font-semibold">GIEN Governance</div>
              <div className="text-[10px] font-mono text-amber-600">FICTIONAL / SIMULATION</div>
            </div>
          </div>
        </div>
        <nav className="p-2">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === '/'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-2 rounded text-sm ${isActive ? 'bg-sky-100 text-sky-900 dark:bg-sky-950 dark:text-sky-200' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'}`
              }>
              <Icon className="w-4 h-4 shrink-0" />
              <span className="truncate">{label}</span>
            </NavLink>
          ))}
        </nav>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 sticky top-0 z-10">
          <div className="px-4 py-2 flex items-center gap-2 flex-wrap">
            <button className="lg:hidden p-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800" onClick={() => setSidebarOpen(!sidebarOpen)} aria-label="Toggle navigation">
              <ChevronRight className="w-5 h-5" />
            </button>
            <select value={role} onChange={e => setRole(e.target.value as Role)}
              className="text-sm rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-1">
              {ROLES.map(r => <option key={r.id} value={r.id}>{r.label}</option>)}
            </select>
            <div className="flex rounded border border-slate-300 dark:border-slate-700 overflow-hidden text-xs">
              {LAYERS.map(l => (
                <button key={l.id} onClick={() => setLayer(l.id)}
                  className={`px-2 py-1 ${layer === l.id ? 'bg-sky-600 text-white' : 'bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700'}`}>
                  {l.label}
                </button>
              ))}
            </div>
            <div className="flex-1" />
            <button onClick={toggle} className="p-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800" aria-label="Toggle theme">
              {theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
            </button>
            <button onClick={() => setStopConfirm(true)} className="px-3 py-1 text-xs font-medium rounded bg-red-600 text-white hover:bg-red-700">
              Emergency Stop
            </button>
          </div>
          <div className="px-4 py-1 text-[10px] font-mono bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border-t border-amber-200 dark:border-amber-900">
            FICTIONAL / SIMULATION — NOT REGULATORY ADVICE — All entities, indices, treaties and cryptographic artifacts are synthetic.
          </div>
        </header>

        <main className="flex-1 p-4 md:p-6">{children}</main>

        <footer className="px-4 py-3 text-xs text-slate-500 border-t border-slate-200 dark:border-slate-800">
          Window: 2026-10-26T09:00:00Z · Role: {role} · Layer: {layer}
        </footer>
      </div>

      {stopConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" role="dialog" aria-modal="true">
          <div className="bg-white dark:bg-slate-900 rounded-lg p-6 max-w-md w-full">
            <h3 className="font-semibold mb-2 flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-red-600" /> Confirm emergency stop</h3>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
              This is a <strong>simulation affordance only</strong>. It logs an audit entry and shows a toast. No real systems are affected. Confirm?
            </p>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setStopConfirm(false)} className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700">Cancel</button>
              <button onClick={triggerStop} className="px-3 py-1.5 text-sm rounded bg-red-600 text-white hover:bg-red-700">Confirm</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
