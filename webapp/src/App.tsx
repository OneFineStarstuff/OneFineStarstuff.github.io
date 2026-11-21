import { useEffect, useState } from 'react';
import { NavLink, Route, Routes } from 'react-router-dom';
import { ScrollText, LayoutDashboard, Info, Scale, Activity } from 'lucide-react';
import ClassificationBanner from './components/ClassificationBanner';
import ThemeToggle from './components/ThemeToggle';
import Footer from './components/Footer';
import Dashboard from './pages/Dashboard';
import BriefingViewer from './pages/BriefingViewer';
import Compliance from './pages/Compliance';
import Drills from './pages/Drills';
import { Role } from './types/gien';

export default function App() {
  const [dark, setDark] = useState(false);
  const [role, setRole] = useState<Role>('supervisor');

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);

  const nav = [
    { to: '/', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
    { to: '/briefing', label: 'Daily Brief', icon: <ScrollText size={16} /> },
    { to: '/compliance', label: 'Compliance', icon: <Scale size={16} /> },
    { to: '/drills', label: 'Drills', icon: <Activity size={16} /> },
    { to: '/about', label: 'About', icon: <Info size={16} /> }
  ];

  return (
    <div className="min-h-screen bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">
      <ClassificationBanner />
      <header className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-700">
        <nav className="flex gap-4" aria-label="Primary">
          {nav.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) =>
                'inline-flex items-center gap-1.5 text-sm font-medium ' +
                (isActive ? 'underline underline-offset-4' : 'hover:underline')
              }
            >
              {n.icon} {n.label}
            </NavLink>
          ))}
        </nav>
        <ThemeToggle dark={dark} onToggle={() => setDark(!dark)} />
      </header>
      <main className="max-w-5xl mx-auto px-4 py-6">
        <Routes>
          <Route path="/" element={<Dashboard role={role} />} />
          <Route path="/briefing" element={<BriefingViewer role={role} onRoleChange={setRole} />} />
          <Route path="/compliance" element={<Compliance role={role} />} />
          <Route path="/drills" element={<Drills role={role} />} />
          <Route path="/about" element={<About />} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
}

function About() {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">About this console</h1>
      <p className="text-sm">
        Phase 2 is delivered through the CI trust and knowledge backbone. M4 (WP-110) delivered
        regulator-ready exports and the OPA-Rego promotion gate policy; M3 (WP-108) the compliance
        matrix (17 regimes) and the drills register; M2 (WP-106) evidence drawers with honest
        root-recomputability semantics and the Merkle inspector; M1 (WP-102) the static shell and
        briefing viewer. WP-114 added the CI trust and knowledge backbone (determinism lint and
        Playwright invariants, bands-bound p(doom) test, reproducible build gate, accessible
        Sparkline, checksum-pinned OPA bundles, OSCAL diff focus, glossary, constitution, and
        crosswalk with validator). WP-116 records the ANSM profile promotion from advisory to
        enforced (PROMO-R11 college adjudication, 2026-11-19, with zero gate denies) and upgrades
        the Dashboard fixture to dossier-2026-321 (dossier-2026-318 retained as archive). WP-117
        upgrades the briefing, evidence, and Dashboard fixtures to the sealed dossier-2026-324
        lineage (weekly G-SRI/S_sys series embedded in the evidence payloads; dossier-2026-318
        and -321 retained as archives).
      </p>
      <p className="text-sm">
        Role-based progressive disclosure: the Supervisor/Regulator view shows bands and outcomes; the
        Governance Engineer view unseals hashes and full notes; the Educational view adds learning notes.
        Exports follow the same gating.
      </p>
      <p className="text-sm">
        Shared band thresholds (WP-108): webapp/src/data/bands.json is the single machine-readable
        threshold source, consumed by src/lib/bands.ts and by telemetry/gsri_monitor.py.
      </p>
    </div>
  );
}
