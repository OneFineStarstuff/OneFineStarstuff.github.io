import { Link } from 'react-router-dom';
import { ArrowRight, ShieldCheck, AlertTriangle, Activity } from 'lucide-react';
import { Page, Card, RiskGauge, StatusBadge, Disclosure } from '../components/ui';
import { riskIndices, frameworks, domains, alerts } from '../data';

export default function ExecutiveSummary() {
  const headline = riskIndices.slice(0, 5);
  const ambers = domains.filter(d => d.status !== 'GREEN');
  return (
    <Page title="Executive Summary" subtitle="24-hour supervisory briefing · window ending 2026-10-26 09:00 UTC">
      <div className="grid md:grid-cols-3 gap-4">
        <Card title="Overall posture">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-10 h-10 text-emerald-600" />
            <div>
              <div className="text-lg font-semibold">ELEVATED-BASELINE</div>
              <div className="text-xs text-slate-500">Safeguard mode: not engaged</div>
            </div>
          </div>
        </Card>
        <Card title="GIEN-ZTAI-02">
          <div className="text-lg font-semibold">100% closed</div>
          <div className="text-xs text-slate-500">25 / 25 findings remediated</div>
        </Card>
        <Card title="Constitutional invariants">
          <div className="text-lg font-semibold">0 violations</div>
          <div className="text-xs text-slate-500">TLA+ proofs · Δ_constitution = 0.00</div>
        </Card>
      </div>

      <Card title="Headline risk indices">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
          {headline.map(r => (
            <div key={r.id} className="text-center">
              <RiskGauge value={r.value} thresholds={r.thresholds} label={r.label} />
              <div className="text-xs font-medium">{r.label}</div>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Top items this window">
          <ul className="space-y-2 text-sm">
            <li className="flex gap-2"><Activity className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" />ZTAI-02 fully closed (25/25). Program transitions to maintenance.</li>
            <li className="flex gap-2"><AlertTriangle className="w-4 h-4 shrink-0 text-amber-600 mt-0.5" />SCP v3.0 bundle derivation ran 4 min over SLA. No data loss.</li>
            <li className="flex gap-2"><Activity className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" />vkFMv3 verification-key rotation fully propagated.</li>
          </ul>
        </Card>
        <Card title="Open AMBER domains">
          {ambers.length === 0 ? <div className="text-sm text-slate-500">All control domains GREEN.</div> : (
            <ul className="space-y-2 text-sm">
              {ambers.map(d => (
                <li key={d.id} className="flex items-center justify-between gap-2">
                  <span>{d.id} — {d.name}</span>
                  <StatusBadge status={d.status} />
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Disclosure min="engineering">
        <Card title="Engineering rollup">
          <div className="grid sm:grid-cols-2 gap-3 text-sm">
            <div>Frameworks COMPLIANT: {frameworks.filter(f => f.status === 'COMPLIANT').length}/{frameworks.length}</div>
            <div>OPA violations: {frameworks.reduce((s, f) => s + f.opaViolations, 0)}</div>
            <div>OSCAL SSP/AR: all validated</div>
            <div>Merkle root: sha3-512:62af…d18c</div>
          </div>
        </Card>
      </Disclosure>

      <div className="flex gap-2 flex-wrap">
        <Link to="/telemetry" className="inline-flex items-center gap-1 text-sm text-sky-600 hover:underline">View full telemetry <ArrowRight className="w-3 h-3" /></Link>
        <Link to="/export" className="inline-flex items-center gap-1 text-sm text-sky-600 hover:underline">Generate regulator dossier <ArrowRight className="w-3 h-3" /></Link>
      </div>
    </Page>
  );
}
