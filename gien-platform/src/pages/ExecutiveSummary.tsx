import { Link } from 'react-router-dom';
import { ArrowRight, ShieldCheck, AlertTriangle, Activity } from 'lucide-react';
import { Page, Card, RiskGauge, StatusBadge, Disclosure } from '../components/ui';
import { riskIndices, frameworks, domains, alerts } from '../data';
import { formatReportingWindow, getReportingWindow } from '../reportingWindow.js';

export default function ExecutiveSummary() {
  const reportingWindow = getReportingWindow();
  const headline = riskIndices.slice(0, 5);
  const ambers = domains.filter(d => d.status !== 'GREEN');
  return (
    <Page title="Executive Summary" subtitle={`Simulation briefing · operational status NOT ASSESSED · requested window ${formatReportingWindow(reportingWindow)}`}>
      <div className="grid md:grid-cols-3 gap-4">
        <Card title="Overall posture">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-10 h-10 text-emerald-600" />
            <div>
              <div className="text-lg font-semibold">SIMULATED BASELINE</div>
              <div className="text-xs text-slate-500">Demo field only · operational state NOT ASSESSED</div>
            </div>
          </div>
        </Card>
        <Card title="GIEN-ZTAI-02">
          <div className="text-lg font-semibold">SIMULATED 100% closed</div>
          <div className="text-xs text-slate-500">illustrative scenario only · current remediation evidence NOT ASSESSED</div>
        </Card>
        <Card title="Constitutional invariants">
          <div className="text-lg font-semibold">SIMULATED 0 violations</div>
          <div className="text-xs text-slate-500">fixture assertion · formal-verification evidence NOT SUPPLIED</div>
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
            <li className="flex gap-2"><Activity className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" />Simulation fixture: ZTAI-02 closure scenario. Current remediation evidence is NOT ASSESSED.</li>
            <li className="flex gap-2"><AlertTriangle className="w-4 h-4 shrink-0 text-amber-600 mt-0.5" />Simulation alert fixture: SCP v3.0 derivation exceeded an illustrative SLA; no live alert connector is configured.</li>
            <li className="flex gap-2"><Activity className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" />Simulation fixture: vkFMv3 propagation scenario; key lifecycle evidence is NOT ASSESSED.</li>
          </ul>
        </Card>
        <Card title="Illustrative AMBER domain fixtures">
          {ambers.length === 0 ? <div className="text-sm text-slate-500">Seeded demo fixtures are all GREEN; operational domain status is NOT ASSESSED.</div> : (
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
            <div>Framework assessments NOT ASSESSED: {frameworks.filter(f => f.status === 'NOT ASSESSED').length}/{frameworks.length}</div>
            <div>OPA executions with evidence: {frameworks.filter(f => f.opaViolations !== null && f.opaWarnings !== null).length}/{frameworks.length}</div>
            <div>OSCAL SSP/AR: NOT ASSESSED (evidence not attached)</div>
            <div>Demo Merkle-root label: NOT VERIFIED (no current signed ledger fetched)</div>
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
