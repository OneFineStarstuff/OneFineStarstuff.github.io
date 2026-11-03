import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import DetailDrawer from '../components/DetailDrawer';
import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ProgressBar from '../components/ProgressBar';
import StatusBadge from '../components/StatusBadge';
import { CONTROL_DOMAINS } from '../data/gienData';
import { fakeHash } from '../data/helpers';
import { FICTIONAL_NOTICE } from '../data/extendedData';
import type { ControlDomain } from '../types';

export default function ControlDomains() {
  const [selected, setSelected] = useState<ControlDomain | null>(null);

  const avg = Math.round(CONTROL_DOMAINS.reduce((s, d) => s + d.complianceScore, 0) / CONTROL_DOMAINS.length);
  const controls = CONTROL_DOMAINS.reduce((s, d) => s + d.activeControls, 0);
  const findings = CONTROL_DOMAINS.reduce((s, d) => s + d.openFindings, 0);

  return (
    <div>
      <PageHeader
        title="GIEN Control Domains 01–10"
        subtitle="Control-domain status, evidence and findings across the planetary governance mesh"
        crumbs={[{ label: 'Home', to: '/dashboard' }, { label: 'Control Domains' }]}
      />

      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Mean domain compliance" value={`${avg}%`} status={avg >= 95 ? 'NOMINAL' : 'ELEVATED'} />
        <MetricCard label="Active controls" value={controls} footer="OSCAL 1.1.2 codified" />
        <MetricCard label="Open findings" value={findings} status={findings > 5 ? 'ELEVATED' : 'NOMINAL'} />
        <MetricCard label="Treaty-grade domains" value="10 / 10" status="VERIFIED" footer="CFE-1.0 + SGR-028" />
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        {CONTROL_DOMAINS.map((d) => (
          <button
            key={d.id}
            type="button"
            onClick={() => setSelected(d)}
            className="rounded-lg border border-gray-700 bg-gray-800/50 p-4 text-left transition-colors hover:border-indigo-500/60 hover:bg-gray-800"
            aria-label={`Open ${d.id} ${d.name} detail`}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-mono text-[11px] text-indigo-400">{d.id}</p>
                <h2 className="mt-0.5 text-sm font-semibold text-gray-100">{d.name}</h2>
              </div>
              <StatusBadge variant={d.status} />
            </div>
            <p className="mt-2 line-clamp-2 text-xs text-gray-400">{d.description}</p>
            <div className="mt-3">
              <ProgressBar value={d.complianceScore} label="Compliance" threshold={90} />
            </div>
            <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
              <div>
                <dt className="text-gray-500">Controls</dt>
                <dd className="font-mono text-gray-200">{d.activeControls}</dd>
              </div>
              <div>
                <dt className="text-gray-500">Findings</dt>
                <dd className={`font-mono ${d.openFindings > 0 ? 'text-amber-300' : 'text-emerald-300'}`}>{d.openFindings}</dd>
              </div>
            </dl>
          </button>
        ))}
      </div>

      <p className="mt-4 text-[11px] text-gray-500">{FICTIONAL_NOTICE}</p>

      <DetailDrawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected ? `${selected.id} — ${selected.name}` : ''}
        subtitle="Control-domain detail, evidence and findings"
      >
        {selected && (
          <div className="space-y-4 text-sm">
            <p className="text-gray-300">{selected.description}</p>

            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-md border border-gray-700 bg-gray-800/50 p-3">
                <p className="text-xs text-gray-400">Compliance</p>
                <p className="mt-1 font-mono text-xl text-gray-100">{selected.complianceScore}%</p>
              </div>
              <div className="rounded-md border border-gray-700 bg-gray-800/50 p-3">
                <p className="text-xs text-gray-400">Open findings</p>
                <p className="mt-1 font-mono text-xl text-gray-100">{selected.openFindings}</p>
              </div>
            </div>

            <section>
              <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-400">
                <ShieldCheck size={13} /> Sample controls
              </h3>
              <ul className="space-y-1.5">
                {Array.from({ length: Math.min(5, selected.activeControls) }).map((_, i) => (
                  <li key={i} className="flex items-center justify-between rounded border border-gray-700/70 bg-gray-900/60 px-2.5 py-1.5 font-mono text-[11px] text-gray-300">
                    <span>{selected.id}-C{String(i + 1).padStart(2, '0')}</span>
                    <StatusBadge variant="COMPLIANT" />
                  </li>
                ))}
              </ul>
            </section>

            <section>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-400">Evidence artefacts</h3>
              <ul className="space-y-1.5 font-mono text-[11px] text-gray-400">
                <li className="truncate">OSCAL-SSP: {fakeHash(`${selected.id}-ssp`)}</li>
                <li className="truncate">ASSESS-RESULTS: {fakeHash(`${selected.id}-ar`)}</li>
                <li className="truncate">REGO-PACK: {fakeHash(`${selected.id}-rego`)}</li>
              </ul>
            </section>

            {selected.openFindings > 0 ? (
              <section>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-400">Open findings</h3>
                <ul className="space-y-2 text-xs text-gray-300">
                  <li className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2">
                    {selected.id}-F01 — evidence freshness beyond 24h for {selected.openFindings} control(s); remediation owned by governance engineering.
                  </li>
                </ul>
              </section>
            ) : (
              <p className="rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
                No open findings in the current evaluation window.
              </p>
            )}

            <p className="text-[11px] text-gray-500">{FICTIONAL_NOTICE}</p>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
