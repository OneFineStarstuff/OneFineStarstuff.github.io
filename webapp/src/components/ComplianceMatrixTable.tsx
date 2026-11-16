import { REGIMES, CATALOG_REV } from '../data/regimes';
import { Role } from '../types/gien';

export default function ComplianceMatrixTable({ role }: { role: Role }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-slate-600 dark:text-slate-300">
        OSCAL 1.1.2 SSP and assessment-results JSON: validated. Catalog rev {CATALOG_REV} steady-state;
        crosswalk drift scan clean; OPA-Rego gates deny-by-default with zero bypass events. The WP-096
        webapp-side seed catalog (OSCAL-SEED-GIEN-WEBAPP-1.0.0) remains outside the operational catalog.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left border-b border-slate-300 dark:border-slate-600">
              <th className="py-2 pr-3">Regime</th>
              <th className="py-2 pr-3">OSCAL 1.1.2</th>
              <th className="py-2 pr-3">OPA-Rego</th>
              <th className="py-2 pr-3">Note</th>
            </tr>
          </thead>
          <tbody>
            {REGIMES.map((r) => (
              <tr key={r.name} className="border-b border-slate-200 dark:border-slate-700 align-top">
                <td className="py-2 pr-3 font-medium">{r.name}</td>
                <td className="py-2 pr-3">{r.oscal === 'validated' ? 'validated' : r.oscal}</td>
                <td className="py-2 pr-3">{r.opa}</td>
                <td className="py-2 pr-3 text-slate-600 dark:text-slate-300">
                  {role === 'supervisor' ? r.band + ' — bands and outcomes only' : r.note}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-400">
        Simulated data. Every conformance claim in a regulator-ready export must link an artefact digest;
        this static table renders the sealed dossier corpus and does not itself constitute evidence.
      </p>
    </div>
  );
}
