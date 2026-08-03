export const metadata = { title: 'Maturity Rubric – Incentive Alignment' } as const;

export default function Page() {
  return (
    <main className="space-y-4">
      <h1 className="text-2xl font-semibold">Maturity Rubric – Incentive Alignment</h1>
      <p className="text-sm text-slate-600">Scoring guidance (0–3) with example evidence. Use alongside the Capability Matrix.</p>

      <div className="overflow-x-auto">
        <table className="min-w-[720px] border-collapse">
          <thead>
            <tr>
              <th className="border bg-slate-50 px-3 py-2 text-left text-xs font-semibold">Level</th>
              <th className="border bg-slate-50 px-3 py-2 text-left text-xs font-semibold">Descriptor</th>
              <th className="border bg-slate-50 px-3 py-2 text-left text-xs font-semibold">Example Evidence</th>
            </tr>
          </thead>
          <tbody className="text-sm">
            <tr>
              <td className="border px-3 py-2 align-top font-semibold">0 – Absent</td>
              <td className="border px-3 py-2 align-top">No alignment between incentives and governance outcomes.</td>
              <td className="border px-3 py-2 align-top">Compensation structures tied only to delivery speed.</td>
            </tr>
            <tr>
              <td className="border px-3 py-2 align-top font-semibold">1 – Emerging</td>
              <td className="border px-3 py-2 align-top">Initial awareness of misaligned incentives; isolated pilots.</td>
              <td className="border px-3 py-2 align-top">One BU links compliance KPIs to annual bonuses.</td>
            </tr>
            <tr>
              <td className="border px-3 py-2 align-top font-semibold">2 – Established</td>
              <td className="border px-3 py-2 align-top">Governance outcomes embedded in performance metrics across multiple teams.</td>
              <td className="border px-3 py-2 align-top">Quarterly OKRs include safety and risk metrics.</td>
            </tr>
            <tr>
              <td className="border px-3 py-2 align-top font-semibold">3 – Integrated</td>
              <td className="border px-3 py-2 align-top">Incentive structures systematically reinforce governance across the organization.</td>
              <td className="border px-3 py-2 align-top">Board-level oversight of governance KPIs in executive comp packages.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="rounded border bg-white p-3 text-sm">
        <div className="font-semibold">Use</div>
        <ul className="ml-5 list-disc">
          <li>Score quarterly (Governance Office); align target levels with roadmap and budget cycles.</li>
          <li>Acceptable evidence includes: policy updates, KPI definitions, comp framework excerpts, audit logs, OKR snapshots.</li>
          <li>Record decisions in Governance Decision Records (GDRs) when targets or metrics change.</li>
        </ul>
      </div>
    </main>
  );
}
