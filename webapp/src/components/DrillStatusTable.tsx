import { DRILLS } from '../data/drills';
import BandBadge from './BandBadge';

export default function DrillStatusTable() {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="text-left border-b border-slate-300 dark:border-slate-600">
            <th className="py-2 pr-3">Drill</th>
            <th className="py-2 pr-3">Date</th>
            <th className="py-2 pr-3">Mode</th>
            <th className="py-2 pr-3">Outcome</th>
            <th className="py-2 pr-3">Convergence</th>
            <th className="py-2 pr-3">Target</th>
            <th className="py-2 pr-3">Replay determinism</th>
            <th className="py-2 pr-3">Band</th>
            <th className="py-2 pr-3">Note</th>
          </tr>
        </thead>
        <tbody>
          {DRILLS.map((d) => (
            <tr key={d.id + d.mode + d.date} className="border-b border-slate-200 dark:border-slate-700 align-top">
              <td className="py-2 pr-3 font-medium">{d.id} {d.name}</td>
              <td className="py-2 pr-3">{d.date}</td>
              <td className="py-2 pr-3">{d.mode}</td>
              <td className="py-2 pr-3">{d.outcome}</td>
              <td className="py-2 pr-3">{d.convergence || '-'}</td>
              <td className="py-2 pr-3">{d.target}</td>
              <td className="py-2 pr-3">{d.replayDeterminism}</td>
              <td className="py-2 pr-3"><BandBadge band={d.band} /></td>
              <td className="py-2 pr-3 text-slate-600 dark:text-slate-300">{d.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
