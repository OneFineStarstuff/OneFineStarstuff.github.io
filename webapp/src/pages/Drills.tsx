import DrillStatusTable from '../components/DrillStatusTable';
import ExportMenu from '../components/ExportMenu';
import { Role } from '../types/gien';

export default function Drills({ role }: { role: Role }) {
  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <h1 className="text-2xl font-bold">Supervisory Digital Twin — Drills Register</h1>
        <ExportMenu role={role} dataset="drills" />
      </div>
      <DrillStatusTable />
    </div>
  );
}
