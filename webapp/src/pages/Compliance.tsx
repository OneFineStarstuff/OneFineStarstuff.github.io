import ComplianceMatrixTable from '../components/ComplianceMatrixTable';
import { Role } from '../types/gien';

export default function Compliance({ role }: { role: Role }) {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Compliance Matrix — 17 regimes (OSCAL 1.1.2 / OPA-Rego)</h1>
      <ComplianceMatrixTable role={role} />
    </div>
  );
}
