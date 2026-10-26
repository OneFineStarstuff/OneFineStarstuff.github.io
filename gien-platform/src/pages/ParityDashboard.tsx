import { Page, Card } from '../components/ui';
import { ParityBars } from '../components/charts';

const items = [
  { label: 'Autonomous routing', capability: 0.82, control: 0.78 },
  { label: 'Cross-jurisdictional export', capability: 0.70, control: 0.72 },
  { label: 'zkML fairness', capability: 0.60, control: 0.65 },
  { label: 'Kill-switch', capability: 0.95, control: 0.95 },
  { label: 'Prompt safety', capability: 0.80, control: 0.72 },
  { label: 'RAG provenance', capability: 0.85, control: 0.82 },
];

export default function ParityDashboard() {
  return (
    <Page title="Parity Dashboard" subtitle="Capability vs. control — gap analysis">
      <Card title="Capability (blue) vs. control (green)">
        <ParityBars items={items} />
      </Card>
      <Card title="Interpretation">
        <p className="text-sm text-slate-500">Positive gap = capability ahead of control; negative = control ahead of capability. Two items worth attention: <strong>Prompt safety</strong> (capability 0.80, control 0.72) and <strong>Autonomous routing</strong> (0.82 / 0.78).</p>
      </Card>
    </Page>
  );
}
