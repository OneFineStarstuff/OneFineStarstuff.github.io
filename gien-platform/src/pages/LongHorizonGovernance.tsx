import { Page, Card } from '../components/ui';
import { EpochTimeline } from '../components/charts';
import { phases } from '../data';

export default function LongHorizonGovernance() {
  return (
    <Page title="Long-Horizon Governance" subtitle="Phases VI-δ through XIII and Ω-GAR">
      <Card title="Phase readiness">
        <EpochTimeline phases={phases} />
      </Card>
      {phases.map(p => (
        <Card key={p.id} title={`${p.name} — ${p.epoch}`}>
          <div className="grid md:grid-cols-2 gap-3">
            <div>
              <div className="text-xs uppercase text-slate-500 mb-1">Objectives</div>
              <ul className="list-disc list-inside text-sm space-y-1">{p.objectives.map((o, i) => <li key={i}>{o}</li>)}</ul>
            </div>
            <div>
              <div className="text-xs uppercase text-slate-500 mb-1">Active invariants</div>
              <ul className="text-sm space-y-1 font-mono">{p.invariants.map((inv, i) => <li key={i}>{inv}</li>)}</ul>
              <div className="text-xs uppercase text-slate-500 mt-3 mb-1">Milestones</div>
              <ul className="text-sm space-y-1">{p.milestones.map((m, i) => <li key={i}>{m.done ? '✓' : '○'} {m.label}</li>)}</ul>
            </div>
          </div>
        </Card>
      ))}
      <Card title="Ω-GAR artefacts">
        <ul className="text-sm space-y-1">
          <li>GIEN-UNIFIED-CODEX-OMEGA — sealing protocol frozen</li>
          <li>GIEN-EPITAPH-OMEGA — invocation transcript drafted</li>
          <li>GIEN-INVOCATION-OMEGA — Beacon Signature design frozen</li>
          <li>Eternal Corpus Transmission Protocol — awaiting epoch activation</li>
        </ul>
      </Card>
    </Page>
  );
}
