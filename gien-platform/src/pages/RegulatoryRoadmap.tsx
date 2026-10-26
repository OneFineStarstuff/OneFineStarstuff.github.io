import { Page, Card } from '../components/ui';
import { EpochTimeline } from '../components/charts';
import { phases } from '../data';

export default function RegulatoryRoadmap() {
  return (
    <Page title="Regulatory Roadmap" subtitle="Epochs and phases 2026 → 2100+">
      <Card title="Phase readiness">
        <EpochTimeline phases={phases} activeId="VI-δ" />
      </Card>
      <Card title="Epoch summary">
        <div className="grid md:grid-cols-2 gap-3">
          <div className="rounded border border-slate-200 dark:border-slate-800 p-3">
            <div className="font-medium">2026–2035</div>
            <div className="text-sm text-slate-500 mt-1">Primary epoch. Focus: ZTAI hardening, PQC migration, MoE stability. Phase VI-δ closes 2028-Q2; Phase VII prep underway.</div>
          </div>
          <div className="rounded border border-slate-200 dark:border-slate-800 p-3">
            <div className="font-medium">2035–2100+</div>
            <div className="text-sm text-slate-500 mt-1">Phases VIII–XIII and Ω-GAR. Focus: Interstellar Accord ratification, Infinity Pillar Level 5, multiversal synthesis, dissolution arc and Eternal Corpus Transmission Protocol.</div>
          </div>
        </div>
      </Card>
    </Page>
  );
}
