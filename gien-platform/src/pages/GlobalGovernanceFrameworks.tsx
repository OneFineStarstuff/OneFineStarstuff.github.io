import { Page, Card } from '../components/ui';
import { FrameworkGraph } from '../components/charts';
import { frameworks } from '../data';

export default function GlobalGovernanceFrameworks() {
  return (
    <Page title="Global Governance Frameworks" subtitle="Relationship map">
      <Card>
        <FrameworkGraph names={frameworks.map(f => f.name)} />
      </Card>
      <Card title="Adaptive governance archetypes">
        <div className="grid md:grid-cols-3 gap-3">
          {[
            { title: 'Rule-based', text: 'Fixed obligations, high legal certainty, slow adaptation.' },
            { title: 'Principle-based', text: 'Flexible, requires interpretation, moderate certainty.' },
            { title: 'Adaptive / telemetry-driven', text: 'Continuous assurance via OSCAL/OPA, strong observability. GIEN is modeled on this archetype.' },
          ].map(a => (
            <div key={a.title} className="rounded border border-slate-200 dark:border-slate-800 p-3">
              <div className="font-medium text-sm">{a.title}</div>
              <p className="text-xs text-slate-500 mt-1">{a.text}</p>
            </div>
          ))}
        </div>
      </Card>
    </Page>
  );
}
