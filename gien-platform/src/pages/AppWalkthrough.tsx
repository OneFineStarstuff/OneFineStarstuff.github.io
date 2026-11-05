import { useState } from 'react';
import { Page, Card } from '../components/ui';

const steps = [
  { title: '1. Start with the Executive Summary', text: 'The summary page gives you the posture, headline indices, and top items for the 24h window. Every claim is traceable to deeper evidence.' },
  { title: '2. Adjust role and layer', text: 'Use the top-bar selectors to switch between Executive, Engineering, and Cryptographic views. Regulator links preserve your role and layer in the URL.' },
  { title: '3. Drill into risk telemetry', text: 'Click any index card to see thresholds, series, and (if applicable) the fictional/simulation flag on p(doom) fields.' },
  { title: '4. Check compliance', text: 'The Compliance Matrix lists all 18 frameworks. Filter by family or status and export to CSV.' },
  { title: '5. Generate a dossier', text: 'The Regulator Export page builds a title/abstract/content dossier you can download or print to PDF.' },
];

export default function AppWalkthrough() {
  const [step, setStep] = useState(0);
  return (
    <Page title="App Walkthrough" subtitle="Role-based onboarding" fictional={false}>
      <Card>
        <div className="text-xs uppercase text-slate-500 mb-2">Step {step + 1} of {steps.length}</div>
        <div className="text-lg font-medium">{steps[step].title}</div>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-2">{steps[step].text}</p>
        <div className="flex gap-2 mt-4">
          <button disabled={step === 0} onClick={() => setStep(step - 1)} className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700 disabled:opacity-40">Back</button>
          <button disabled={step === steps.length - 1} onClick={() => setStep(step + 1)} className="px-3 py-1.5 text-sm rounded bg-sky-600 text-white disabled:opacity-40">Next</button>
        </div>
      </Card>
      <Card title="All steps">
        <ol className="list-decimal list-inside text-sm space-y-1">
          {steps.map((s, i) => <li key={i} className={i === step ? 'font-medium' : 'text-slate-500'}>{s.title}</li>)}
        </ol>
      </Card>
    </Page>
  );
}
