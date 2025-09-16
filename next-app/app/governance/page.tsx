import Link from 'next/link';

export const metadata = { title: 'Governance Cockpit' };
export default function GovernancePage() {
  return (
    <main className="space-y-4">
      <h1 className="text-2xl font-semibold">Governance Cockpit</h1>
      <p className="text-sm text-slate-600">Board-ready artifact hub with live roadmap, mappings, and templates.</p>
      <ul className="list-disc pl-6 text-amber-800">
        <li><Link href="/docs/roadmap" className="underline">Roadmap (capacity-aware)</Link></li>
        <li><Link href="/docs/governance-terms-mapping" className="underline">Integrated 18‑Point Mapping</Link></li>
        <li><Link href="/docs/readiness-checklist" className="underline">Implementation Readiness Checklist</Link></li>
        <li><Link href="/templates/artefact-templates" className="underline">Governance Artefact Templates</Link></li>
        <li><Link href="/risk" className="underline">Interactive Risk & Governance Demos</Link></li>
      </ul>
    </main>
  );
}
