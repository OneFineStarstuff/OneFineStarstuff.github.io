import Link from 'next/link';

export const metadata = { title: 'Governance Cockpit' };
export default function GovernancePage() {
  return (
    <main className="space-y-4">
      <h1 className="text-2xl font-semibold">Governance Cockpit</h1>
      <p className="text-sm text-slate-600">Board-ready artifact hub with live roadmap, mappings, and templates.</p>
      <ul className="list-disc pl-6 text-amber-800">
        <li><Link href="/docs/exec-overlay/action-brief" className="underline font-bold text-red-700">Board Action Brief 🎯 ⭐⭐</Link> <span className="text-xs text-slate-500">/ <Link href="/docs/exec-overlay/slides" className="underline font-bold text-indigo-600">Board Slides 🎬</Link> / <Link href="/docs/exec-overlay/summary" className="underline font-semibold text-green-700">Executive Summary 📋</Link> / <Link href="/docs/launch-brief" className="underline">Launch Brief</Link> / <Link href="/docs/exec-overlay" className="underline">Exec Overlay</Link> / <Link href="/docs/exec-overlay/visual" className="underline">Visuals</Link> / <Link href="/docs/exec-overlay/board-pack" className="underline font-semibold text-blue-600">Board Pack</Link></span></li>
        <li><Link href="/docs/roadmap" className="underline">Roadmap (capacity-aware)</Link></li>
        <li><Link href="/docs/strategy-map" className="underline">Strategy Map (phases × dimensions)</Link></li>
        <li><Link href="/docs/governance-terms-mapping" className="underline">Integrated 18‑Point Mapping</Link></li>
        <li><Link href="/docs/readiness-checklist" className="underline">Implementation Readiness Checklist</Link></li>
        <li><Link href="/templates/artefact-templates" className="underline">Governance Artefact Templates</Link></li>
        <li><Link href="/governance/maturity" className="underline">Governance Capability Matrix</Link> <span className="text-xs text-slate-500">/ <Link href="/governance/rubric" className="underline">Rubric</Link></span></li>
        <li><Link href="/governance/dashboard" className="underline">Readiness Dashboard (prototype)</Link></li>
        <li><Link href="/risk" className="underline">Interactive Risk & Governance Demos</Link></li>
      </ul>
    </main>
  );
}
