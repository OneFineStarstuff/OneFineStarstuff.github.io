import { useMemo, useState } from "react";
import { BookOpen, CheckCircle2, Download, ExternalLink, FileCheck2, Plus, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import {
  EVIDENCE_VERDICTS,
  validateClaimRecord,
  validateClaimSet,
  type ClaimRecord,
  type EvidenceSource,
  type EvidenceVerdict,
} from "../evidence/claim-validation.mjs";

type SourceDraft = { url: string; title: string; excerpt: string };
type ReviewDraft = { reviewer: string; rationale: string };

const evalsSourceUrl = "https://developers.openai.com/api/docs/guides/evals";
const initialClaims: ClaimRecord[] = [{
  id: "CLM-EVALS-001",
  text: "OpenAI's Evals platform is scheduled to become read-only on 31 October 2026 and shut down on 30 November 2026.",
  sources: [{
    id: "SRC-OPENAI-EVALS-DOCS",
    url: evalsSourceUrl,
    title: "Working with evals — OpenAI API",
    excerpt: "Evals will become read-only for existing users on October 31, 2026, and the platform is scheduled to shut down on November 30, 2026.",
    retrievedAt: "2026-10-12T05:00:00.000Z",
  }],
  verdict: "UNVERIFIED",
}];

function downloadBundle(content: string) {
  const blob = new Blob([content], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "gien-claim-evidence-bundle.json";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function validationLabel(result: ReturnType<typeof validateClaimRecord>) {
  if (result.eligibleForRelease) return "STRUCTURALLY READY · REVIEWED";
  if (result.issues.some((issue) => issue.code === "MISSING_REVIEW" || issue.code === "MISSING_REVIEWER" || issue.code === "MISSING_REVIEW_RATIONALE")) {
    return "REVIEW REQUIRED";
  }
  return "BLOCKED · EVIDENCE GAP";
}

export default function EvidenceValidationPage() {
  const [claims, setClaims] = useState<ClaimRecord[]>(initialClaims);
  const [newClaimText, setNewClaimText] = useState("");
  const [sourceDrafts, setSourceDrafts] = useState<Record<string, SourceDraft>>({});
  const [reviewDrafts, setReviewDrafts] = useState<Record<string, ReviewDraft>>({});
  const [notice, setNotice] = useState("");
  const results = useMemo(() => validateClaimSet(claims), [claims]);
  const now = new Date().toISOString();

  const updateClaim = (claimId: string, updater: (claim: ClaimRecord) => ClaimRecord) => {
    setClaims((current) => current.map((claim) => {
      if (claim.id !== claimId) return claim;
      const updated = updater(claim);
      // Any evidence-affecting change invalidates the prior reviewer attestation.
      return { ...updated, review: undefined };
    }));
    setNotice("Claim or evidence changed. Any prior review was cleared; re-review before release.");
  };

  const addClaim = () => {
    const text = newClaimText.trim();
    if (!text) {
      setNotice("Enter a claim before adding it to the review queue.");
      return;
    }
    const id = "CLM-" + Date.now();
    setClaims((current) => [...current, { id, text, sources: [], verdict: "UNVERIFIED" }]);
    setReviewDrafts((current) => ({ ...current, [id]: { reviewer: "", rationale: "" } }));
    setSourceDrafts((current) => ({ ...current, [id]: { url: "", title: "", excerpt: "" } }));
    setNewClaimText("");
    setNotice("Claim added in local browser state. Attach source evidence and record a human review.");
  };

  const attachSource = (claim: ClaimRecord) => {
    const draft = sourceDrafts[claim.id] ?? { url: "", title: "", excerpt: "" };
    if (!draft.url.trim() || !draft.title.trim() || !draft.excerpt.trim()) {
      setNotice("Enter the source URL, title, and supporting excerpt before attaching it.");
      return;
    }
    const newSource: EvidenceSource = {
      id: "SRC-" + claim.id + "-" + Date.now(),
      url: draft.url.trim(),
      title: draft.title.trim(),
      excerpt: draft.excerpt.trim(),
      retrievedAt: new Date().toISOString(),
    };
    updateClaim(claim.id, (current) => ({ ...current, sources: [...current.sources, newSource], verdict: "UNVERIFIED" }));
    setSourceDrafts((current) => ({ ...current, [claim.id]: { url: "", title: "", excerpt: "" } }));
  };

  const recordReview = (claim: ClaimRecord) => {
    const draft = reviewDrafts[claim.id] ?? { reviewer: "", rationale: "" };
    if (claim.verdict === "UNVERIFIED") {
      setNotice("Choose an adjudicated verdict before recording the reviewer attestation.");
      return;
    }
    if (!draft.reviewer.trim() || !draft.rationale.trim()) {
      setNotice("Reviewer identity and review rationale are both required.");
      return;
    }
    setClaims((current) => current.map((item) => item.id === claim.id ? {
      ...item,
      review: { reviewer: draft.reviewer.trim(), rationale: draft.rationale.trim(), reviewedAt: new Date().toISOString() },
    } : item));
    setNotice("Reviewer attestation recorded locally. Structural validation is not a semantic truth check.");
  };

  const exportJson = () => {
    const payload = {
      schemaVersion: "gien.claim-evidence.v1",
      generatedAt: new Date().toISOString(),
      evidenceScope: "LOCAL_BROWSER_DEMO",
      semanticSupportAutomaticallyVerified: false,
      releaseEligible: results.releaseEligible,
      summary: {
        claimCount: results.claimCount,
        eligibleClaimCount: results.eligibleClaimCount,
        blockedClaimCount: results.blockedClaimCount,
      },
      claims,
      validation: results,
    };
    downloadBundle(JSON.stringify(payload, null, 2));
    setNotice("Exported a local JSON snapshot. Nothing was sent to an API or remote service.");
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-[0.18em] text-sky-300"><BookOpen size={15}/> Evidence operations / claim review</div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-100">Source-to-Claim Validation</h1>
        <p className="max-w-4xl text-sm leading-6 text-slate-400">Attach source records to individual claims, retain the exact passage reviewed, capture a named reviewer attestation, and apply deterministic completeness and freshness gates before a bundle can be marked evidence-qualified.</p>
      </header>

      <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4 text-sm leading-6 text-amber-100">
        <div className="mb-1 flex items-center gap-2 font-semibold"><ShieldAlert size={16}/> Prototype and validation boundary</div>
        This workspace keeps state in the browser only. It does not fetch URLs, establish that excerpts support a claim, persist records to a backend, or certify compliance. A SUPPORTED verdict is a human reviewer attestation; automated checks below are structural only. The 90-day freshness window is a configurable project default, not a regulatory requirement.
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-4"><div className="text-xs uppercase tracking-wide text-slate-400">Claims in queue</div><div className="mt-2 text-3xl font-semibold text-slate-100">{results.claimCount}</div></div>
        <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-4"><div className="text-xs uppercase tracking-wide text-slate-400">Structurally eligible</div><div className="mt-2 text-3xl font-semibold text-emerald-300">{results.eligibleClaimCount}</div></div>
        <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-4"><div className="text-xs uppercase tracking-wide text-slate-400">Blocked claims</div><div className="mt-2 text-3xl font-semibold text-amber-200">{results.blockedClaimCount}</div></div>
        <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-4"><div className="text-xs uppercase tracking-wide text-slate-400">Bundle gate</div><div className="mt-2 flex items-center gap-2 text-lg font-semibold">{results.releaseEligible ? <><ShieldCheck size={18} className="text-emerald-300"/> ELIGIBLE</> : <><ShieldAlert size={18} className="text-amber-300"/> BLOCKED</>}</div></div>
      </div>

      <section className="rounded-xl border border-slate-700 bg-slate-900/50 p-4 sm:p-5">
        <h2 className="text-base font-semibold text-slate-100">Add a claim</h2>
        <p className="mt-1 text-xs text-slate-400">Claims start UNVERIFIED and cannot pass the release gate until source evidence and a current review are recorded.</p>
        <div className="mt-3 flex flex-col gap-3 sm:flex-row">
          <textarea aria-label="Claim text" value={newClaimText} onChange={(event) => setNewClaimText(event.target.value)} rows={2} placeholder="Enter one independently reviewable factual claim…" className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"/>
          <button type="button" onClick={addClaim} className="inline-flex items-center justify-center gap-2 self-start rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500"><Plus size={16}/> Add claim</button>
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div><h2 className="text-lg font-semibold text-slate-100">Claim evidence queue</h2><p className="mt-1 text-xs text-slate-400">Inspect each source and excerpt. A source link by itself is not proof of semantic support.</p></div>
        <button type="button" onClick={exportJson} className="inline-flex items-center gap-2 rounded-lg border border-slate-600 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800"><Download size={15}/> Export JSON evidence bundle</button>
      </div>

      {claims.map((claim) => {
        const result = validateClaimRecord(claim);
        const sourceDraft = sourceDrafts[claim.id] ?? { url: "", title: "", excerpt: "" };
        const reviewDraft = reviewDrafts[claim.id] ?? { reviewer: "", rationale: "" };
        return (
          <section key={claim.id} className="overflow-hidden rounded-xl border border-slate-700 bg-slate-900/50">
            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-700 p-4 sm:p-5">
              <div className="min-w-0 flex-1"><div className="text-xs font-medium text-sky-300">{claim.id}</div><label className="mt-2 block text-xs font-medium text-slate-400">Claim statement</label><textarea aria-label={"Claim statement " + claim.id} value={claim.text} onChange={(event) => updateClaim(claim.id, (current) => ({ ...current, text: event.target.value }))} rows={2} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm leading-6 text-slate-100 focus:border-sky-400 focus:outline-none"/></div>
              <div className="min-w-[190px]"><div className="text-xs text-slate-400">Structural status</div><div className={"mt-2 inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold " + (result.eligibleForRelease ? "border-emerald-500/40 bg-emerald-950/40 text-emerald-200" : "border-amber-500/40 bg-amber-950/30 text-amber-200")}>{result.eligibleForRelease ? <CheckCircle2 size={14}/> : <ShieldAlert size={14}/>} {validationLabel(result)}</div><div className="mt-2 text-xs text-slate-400">{claim.sources.length} linked source(s)</div></div>
            </div>

            <div className="grid gap-4 p-4 sm:p-5 xl:grid-cols-2">
              <div className="space-y-3">
                <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100"><FileCheck2 size={15}/> Source evidence</h3>
                {claim.sources.map((source) => (
                  <article key={source.id} className="rounded-lg border border-slate-700 bg-slate-950/70 p-3">
                    <div className="flex items-start gap-2"><div className="min-w-0 flex-1"><div className="text-xs font-medium text-slate-200">{source.title}</div><a href={source.url} target="_blank" rel="noopener noreferrer" className="mt-1 inline-flex max-w-full items-center gap-1 break-all text-xs text-sky-300 underline">{source.url}<ExternalLink size={12}/></a><p className="mt-2 whitespace-pre-wrap text-xs leading-5 text-slate-300">{source.excerpt}</p><p className="mt-2 text-[11px] text-slate-500">Retrieved: {source.retrievedAt}</p></div><button type="button" aria-label={"Remove source " + source.id} onClick={() => updateClaim(claim.id, (current) => ({ ...current, sources: current.sources.filter((item) => item.id !== source.id), verdict: "UNVERIFIED" }))} className="rounded-md p-1 text-slate-400 hover:bg-slate-800 hover:text-rose-300"><Trash2 size={14}/></button></div>
                  </article>
                ))}
                <div className="space-y-2 rounded-lg border border-dashed border-slate-600 p-3">
                  <h4 className="text-xs font-semibold text-slate-200">Attach another source</h4>
                  <input aria-label={"Source URL for " + claim.id} type="url" value={sourceDraft.url} onChange={(event) => setSourceDrafts((current) => ({ ...current, [claim.id]: { ...sourceDraft, url: event.target.value } }))} placeholder="https://…" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"/>
                  <input aria-label={"Source title for " + claim.id} value={sourceDraft.title} onChange={(event) => setSourceDrafts((current) => ({ ...current, [claim.id]: { ...sourceDraft, title: event.target.value } }))} placeholder="Page/document title" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"/>
                  <textarea aria-label={"Source excerpt for " + claim.id} value={sourceDraft.excerpt} onChange={(event) => setSourceDrafts((current) => ({ ...current, [claim.id]: { ...sourceDraft, excerpt: event.target.value } }))} rows={3} placeholder="Paste the exact passage to be checked by a reviewer…" className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs leading-5 text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"/>
                  <button type="button" onClick={() => attachSource(claim)} className="inline-flex items-center gap-2 rounded-lg border border-slate-600 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800"><Plus size={13}/> Attach source</button>
                </div>
              </div>

              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-slate-100">Adjudication and review</h3>
                <label className="block text-xs font-medium text-slate-400">Evidence verdict
                  <select aria-label={"Verdict for " + claim.id} value={claim.verdict} onChange={(event) => updateClaim(claim.id, (current) => ({ ...current, verdict: event.target.value as EvidenceVerdict }))} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none">{EVIDENCE_VERDICTS.map((verdict) => <option key={verdict} value={verdict}>{verdict.replace(/_/g, " ")}</option>)}</select>
                </label>
                {claim.review && <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-3 text-xs text-emerald-100"><div className="font-semibold">Reviewer attestation recorded</div><p className="mt-1">{claim.review.reviewer} · {claim.review.reviewedAt}</p><p className="mt-1 text-emerald-100/80">{claim.review.rationale}</p></div>}
                <label className="block text-xs font-medium text-slate-400">Reviewer identity<input value={reviewDraft.reviewer} onChange={(event) => setReviewDrafts((current) => ({ ...current, [claim.id]: { ...reviewDraft, reviewer: event.target.value } }))} placeholder="Name or accountable identity" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"/></label>
                <label className="block text-xs font-medium text-slate-400">Review rationale<textarea value={reviewDraft.rationale} onChange={(event) => setReviewDrafts((current) => ({ ...current, [claim.id]: { ...reviewDraft, rationale: event.target.value } }))} rows={3} placeholder="Explain how the passage supports or contradicts the exact claim…" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm leading-5 text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"/></label>
                <button type="button" onClick={() => recordReview(claim)} disabled={claim.verdict === "UNVERIFIED" || !reviewDraft.reviewer.trim() || !reviewDraft.rationale.trim()} className="inline-flex items-center gap-2 rounded-lg bg-slate-700 px-3 py-2 text-xs font-semibold text-white enabled:hover:bg-slate-600 disabled:cursor-not-allowed"><CheckCircle2 size={14}/> Record reviewer attestation</button>
                <div className="rounded-lg border border-slate-700 bg-slate-950/70 p-3">
                  <div className="mb-2 text-xs font-semibold text-slate-200">Validation findings</div>
                  {result.issues.length === 0 ? <p className="flex items-center gap-2 text-xs text-emerald-300"><CheckCircle2 size={14}/> Structural checks passed. Semantic support still needs human judgment.</p> : <ul className="space-y-2">{result.issues.map((issue) => <li key={issue.code} className="flex gap-2 text-xs leading-5 text-amber-100"><ShieldAlert size={13} className="mt-0.5 shrink-0 text-amber-300"/><span><strong>{issue.code.replace(/_/g, " ")}:</strong> {issue.message}</span></li>)}</ul>}
                </div>
              </div>
            </div>
          </section>
        );
      })}

      {notice && <div role="status" aria-live="polite" className="rounded-lg border border-sky-500/30 bg-sky-950/30 p-3 text-sm text-sky-100">{notice}</div>}
      <div className="rounded-xl border border-slate-700 bg-slate-900/40 p-4 text-xs leading-5 text-slate-400"><strong className="text-slate-200">Release rule:</strong> the JSON bundle is eligible only when every claim has a valid source record, fresh retrieval timestamp, a human attestation, and verdict SUPPORTED. Contradicted, partially supported, outdated, missing, stale, or unreviewed evidence blocks eligibility. Eligibility is a workflow gate—not regulatory approval or independent assurance. <span className="mt-1 block">Bundle evaluation timestamp (UTC): {now}</span></div>
    </div>
  );
}
