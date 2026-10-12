import { useEffect, useMemo, useState } from 'react';
import {
  ArrowRight,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  FileText,
  Info,
  Layers,
  Lock,
  Printer,
  RefreshCw,
  Send,
  Shield,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import TaggedDocument from '../components/TaggedDocument';
import ProgressBar from '../components/ProgressBar';
import { useGovernance } from '../context/GovernanceContext';
import { FILING_METADATA } from '../data/gienData';
import { fakeHash, fakeSignature, truncateHash } from '../data/helpers';
import {
  DISPATCH_PROTOCOL_STAGES,
  SUBMISSION_SECTIONS,
  SUPERVISORY_MANIFEST_ARTEFACTS,
} from '../data/submissionData';

const PACKAGE_TYPES = [
  'Daily Supervisory Brief (SGR-028 filing)',
  'Quarterly Compliance Report',
  'Incident Notification',
  'Treaty Audit Submission',
  'Ω-GAR Dissolution Notice',
  'Supervisory College Transmission',
];

const TARGET_AUDIENCES = [
  'Regulator',
  'Supervisory College',
  'Internal',
  'Executive',
  'Redacted Public Version',
];

export default function SubmissionPackages() {
  const { role, evaluationWindow, filingRef } = useGovernance();

  // Step state (1..4)
  const [step, setStep] = useState<number>(1);

  // Step 1: Configuration
  const [packageType, setPackageType] = useState<string>(PACKAGE_TYPES[0]);
  const [targetAudience, setTargetAudience] = useState<string>(
    role === 'EXECUTIVE' ? 'Executive' : 'Regulator'
  );
  const [filingReference, setFilingReference] = useState<string>(
    FILING_METADATA.reference || filingRef
  );
  const [evalWindow, setEvalWindow] = useState<string>(evaluationWindow);

  // Step 2: Content Selection
  const initialSelectedIds = useMemo(() => {
    if (role === 'EXECUTIVE') {
      return SUBMISSION_SECTIONS.filter((s) => s.defaultSelectedExecutive).map((s) => s.id);
    }
    return SUBMISSION_SECTIONS.map((s) => s.id);
  }, [role]);

  const [selectedSectionIds, setSelectedSectionIds] = useState<string[]>(initialSelectedIds);

  // Sync role changes if user switches role in context
  useEffect(() => {
    if (role === 'EXECUTIVE') {
      setSelectedSectionIds(SUBMISSION_SECTIONS.filter((s) => s.defaultSelectedExecutive).map((s) => s.id));
      setTargetAudience('Executive');
    } else {
      setSelectedSectionIds(SUBMISSION_SECTIONS.map((s) => s.id));
      setTargetAudience('Regulator');
    }
  }, [role]);

  // Step 3 Preview State
  const [expandedSignature, setExpandedSignature] = useState<boolean>(false);

  // Step 4 Export & Transmission State
  const [copyFeedback, setCopyFeedback] = useState<boolean>(false);

  // Modal transmission simulation
  const [simulatingTransmission, setSimulatingTransmission] = useState<boolean>(false);
  const [transmissionStep, setTransmissionStep] = useState<number>(0);
  const [transmissionCompleted, setTransmissionCompleted] = useState<boolean>(false);

  // Inline archive generation state
  const [generatingArchive, setGeneratingArchive] = useState<boolean>(false);
  const [archiveProgress, setArchiveProgress] = useState<number>(0);
  const [generatedArchiveData, setGeneratedArchiveData] = useState<{
    archiveId: string;
    anchorHash: string;
  } | null>(null);

  // Manifest table pagination state
  const [manifestPage, setManifestPage] = useState<number>(1);
  const pageSize = 5;

  // Computed hashes for package
  const joinedIds = selectedSectionIds.slice().sort().join(':');
  const packageMerkleRoot = useMemo(() => {
    return fakeHash(`merkle-package:${filingReference}:${joinedIds}`);
  }, [filingReference, joinedIds]);

  const fullPqcSignature = useMemo(() => {
    return fakeHash(`pqc-sig-ml-dsa-65:${filingReference}:${packageMerkleRoot}`);
  }, [filingReference, packageMerkleRoot]);

  // Toggle individual section selection
  const toggleSection = (id: string) => {
    setSelectedSectionIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const selectAllSections = () => {
    setSelectedSectionIds(SUBMISSION_SECTIONS.map((s) => s.id));
  };

  const clearAllSections = () => {
    setSelectedSectionIds([]);
  };

  // Copy JSON action
  const handleCopyJSON = async () => {
    const selectedSectionsData = SUBMISSION_SECTIONS.filter((s) =>
      selectedSectionIds.includes(s.id)
    );

    const jsonPayload = {
      filingReference,
      packageType,
      targetAudience,
      evaluationWindow: evalWindow,
      pqcSignatureAlgorithm: FILING_METADATA.pqcSignatureAlgorithm,
      merkleRoot: packageMerkleRoot,
      pqcSignature: fullPqcSignature,
      generatedAt: new Date().toISOString(),
      sectionCount: selectedSectionsData.length,
      sections: selectedSectionsData.map((s) => ({
        id: s.id,
        title: s.title,
        abstract: s.abstract,
        content: s.content,
      })),
    };

    try {
      await navigator.clipboard.writeText(JSON.stringify(jsonPayload, null, 2));
      setCopyFeedback(true);
      setTimeout(() => setCopyFeedback(false), 2000);
    } catch {
      // Fallback if clipboard API unavailable
    }
  };

  // Transmission simulation modal handler
  const startTransmissionSimulation = () => {
    setSimulatingTransmission(true);
    setTransmissionStep(1);
    setTransmissionCompleted(false);
  };

  useEffect(() => {
    if (!simulatingTransmission) return;
    if (transmissionStep >= 6) {
      setTransmissionCompleted(true);
      return;
    }

    const timer = setInterval(() => {
      setTransmissionStep((prev) => {
        if (prev >= 6) {
          clearInterval(timer);
          setTransmissionCompleted(true);
          return 6;
        }
        return prev + 1;
      });
    }, 900);

    return () => clearInterval(timer);
  }, [simulatingTransmission, transmissionStep]);

  const closeTransmissionModal = () => {
    setSimulatingTransmission(false);
    setTransmissionStep(0);
    setTransmissionCompleted(false);
  };

  // Inline Archive Generation handler
  const handleGenerateArchive = () => {
    setGeneratingArchive(true);
    setArchiveProgress(0);
    setGeneratedArchiveData(null);

    const interval = setInterval(() => {
      setArchiveProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setGeneratingArchive(false);
          setGeneratedArchiveData({
            archiveId: `ARCHIVE-${new Date().toISOString().slice(0, 10)}-${filingReference.slice(-3)}`,
            anchorHash: fakeHash(`archive-anchor:${filingReference}:${Date.now()}`),
          });
          return 100;
        }
        return prev + 25;
      });
    }, 400);
  };

  // Pagination for corpus manifest table
  const totalPages = Math.ceil(SUPERVISORY_MANIFEST_ARTEFACTS.length / pageSize);
  const currentManifestItems = useMemo(() => {
    const start = (manifestPage - 1) * pageSize;
    return SUPERVISORY_MANIFEST_ARTEFACTS.slice(start, start + pageSize);
  }, [manifestPage]);

  return (
    <div className="space-y-8">
      {/* Header */}
      <PageHeader
        title="Regulator-Ready Submission Package Builder"
        subtitle="4-step wizard for assembling, verifying, previewing, and transmitting regulatory filings and supervisory college packages."
        crumbs={[
          { label: 'Supervisory Portal', to: '/' },
          { label: 'Submission Packages' },
        ]}
        actions={
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-400">Current Role:</span>
            <span className="rounded bg-indigo-500/20 px-2.5 py-1 text-xs font-semibold text-indigo-300 border border-indigo-500/30">
              {role}
            </span>
          </div>
        }
      />

      {role === 'EXECUTIVE' && (
        <div className="no-print rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-amber-300 flex items-center gap-3">
          <Info className="h-5 w-5 shrink-0 text-amber-400" />
          <div className="text-sm">
            <span className="font-semibold">Executive Mode Active:</span> Pre-configured high-level defaults are selected. Advanced technical details are streamlined for rapid submission review.
          </div>
        </div>
      )}

      {/* 4-Step Wizard Container */}
      <div className="rounded-xl border border-gray-700 bg-gray-800/50 shadow-xl overflow-hidden">
        {/* Stepper Navigation Bar */}
        <div className="no-print border-b border-gray-700 bg-gray-900/80 p-4">
          <nav aria-label="Wizard Steps" className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              { num: 1, label: 'Configuration', desc: 'Type & Reference' },
              { num: 2, label: 'Content Selection', desc: `${selectedSectionIds.length} sections` },
              { num: 3, label: 'Preview & Attestation', desc: 'Print-Plain Layout' },
              { num: 4, label: 'Export & Transmission', desc: 'PDF / JSON / Transmission' },
            ].map((s) => {
              const isActive = step === s.num;
              const isDone = step > s.num;
              return (
                <button
                  key={s.num}
                  type="button"
                  onClick={() => setStep(s.num)}
                  className={`flex items-center gap-3 rounded-lg border p-3 text-left transition-all ${
                    isActive
                      ? 'border-indigo-500 bg-indigo-950/40 text-gray-100 ring-1 ring-indigo-500/50'
                      : isDone
                      ? 'border-emerald-500/40 bg-emerald-950/20 text-emerald-300 hover:border-emerald-500'
                      : 'border-gray-700/60 bg-gray-800/30 text-gray-400 hover:border-gray-600 hover:text-gray-200'
                  }`}
                  aria-current={isActive ? 'step' : undefined}
                >
                  <div
                    className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full font-mono text-xs font-bold ${
                      isActive
                        ? 'bg-indigo-600 text-white'
                        : isDone
                        ? 'bg-emerald-600 text-white'
                        : 'bg-gray-700 text-gray-300'
                    }`}
                  >
                    {isDone ? <Check className="h-4 w-4" /> : s.num}
                  </div>
                  <div className="hidden sm:block overflow-hidden">
                    <p className="text-xs font-semibold truncate">{s.label}</p>
                    <p className="text-[11px] text-gray-400 truncate">{s.desc}</p>
                  </div>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Step Content Area */}
        <div className="p-6">
          {/* STEP 1: CONFIGURATION */}
          {step === 1 && (
            <div className="space-y-6 max-w-3xl">
              <div>
                <h2 className="text-lg font-semibold text-gray-100">Step 1: Package Configuration</h2>
                <p className="text-xs text-gray-400 mt-1">
                  Specify filing classification, target recipient audience, and administrative metadata.
                </p>
              </div>

              <div className="grid gap-5 sm:grid-cols-2">
                <div>
                  <label htmlFor="package-type" className="block text-xs font-medium text-gray-300 mb-1.5">
                    Package Type
                  </label>
                  <select
                    id="package-type"
                    value={packageType}
                    onChange={(e) => setPackageType(e.target.value)}
                    className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 focus:border-indigo-500 focus:outline-none"
                  >
                    {PACKAGE_TYPES.map((pt) => (
                      <option key={pt} value={pt}>
                        {pt}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="target-audience" className="block text-xs font-medium text-gray-300 mb-1.5">
                    Target Audience
                  </label>
                  <select
                    id="target-audience"
                    value={targetAudience}
                    onChange={(e) => setTargetAudience(e.target.value)}
                    className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 focus:border-indigo-500 focus:outline-none"
                  >
                    {TARGET_AUDIENCES.map((ta) => (
                      <option key={ta} value={ta}>
                        {ta}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid gap-5 sm:grid-cols-2">
                <div>
                  <label htmlFor="filing-ref" className="block text-xs font-medium text-gray-300 mb-1.5">
                    Auto-Generated Filing Reference
                  </label>
                  <div className="relative">
                    <input
                      id="filing-ref"
                      type="text"
                      value={filingReference}
                      onChange={(e) => setFilingReference(e.target.value)}
                      className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 font-mono text-sm text-gray-100 focus:border-indigo-500 focus:outline-none"
                    />
                  </div>
                  <p className="mt-1 text-[11px] text-gray-500">
                    Prefilled from SGR-028 filing metadata. Editable if generating derivative submission.
                  </p>
                </div>

                <div>
                  <label htmlFor="eval-window" className="block text-xs font-medium text-gray-300 mb-1.5">
                    Evaluation Window (ISO 8601 UTC)
                  </label>
                  <input
                    id="eval-window"
                    type="text"
                    value={evalWindow}
                    onChange={(e) => setEvalWindow(e.target.value)}
                    className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 font-mono text-sm text-gray-300 focus:border-indigo-500 focus:outline-none"
                  />
                  <p className="mt-1 text-[11px] text-gray-500">
                    Synchronized from active GovernanceContext telemetry window.
                  </p>
                </div>
              </div>

              <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-4 space-y-2">
                <p className="text-xs font-semibold text-gray-300 flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-cyan-400" />
                  PQC Cryptographic Binding Target
                </p>
                <div className="grid grid-cols-2 gap-4 text-xs font-mono text-gray-400 pt-1">
                  <div>
                    <span className="text-gray-500">Algorithm:</span> {FILING_METADATA.pqcSignatureAlgorithm}
                  </div>
                  <div>
                    <span className="text-gray-500">Ledger Block:</span> #8412337
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* STEP 2: CONTENT SELECTION */}
          {step === 2 && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-semibold text-gray-100">Step 2: Content Section Selection</h2>
                  <p className="text-xs text-gray-400 mt-1">
                    Select sections to include in this submission package. Checked sections contribute directly to the Merkle tree and PQC attestation block.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={selectAllSections}
                    className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 hover:text-white"
                  >
                    Select All
                  </button>
                  <button
                    type="button"
                    onClick={clearAllSections}
                    className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 hover:text-white"
                  >
                    Clear All
                  </button>
                </div>
              </div>

              <div className="text-xs font-semibold text-indigo-300 flex items-center gap-2">
                <Layers className="h-4 w-4 text-indigo-400" />
                {selectedSectionIds.length} of {SUBMISSION_SECTIONS.length} sections selected
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                {SUBMISSION_SECTIONS.map((sec) => {
                  const isChecked = selectedSectionIds.includes(sec.id);
                  return (
                    <label
                      key={sec.id}
                      className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3.5 transition-all ${
                        isChecked
                          ? 'border-indigo-500/60 bg-indigo-950/20 text-gray-100'
                          : 'border-gray-700/80 bg-gray-900/40 text-gray-400 hover:border-gray-600'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleSection(sec.id)}
                        className="mt-1 h-4 w-4 rounded border-gray-700 bg-gray-900 text-indigo-600 focus:ring-indigo-500"
                      />
                      <div className="space-y-1">
                        <p className="text-sm font-semibold text-gray-200">{sec.title}</p>
                        <p className="text-xs text-gray-400 line-clamp-2 leading-relaxed">{sec.abstract}</p>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
          )}

          {/* STEP 3: PREVIEW & ATTESTATION */}
          {step === 3 && (
            <div className="space-y-6">
              <div className="no-print flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-semibold text-gray-100">Step 3: Document Preview & Attestation</h2>
                  <p className="text-xs text-gray-400 mt-1">
                    Preview assembled submission package. Formatted with visible tagged section headers and cryptographic Merkle proof block.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => globalThis.print()}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white shadow hover:bg-indigo-500"
                >
                  <Printer className="h-4 w-4" />
                  Print / Save PDF
                </button>
              </div>

              {/* Document Pane styled print-plain */}
              <div className="print-plain space-y-6 rounded-xl border border-gray-700 bg-gray-900/90 p-6 shadow-inner">
                {/* Document Metadata Banner */}
                <div className="border-b border-gray-700 pb-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-xs font-bold uppercase tracking-widest text-indigo-400">
                      REGULATORY FILING SUBMISSION PACKAGE
                    </span>
                    <span className="font-mono text-xs text-gray-400">Filing Ref: {filingReference}</span>
                  </div>
                  <h1 className="text-xl font-bold text-gray-50">{packageType}</h1>
                  <div className="flex flex-wrap gap-4 text-xs font-mono text-gray-400 pt-1">
                    <div>
                      <span className="text-gray-500">Target Audience:</span> {targetAudience}
                    </div>
                    <div>
                      <span className="text-gray-500">Evaluation Window:</span> {evalWindow}
                    </div>
                    <div>
                      <span className="text-gray-500">Filing Date:</span> 2026-10-10
                    </div>
                  </div>
                </div>

                {/* Render Selected Sections via TaggedDocument */}
                {selectedSectionIds.length === 0 ? (
                  <div className="p-8 text-center text-gray-500 italic border border-dashed border-gray-700 rounded-lg">
                    No sections selected. Go back to Step 2 to choose sections.
                  </div>
                ) : (
                  SUBMISSION_SECTIONS.filter((sec) => selectedSectionIds.includes(sec.id)).map((sec) => (
                    <TaggedDocument key={sec.id} title={sec.title} abstract={sec.abstract}>
                      <p className="text-sm text-gray-300 leading-relaxed font-sans">{sec.content}</p>
                    </TaggedDocument>
                  ))
                )}

                {/* Cryptographic Attestation Footer in Document */}
                <div className="rounded-lg border border-gray-700 bg-gray-950 p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                    <span className="font-mono text-xs font-semibold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Shield className="h-4 w-4" />
                      PACKAGE CRYPTOGRAPHIC ATTESTATION BLOCK
                    </span>
                    <StatusBadge variant="VERIFIED" label="SEALED & VERIFIED" />
                  </div>

                  <div className="grid gap-2 text-xs font-mono">
                    <div>
                      <span className="text-gray-500">Package Merkle Root:</span>{' '}
                      <span className="text-gray-200 select-all">{packageMerkleRoot}</span>
                    </div>

                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-gray-500">PQC Signature (ML-DSA-65):</span>
                        <button
                          type="button"
                          onClick={() => setExpandedSignature((e) => !e)}
                          className="no-print text-[11px] text-indigo-400 hover:underline flex items-center gap-1"
                        >
                          {expandedSignature ? 'Truncate Signature' : 'Expand Full Signature'}
                          <ChevronDown className={`h-3 w-3 transition-transform ${expandedSignature ? 'rotate-180' : ''}`} />
                        </button>
                      </div>
                      <div className="mt-1 rounded bg-gray-900 p-2 text-[11px] text-indigo-300 break-all border border-gray-800">
                        {expandedSignature ? fullPqcSignature : truncateHash(fullPqcSignature, 20, 16)}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* STEP 4: EXPORT & TRANSMISSION */}
          {step === 4 && (
            <div className="space-y-6 max-w-4xl">
              <div>
                <h2 className="text-lg font-semibold text-gray-100">Step 4: Export & Supervisory College Transmission</h2>
                <p className="text-xs text-gray-400 mt-1">
                  Execute final dispatch protocols, copy machine-readable OSCAL JSON payloads, or trigger live simulated transmission.
                </p>
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                {/* Option 1: PDF Print */}
                <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-5 space-y-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-2.5 text-gray-100 font-semibold text-sm">
                      <Printer className="h-5 w-5 text-indigo-400" />
                      Download / Print as PDF
                    </div>
                    <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">
                      Generates a print-friendly document using the browser's native print engine. Formatted for regulatory archive compliance.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => globalThis.print()}
                    className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-indigo-500 transition-colors"
                  >
                    <Printer className="h-4 w-4" />
                    Print / Download PDF
                  </button>
                </div>

                {/* Option 2: Copy JSON */}
                <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-5 space-y-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-2.5 text-gray-100 font-semibold text-sm">
                      <Copy className="h-5 w-5 text-indigo-400" />
                      Copy Machine-Readable JSON
                    </div>
                    <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">
                      Copies complete machine-readable OSCAL and Merkle tree payload to clipboard for automated API ingestion.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleCopyJSON}
                    className="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-indigo-500/50 bg-indigo-950/40 px-4 py-2.5 text-xs font-semibold text-indigo-300 hover:bg-indigo-900/60 transition-colors"
                  >
                    {copyFeedback ? (
                      <>
                        <Check className="h-4 w-4 text-emerald-400" />
                        Copied to Clipboard!
                      </>
                    ) : (
                      <>
                        <Copy className="h-4 w-4" />
                        Copy OSCAL JSON Payload
                      </>
                    )}
                  </button>
                </div>

                {/* Option 3: Simulate Transmission */}
                <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-5 space-y-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-2.5 text-gray-100 font-semibold text-sm">
                      <Send className="h-5 w-5 text-cyan-400" />
                      Simulate Transmission
                    </div>
                    <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">
                      Executes 6-stage protocol dispatch to the BIS/FSB Supervisory College endpoint over PQC Kyber KEM encryption.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={startTransmissionSimulation}
                    className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors"
                  >
                    <Send className="h-4 w-4" />
                    Simulate College Transmission
                  </button>
                </div>

                {/* Option 4: Generate Merkle-Anchored Archive */}
                <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-5 space-y-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-2.5 text-gray-100 font-semibold text-sm">
                      <Lock className="h-5 w-5 text-emerald-400" />
                      Generate Merkle-Anchored Archive
                    </div>
                    <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">
                      Creates a self-verifying, immutable archive bundle anchored directly to WORM audit ledger block #8412337.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleGenerateArchive}
                    disabled={generatingArchive}
                    className="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-emerald-500/50 bg-emerald-950/30 px-4 py-2.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-900/40 disabled:opacity-50 transition-colors"
                  >
                    <Lock className="h-4 w-4" />
                    {generatingArchive ? 'Computing Anchor...' : 'Generate WORM Archive'}
                  </button>
                </div>
              </div>

              {/* Inline Progress / Result for Archive Generation */}
              {generatingArchive && (
                <div className="rounded-lg border border-indigo-500/30 bg-indigo-950/30 p-4 space-y-2">
                  <div className="flex justify-between text-xs text-gray-300">
                    <span className="font-semibold">Building WORM Merkle Archive...</span>
                    <span className="font-mono">{archiveProgress}%</span>
                  </div>
                  <ProgressBar value={archiveProgress} color="bg-indigo-500" />
                </div>
              )}

              {generatedArchiveData && !generatingArchive && (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/30 p-4 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
                    <ShieldCheck className="h-4 w-4" />
                    Merkle-Anchored Archive Generated Successfully
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-xs font-mono text-gray-300 pt-1">
                    <div>
                      <span className="text-gray-500">Archive ID:</span> {generatedArchiveData.archiveId}
                    </div>
                    <div>
                      <span className="text-gray-500">Anchor Hash:</span> {truncateHash(generatedArchiveData.anchorHash, 14, 8)}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Stepper Footer Controls */}
          <div className="no-print mt-8 flex items-center justify-between border-t border-gray-700 pt-4">
            <button
              type="button"
              onClick={() => setStep((s) => Math.max(1, s - 1))}
              disabled={step === 1}
              className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-xs font-semibold text-gray-300 hover:bg-gray-700 disabled:opacity-40"
            >
              Back
            </button>

            <span className="text-xs text-gray-400">Step {step} of 4</span>

            {step < 4 ? (
              <button
                type="button"
                onClick={() => setStep((s) => Math.min(4, s + 1))}
                className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500"
              >
                Next Step
                <ChevronRight className="h-4 w-4" />
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setStep(1)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-xs font-semibold text-gray-300 hover:bg-gray-700"
              >
                Reset Wizard
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Modal for Transmission Simulation */}
      {simulatingTransmission && (
        <div className="no-print fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4" role="dialog" aria-modal="true">
          <div className="w-full max-w-lg rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl space-y-6">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <div className="flex items-center gap-2">
                <Send className="h-5 w-5 text-cyan-400 animate-pulse" />
                <h3 className="text-base font-semibold text-gray-100">
                  Supervisory College Transmission Protocol
                </h3>
              </div>
              <button
                type="button"
                onClick={closeTransmissionModal}
                className="text-gray-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-3">
              {[
                'Package Assembly & Merkle Root Computation',
                'PQC Signature Application (ML-DSA-65)',
                'Encryption (CRYSTALS-Kyber KEM)',
                'Supervisory College Endpoint Transmission',
                'Receipt Acknowledgment & Merkle Validation',
                'Archive Seal & WORM Ledger Anchoring',
              ].map((stageTitle, idx) => {
                const stageNum = idx + 1;
                const isCurrent = transmissionStep === stageNum;
                const isDone = transmissionStep > stageNum || transmissionCompleted;

                return (
                  <div
                    key={stageTitle}
                    className={`flex items-center justify-between rounded-lg border p-3 text-xs transition-all ${
                      isCurrent
                        ? 'border-cyan-500 bg-cyan-950/40 text-cyan-200'
                        : isDone
                        ? 'border-emerald-500/40 bg-emerald-950/20 text-emerald-300'
                        : 'border-gray-800 bg-gray-950/40 text-gray-500'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <span
                        className={`flex h-5 w-5 items-center justify-center rounded-full font-mono text-[10px] font-bold ${
                          isDone
                            ? 'bg-emerald-600 text-white'
                            : isCurrent
                            ? 'bg-cyan-500 text-black'
                            : 'bg-gray-800 text-gray-500'
                        }`}
                      >
                        {isDone ? <Check className="h-3 w-3" /> : stageNum}
                      </span>
                      <span>{stageTitle}</span>
                    </div>
                    {isCurrent && !transmissionCompleted && (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin text-cyan-400" />
                    )}
                    {isDone && <StatusBadge variant="VERIFIED" label="COMPLETE" />}
                  </div>
                );
              })}
            </div>

            {transmissionCompleted && (
              <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 p-4 space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
                  <ShieldCheck className="h-4 w-4" />
                  Transmission Confirmed by Supervisory College
                </div>
                <div className="text-xs font-mono text-gray-300 space-y-1 pt-1">
                  <div>
                    <span className="text-gray-500">Receipt Hash:</span>{' '}
                    {fakeHash(`transmission-receipt:${filingReference}`)}
                  </div>
                  <div>
                    <span className="text-gray-500">Status:</span> 200 OK — Merkle Root Match Validated
                  </div>
                </div>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={closeTransmissionModal}
                className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-xs font-semibold text-gray-200 hover:bg-gray-700"
              >
                Close Protocol Monitor
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SECTION BELOW WIZARD: Bundled Dispatch Transmission Protocol Display */}
      <section className="rounded-xl border border-gray-700 bg-gray-800/40 p-6 space-y-6">
        <div>
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-gray-100 flex items-center gap-2">
              <Zap className="h-5 w-5 text-amber-400" />
              Bundled Dispatch Transmission Protocol Status — {FILING_METADATA.reference}
            </h2>
            <StatusBadge variant="PENDING" label="CYCLE CLOSURE PENDING" />
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Real-time pipeline monitoring for active daily filing SGR-028-CFE-2026-07-001.
          </p>
        </div>

        {/* Stepper / Timeline for stages 1-6 */}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {DISPATCH_PROTOCOL_STAGES.map((stg) => (
            <div
              key={stg.stageNumber}
              className={`rounded-lg border p-4 space-y-2 transition-all ${
                stg.status === 'DONE'
                  ? 'border-emerald-500/30 bg-emerald-950/15'
                  : 'border-amber-500/30 bg-amber-950/15'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-gray-400">
                  STAGE {stg.stageNumber}
                </span>
                <StatusBadge
                  variant={stg.status === 'DONE' ? 'VERIFIED' : 'PENDING'}
                  label={stg.status === 'DONE' ? 'DONE' : 'PENDING (23:59)'}
                />
              </div>
              <p className="text-xs font-semibold text-gray-200">{stg.title}</p>
              <p className="text-[11px] text-gray-400 leading-relaxed">{stg.description}</p>
              {stg.timestamp && (
                <div className="flex items-center gap-1 font-mono text-[10px] text-gray-500 pt-1">
                  <Clock className="h-3 w-3" />
                  {stg.timestamp}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* SECTION BELOW WIZARD: Supervisory Corpus Manifest Table */}
      <section className="rounded-xl border border-gray-700 bg-gray-800/40 p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-semibold text-gray-100 flex items-center gap-2">
              <FileText className="h-5 w-5 text-indigo-400" />
              Supervisory Corpus Manifest
            </h2>
            <p className="text-xs text-gray-400 mt-1">
              Indexed inventory of 14 supervisory artefacts anchored in current filing SGR-028.
            </p>
          </div>
          <span className="text-xs font-mono text-gray-400">
            Total Artefacts: {SUPERVISORY_MANIFEST_ARTEFACTS.length}
          </span>
        </div>

        <div className="overflow-x-auto rounded-lg border border-gray-700">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-gray-700 bg-gray-900/80 font-mono text-[11px] text-gray-400">
              <tr>
                <th className="px-4 py-3">Artefact ID</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Phase</th>
                <th className="px-4 py-3">Timestamp (ISO 8601)</th>
                <th className="px-4 py-3">Merkle Hash</th>
                <th className="px-4 py-3">PQC Signature</th>
                <th className="px-4 py-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y border-gray-700 bg-gray-900/40 text-gray-300 font-mono">
              {currentManifestItems.map((art) => (
                <tr key={art.artefactId} className="hover:bg-gray-800/50">
                  <td className="px-4 py-3 font-semibold text-gray-200">{art.artefactId}</td>
                  <td className="px-4 py-3 font-sans text-gray-300">{art.type}</td>
                  <td className="px-4 py-3">
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-indigo-300 border border-gray-700">
                      {art.phase}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{art.timestamp}</td>
                  <td className="px-4 py-3 text-indigo-300">{truncateHash(art.merkleHash, 8, 4)}</td>
                  <td className="px-4 py-3 text-gray-400">{truncateHash(art.pqcSignature, 8, 4)}</td>
                  <td className="px-4 py-3 text-right font-sans">
                    <StatusBadge variant={art.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination controls */}
        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-gray-400">
            Showing Page {manifestPage} of {totalPages}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setManifestPage((p) => Math.max(1, p - 1))}
              disabled={manifestPage === 1}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-40"
            >
              Previous
            </button>
            <button
              type="button"
              onClick={() => setManifestPage((p) => Math.min(totalPages, p + 1))}
              disabled={manifestPage === totalPages}
              className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
