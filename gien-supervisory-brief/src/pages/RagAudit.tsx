import { Download, FileText, Filter, Layers, Network, RefreshCw, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useMemo, useState } from 'react';
import ExpandableSection from '../components/ExpandableSection';
import NodeGraph, { GraphEdge, GraphNode } from '../components/NodeGraph';
import PageHeader from '../components/PageHeader';
import StatusBadge, { KV } from '../components/StatusBadge';
import Watermark, { watermarkProvenance, withWatermarkRow } from '../components/Watermark';
import { useGovernance } from '../context/GovernanceContext';
import { useToast } from '../context/ToastContext';
import { fakeHash, truncateHash } from '../data/helpers';
import { PII_FINDINGS, PROVENANCE_RECORDS, ProvenanceRecord } from '../data/ragData';

export default function RagAudit() {
  const { filingRef } = useGovernance();
  const { pushToast } = useToast();
  const provenance = watermarkProvenance(filingRef);

  // Filter states
  const [selectedSource, setSelectedSource] = useState<string>('ALL');
  const [selectedClassification, setSelectedClassification] = useState<string>('ALL');
  const [searchTerm, setSearchText] = useState<string>('');
  const [currentPage, setCurrentPage] = useState<number>(1);

  const pageSize = 6;

  // Filtered provenance rows
  const filteredRecords = useMemo(() => {
    return PROVENANCE_RECORDS.filter((rec) => {
      if (selectedSource !== 'ALL' && rec.sourceSystem !== selectedSource) return false;
      if (selectedClassification !== 'ALL' && rec.classification !== selectedClassification) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const matchId = rec.doc_id.toLowerCase().includes(term);
        const matchSource = rec.sourceSystem.toLowerCase().includes(term);
        const matchHash = rec.merkleHash.toLowerCase().includes(term);
        if (!matchId && !matchSource && !matchHash) return false;
      }
      return true;
    });
  }, [selectedSource, selectedClassification, searchTerm]);

  // Paginated records
  const totalPages = Math.max(1, Math.ceil(filteredRecords.length / pageSize));
  const activePage = Math.min(currentPage, totalPages);
  const paginatedRecords = useMemo(() => {
    const start = (activePage - 1) * pageSize;
    return filteredRecords.slice(start, start + pageSize);
  }, [filteredRecords, activePage]);

  // Lineage Node Graph (sources -> ingestion -> chunk store -> retrieval -> answer)
  const lineageNodes: GraphNode[] = [
    { id: 'src-1', label: 'Policy Engine', value: 0.85, status: 'NOMINAL' },
    { id: 'src-2', label: 'Control Library DB', value: 0.9, status: 'NOMINAL' },
    { id: 'src-3', label: 'OSCAL Registry', value: 0.8, status: 'NOMINAL' },
    { id: 'pipe-1', label: 'Ingestion Pipeline', value: 0.95, status: 'NOMINAL' },
    { id: 'store-1', label: 'Vector Chunk Store', value: 0.88, status: 'NOMINAL' },
    { id: 'ret-1', label: 'Hybrid Retriever', value: 0.92, status: 'NOMINAL' },
    { id: 'ans-1', label: 'Answer Synthesizer', value: 0.94, status: 'NOMINAL' },
  ];

  const lineageEdges: GraphEdge[] = [
    { from: 'src-1', to: 'pipe-1', weight: 0.9 },
    { from: 'src-2', to: 'pipe-1', weight: 0.85 },
    { from: 'src-3', to: 'pipe-1', weight: 0.8 },
    { from: 'pipe-1', to: 'store-1', weight: 0.95 },
    { from: 'store-1', to: 'ret-1', weight: 0.92 },
    { from: 'ret-1', to: 'ans-1', weight: 0.94 },
  ];

  // CSV Export handler
  const exportProvenanceCsv = () => {
    const watermarkRows = withWatermarkRow(filteredRecords.map((r) => ({ ...r })) as unknown as Record<string, unknown>[], filingRef);
    const headers = ['doc_id', 'sourceSystem', 'classification', 'ingested_at', 'chunk_count', 'pii_scan', 'license', 'merkleHash', 'watermark'];
    const csvLines = [headers.join(',')];

    watermarkRows.forEach((r) => {
      const row = [
        r.doc_id,
        r.sourceSystem,
        r.classification,
        r.ingested_at,
        r.chunk_count,
        r.pii_scan,
        r.license,
        r.merkleHash,
        r.watermark ? `"${r.watermark}"` : '',
      ];
      csvLines.push(row.join(','));
    });

    const blob = new Blob([csvLines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `RAG_Data_Provenance_${filingRef}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    pushToast('SUCCESS', `Exported ${filteredRecords.length} provenance records with watermark row.`);
  };

  const sourcesList = ['ALL', 'PolicyEngine', 'ControlDB', 'OSCAL-Hub', 'TreatyNet', 'IncidentLog', 'ModelRegistry'];
  const classificationsList = ['ALL', 'PUBLIC', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET', 'REGULATORY_ONLY'];

  return (
    <div className="space-y-8 pb-12">
      <Watermark />

      <PageHeader
        title="RAG Data Audit & Provenance Dashboard"
        subtitle="End-to-end data lineage, cryptographic document Merkle verification, and PII/licensing compliance findings."
        crumbs={[{ label: 'GIEN Governance', to: '/dashboard' }, { label: 'RAG Audit' }]}
        actions={
          <button
            type="button"
            onClick={exportProvenanceCsv}
            className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white shadow hover:bg-indigo-500 transition-colors"
          >
            <Download className="h-4 w-4" />
            Export provenance CSV
          </button>
        }
      />

      {/* End-to-End Lineage Graph */}
      <section aria-labelledby="lineage-heading">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-indigo-400" />
            <h2 id="lineage-heading" className="text-base font-bold text-gray-100">
              Document Data Lineage Topology
            </h2>
          </div>
          <span className="text-xs font-mono text-gray-400">
            Source Systems → Ingestion Engine → Chunk Store → Retrieval → Answer
          </span>
        </div>

        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
          <NodeGraph nodes={lineageNodes} edges={lineageEdges} size={440} />
        </div>
      </section>

      {/* Provenance Table Section */}
      <section aria-labelledby="provenance-table-heading" className="space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-cyan-400" />
            <h2 id="provenance-table-heading" className="text-base font-bold text-gray-100">
              18-Row Provenance Register
            </h2>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="relative flex items-center">
              <Search className="absolute left-2.5 h-3.5 w-3.5 text-gray-400" />
              <input
                type="text"
                placeholder="Search document ID / hash..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchText(e.target.value);
                  setCurrentPage(1);
                }}
                className="rounded border border-gray-700 bg-gray-900 pl-8 pr-3 py-1 text-xs text-gray-200 placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
              />
            </div>

            <select
              value={selectedSource}
              onChange={(e) => {
                setSelectedSource(e.target.value);
                setCurrentPage(1);
              }}
              className="rounded border border-gray-700 bg-gray-900 px-2.5 py-1 text-xs text-gray-200 focus:border-indigo-500 focus:outline-none"
            >
              {sourcesList.map((s) => (
                <option key={s} value={s}>
                  {s === 'ALL' ? 'All Sources' : s}
                </option>
              ))}
            </select>

            <select
              value={selectedClassification}
              onChange={(e) => {
                setSelectedClassification(e.target.value);
                setCurrentPage(1);
              }}
              className="rounded border border-gray-700 bg-gray-900 px-2.5 py-1 text-xs text-gray-200 focus:border-indigo-500 focus:outline-none"
            >
              {classificationsList.map((c) => (
                <option key={c} value={c}>
                  {c === 'ALL' ? 'All Classifications' : c}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Table Container */}
        <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800/40">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-700 bg-gray-900/80 font-semibold text-gray-300 uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-3">Doc ID</th>
                  <th className="px-4 py-3">Source System</th>
                  <th className="px-4 py-3">Classification</th>
                  <th className="px-4 py-3">Ingested At</th>
                  <th className="px-4 py-3">Chunks</th>
                  <th className="px-4 py-3">PII Scan</th>
                  <th className="px-4 py-3">License</th>
                  <th className="px-4 py-3">Merkle Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/60 font-mono text-gray-200">
                {paginatedRecords.length > 0 ? (
                  paginatedRecords.map((rec) => (
                    <tr key={rec.doc_id} className="hover:bg-gray-800/60 transition-colors">
                      <td className="px-4 py-3 font-semibold text-indigo-300">{rec.doc_id}</td>
                      <td className="px-4 py-3 text-gray-300 font-sans">{rec.sourceSystem}</td>
                      <td className="px-4 py-3">
                        <span className="rounded bg-gray-900 px-1.5 py-0.5 text-[10px] text-gray-300 border border-gray-700">
                          {rec.classification}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-400">{rec.ingested_at}</td>
                      <td className="px-4 py-3 text-cyan-400 font-bold">{rec.chunk_count}</td>
                      <td className="px-4 py-3">
                        <StatusBadge
                          variant={rec.pii_scan === 'MASKED' ? 'ELEVATED' : 'NOMINAL'}
                          label={rec.pii_scan}
                        />
                      </td>
                      <td className="px-4 py-3 text-gray-400 font-sans">{rec.license}</td>
                      <td className="px-4 py-3 text-indigo-400 font-mono">{rec.merkleHash}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-gray-400 font-sans">
                      No provenance records match the selected filter criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="flex items-center justify-between border-t border-gray-700 bg-gray-900/60 px-4 py-3 text-xs text-gray-400">
            <span>
              Showing {filteredRecords.length > 0 ? (activePage - 1) * pageSize + 1 : 0} to{' '}
              {Math.min(activePage * pageSize, filteredRecords.length)} of {filteredRecords.length} records
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={activePage === 1}
                className="rounded border border-gray-700 bg-gray-800 px-2.5 py-1 text-xs text-gray-300 disabled:opacity-50 hover:bg-gray-700 transition-colors"
              >
                Previous
              </button>
              <span className="font-mono text-gray-200">
                Page {activePage} of {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={activePage === totalPages}
                className="rounded border border-gray-700 bg-gray-800 px-2.5 py-1 text-xs text-gray-300 disabled:opacity-50 hover:bg-gray-700 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Expandable Section: PII and Licensing Findings */}
      <ExpandableSection
        title="PII and licensing findings"
        subtitle="Automated scanner audit findings across ingested documents and vector chunk indexes."
        defaultOpen={true}
        badge={<StatusBadge variant="ELEVATED" label="4 FINDINGS" />}
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 p-2">
          {PII_FINDINGS.map((finding) => (
            <div
              key={finding.id}
              className="flex flex-col justify-between rounded-md border border-gray-700/80 bg-gray-900/60 p-4 space-y-3"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className="font-mono text-xs font-bold text-indigo-400">{finding.id}</span>
                  <StatusBadge variant={finding.severity} />
                </div>
                <h3 className="text-xs font-bold text-gray-100">{finding.title}</h3>
                <p className="mt-1 text-[11px] text-gray-400">{finding.description}</p>
              </div>

              <div className="flex items-center justify-between border-t border-gray-800 pt-2 text-[11px] font-mono text-gray-400">
                <span>Source: <strong className="text-gray-300">{finding.sourceSystem}</strong></span>
                <span>Status: <strong className="text-emerald-400">{finding.status}</strong></span>
              </div>
            </div>
          ))}
        </div>
      </ExpandableSection>
    </div>
  );
}
