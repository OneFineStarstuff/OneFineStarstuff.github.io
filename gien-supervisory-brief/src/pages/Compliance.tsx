import { useMemo, useState } from 'react';
import {
  CircleAlert,
  CircleCheck,
  CircleHelp,
  CircleMinus,
  CircleX,
  Download,
  Filter,
  Info,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import CodeBlock from '../components/CodeBlock';
import DetailDrawer from '../components/DetailDrawer';
import ExpandableSection from '../components/ExpandableSection';
import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ProgressBar from '../components/ProgressBar';
import StatusBadge, { KV } from '../components/StatusBadge';
import { useGovernance } from '../context/GovernanceContext';
import {
  generateOSCALBundleExport,
  getCell,
  MATRIX_CELLS,
  MATRIX_ROWS,
  type MatrixCell,
} from '../data/complianceData';
import { FRAMEWORKS } from '../data/gienData';
import { fakeHash, truncateHash } from '../data/helpers';
import type { ComplianceStatus } from '../types';

export default function Compliance() {
  const { phase, filingRef } = useGovernance();

  // Filters state
  const [frameworkFilter, setFrameworkFilter] = useState<string>('ALL');
  const [domainFilter, setDomainFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Toggles
  const [onlyGaps, setOnlyGaps] = useState<boolean>(false);
  const [onlyCriticalFrameworks, setOnlyCriticalFrameworks] = useState<boolean>(false);
  const [treatyGradeOnly, setTreatyGradeOnly] = useState<boolean>(false);

  // Selected cell for DetailDrawer
  const [selectedCell, setSelectedCell] = useState<MatrixCell | null>(null);

  // Filtered Frameworks (Columns)
  const filteredFrameworks = useMemo(() => {
    return FRAMEWORKS.filter((fw) => {
      if (frameworkFilter !== 'ALL' && fw.id !== frameworkFilter) return false;
      if (onlyCriticalFrameworks && fw.criticalGaps.length === 0) return false;
      if (treatyGradeOnly && !fw.treatyGrade) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchName = fw.name.toLowerCase().includes(q);
        const matchId = fw.id.toLowerCase().includes(q);
        if (!matchName && !matchId) return false;
      }
      return true;
    });
  }, [frameworkFilter, onlyCriticalFrameworks, treatyGradeOnly, searchQuery]);

  // Filtered Matrix Rows
  const filteredRows = useMemo(() => {
    return MATRIX_ROWS.filter((row) => {
      if (domainFilter !== 'ALL' && row.domainId !== domainFilter) return false;
      if (searchQuery.trim() && frameworkFilter === 'ALL') {
        const q = searchQuery.toLowerCase();
        const matchName = row.name.toLowerCase().includes(q);
        const matchId = row.id.toLowerCase().includes(q);
        const matchDesc = row.description.toLowerCase().includes(q);
        if (!matchName && !matchId && !matchDesc) {
          // Check if any framework matched search instead
          const matchesFw = FRAMEWORKS.some(
            (f) => f.name.toLowerCase().includes(q) || f.id.toLowerCase().includes(q)
          );
          if (!matchesFw) return false;
        }
      }
      return true;
    });
  }, [domainFilter, searchQuery, frameworkFilter]);

  // Frameworks sorted by gap count descending for summary grid
  const frameworksByGaps = useMemo(() => {
    return [...FRAMEWORKS].sort((a, b) => b.gapCount - a.gapCount);
  }, []);

  // Summary Metrics calculations
  const overallAvgCompliance = useMemo(() => {
    const sum = FRAMEWORKS.reduce((acc, f) => acc + f.compliancePercent, 0);
    return (sum / FRAMEWORKS.length).toFixed(1);
  }, []);

  const totalCriticalGaps = useMemo(() => {
    return FRAMEWORKS.reduce((acc, f) => acc + f.criticalGaps.length, 0);
  }, []);

  const treatyGradeScore = useMemo(() => {
    const treatyFws = FRAMEWORKS.filter((f) => f.treatyGrade);
    if (treatyFws.length === 0) return '98.5';
    const sum = treatyFws.reduce((acc, f) => acc + f.compliancePercent, 0);
    return (sum / treatyFws.length).toFixed(1);
  }, []);

  // OSCAL Export Handler
  const handleExportOSCAL = () => {
    const exportData = generateOSCALBundleExport();
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `oscal-bundle-2026-10-12.json`;
    link.click();
    URL.revokeObjectURL(url);
  };


  // Compliance matrix CSV export (watermarked)
  const handleExportCsv = () => {
    const fwIds = new Set(filteredFrameworks.map((f) => f.id));
    const rowIds = new Set(filteredRows.map((r) => r.id));
    const rowName = new Map(MATRIX_ROWS.map((r) => [r.id, r.name]));
    let records = MATRIX_CELLS.filter((c) => fwIds.has(c.frameworkId) && rowIds.has(c.rowId));
    if (statusFilter !== 'ALL') records = records.filter((c) => c.status === statusFilter);
    if (onlyGaps) records = records.filter((c) => c.status !== 'COMPLIANT' && c.status !== 'NOT_APPLICABLE');
    const esc = (v: string) => `"${String(v).replace(/"/g, '""')}"`;
    const header = [
      'control_domain',
      'control_name',
      'framework_id',
      'framework_name',
      'framework_reference',
      'oscal_control_id',
      'status',
      'risk_level',
      'assessed_at',
      'filing_ref',
      'watermark',
    ];
    const lines = [header.join(',')];
    records.forEach((c) => {
      lines.push(
        [
          esc(c.domainId),
          esc(rowName.get(c.rowId) ?? c.rowId),
          esc(c.frameworkId),
          esc(c.frameworkName),
          esc(c.frameworkArticleRef),
          esc(c.oscalControlId),
          esc(c.status),
          esc(c.riskLevel),
          esc(c.assessmentTimestamp),
          esc(filingRef),
          esc('FICTIONAL / SIMULATION — GIEN scenario data. Not a real regulatory filing.'),
        ].join(',')
      );
    });
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `gien-compliance-matrix-2026-11-03.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Helper for cell glyph & styling
  const renderCellGlyph = (status: ComplianceStatus) => {
    switch (status) {
      case 'COMPLIANT':
        return <CircleCheck className="h-4 w-4 text-emerald-400" />;
      case 'PARTIAL':
        return <CircleAlert className="h-4 w-4 text-amber-400" />;
      case 'NON_COMPLIANT':
        return <CircleX className="h-4 w-4 text-red-400" />;
      case 'NOT_APPLICABLE':
        return <CircleMinus className="h-4 w-4 text-gray-500" />;
      case 'PENDING':
        return <CircleHelp className="h-4 w-4 text-blue-400" />;
    }
  };

  const getCellBgClass = (status: ComplianceStatus, matchesFilters: boolean) => {
    if (!matchesFilters) {
      return 'bg-gray-900/20 text-gray-700 opacity-30 border-gray-800/20 pointer-events-none';
    }
    switch (status) {
      case 'COMPLIANT':
        return 'bg-emerald-950/40 text-emerald-400 border-emerald-800/30 hover:bg-emerald-900/60 hover:border-emerald-500/50';
      case 'PARTIAL':
        return 'bg-amber-950/40 text-amber-400 border-amber-800/30 hover:bg-amber-900/60 hover:border-amber-500/50';
      case 'NON_COMPLIANT':
        return 'bg-red-950/40 text-red-400 border-red-800/30 hover:bg-red-900/60 hover:border-red-500/50';
      case 'NOT_APPLICABLE':
        return 'bg-gray-900/40 text-gray-500 border-gray-800/30 hover:bg-gray-800/60 hover:text-gray-300';
      case 'PENDING':
        return 'bg-blue-950/40 text-blue-400 border-blue-800/30 hover:bg-blue-900/60 hover:border-blue-500/50';
    }
  };

  const isCellMatchingFilters = (cell?: MatrixCell) => {
    if (!cell) return false;
    if (onlyGaps && cell.status !== 'PARTIAL' && cell.status !== 'NON_COMPLIANT') return false;
    if (statusFilter !== 'ALL' && cell.status !== statusFilter) return false;
    if (riskFilter !== 'ALL' && cell.riskLevel !== riskFilter) return false;
    return true;
  };

  const resetFilters = () => {
    setFrameworkFilter('ALL');
    setDomainFilter('ALL');
    setStatusFilter('ALL');
    setRiskFilter('ALL');
    setSearchQuery('');
    setOnlyGaps(false);
    setOnlyCriticalFrameworks(false);
    setTreatyGradeOnly(false);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cross-Jurisdictional Compliance Matrix"
        subtitle="OSCAL 1.1.2 machine-readable compliance catalog mapped across 20 global and treaty-grade regulatory frameworks."
        crumbs={[{ label: 'Home', to: '/' }, { label: 'Compliance' }]}
        actions={
          <div className="flex items-center gap-2">
            <span className="rounded bg-indigo-500/10 px-2.5 py-1 text-xs font-mono text-indigo-400 border border-indigo-500/20">
              Ref: {filingRef}
            </span>
            <span className="rounded bg-emerald-500/10 px-2.5 py-1 text-xs font-mono text-emerald-400 border border-emerald-500/20">
              {phase}
            </span>
          </div>
        }
      />

      {/* Summary Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Overall Compliance"
          value={`${overallAvgCompliance}%`}
          status="COMPLIANT"
          footer={
            <div className="mt-2 text-xs text-gray-400">
              Across 20 regulatory frameworks &amp; 10 Control Domains
            </div>
          }
        />
        <MetricCard
          label="Critical Regulatory Gaps"
          value={totalCriticalGaps}
          status={totalCriticalGaps > 0 ? 'ELEVATED' : 'NOMINAL'}
          footer={
            <div className="mt-2 text-xs text-amber-400/90 font-mono flex items-center gap-1">
              <CircleAlert className="h-3.5 w-3.5 shrink-0" />
              <span>2 High-Priority gaps (EU AI Act &amp; Fed SR 26-2)</span>
            </div>
          }
        />
        <MetricCard
          label="Treaty-Grade Score"
          value={`${treatyGradeScore}%`}
          status="VERIFIED"
          footer={
            <div className="mt-2 flex items-center justify-between text-xs">
              <span className="text-cyan-400 font-mono">CFE-1.0 + SGR-028</span>
              <span className="rounded bg-cyan-500/15 px-1.5 py-0.5 text-[10px] font-bold text-cyan-300 border border-cyan-500/30">
                TREATY
              </span>
            </div>
          }
        />
        <MetricCard
          label="OSCAL Catalog Entries"
          value={MATRIX_CELLS.length}
          status="NOMINAL"
          footer={
            <div className="mt-2 text-xs text-gray-400 font-mono">
              20 Domains × 20 Frameworks = 400 Cells
            </div>
          }
        />
      </div>

      {/* OSCAL 1.1.2 Machine-Readable Validation Panel */}
      <ExpandableSection
        title="OSCAL 1.1.2 Validation & Export Panel"
        subtitle="Machine-readable SSP validation proof, Merkle-root attestation, and ML-DSA-65 signature verification"
        defaultOpen={false}
        badge={<StatusBadge variant="VERIFIED" label="OSCAL 1.1.2 VERIFIED" />}
      >
        <div className="space-y-4 pt-2">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-3">
              <span className="text-xs text-gray-400">SSP Validation</span>
              <div className="mt-1 flex items-center justify-between">
                <span className="text-sm font-semibold text-gray-200">Schema v1.1.2</span>
                <StatusBadge variant="VERIFIED" label="VERIFIED" />
              </div>
            </div>
            <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-3">
              <span className="text-xs text-gray-400">Assessment-Results</span>
              <div className="mt-1 flex items-center justify-between">
                <span className="text-sm font-semibold text-gray-200">JSON Proofs</span>
                <StatusBadge variant="COMPLIANT" label="PASS" />
              </div>
            </div>
            <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-3">
              <span className="text-xs text-gray-400">ML-DSA-65 Signature</span>
              <div className="mt-1 flex items-center justify-between">
                <span className="text-sm font-semibold text-gray-200">FIPS 204 Proof</span>
                <StatusBadge variant="VERIFIED" label="VERIFIED" />
              </div>
            </div>
            <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-3">
              <span className="text-xs text-gray-400">Bundle Merkle Root</span>
              <div className="mt-1 font-mono text-xs text-indigo-300 truncate" title={fakeHash('oscal-bundle-2026-10-12')}>
                {truncateHash(fakeHash('oscal-bundle-2026-10-12'), 8, 6)}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-gray-700/80 bg-gray-900/80 p-3">
            <div className="flex items-center gap-2 text-xs text-gray-300">
              <Sparkles className="h-4 w-4 text-cyan-400" />
              <span>
                Export complete machine-readable System Security Plan (SSP) and Assessment Results bundle in OSCAL 1.1.2 format.
              </span>
            </div>
            <button
              type="button"
              onClick={handleExportCsv}
              className="inline-flex items-center gap-2 rounded-md border border-gray-600 bg-gray-800 px-3.5 py-1.5 text-xs font-medium text-gray-200 hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-colors"
            >
              <Download className="h-3.5 w-3.5" />
              Export Matrix (CSV)
            </button>
            <button
              type="button"
              onClick={handleExportOSCAL}
              className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3.5 py-1.5 text-xs font-medium text-white shadow hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-colors"
            >
              <Download className="h-3.5 w-3.5" />
              Export Machine-Readable Controls (JSON)
            </button>
          </div>
        </div>
      </ExpandableSection>

      {/* Framework Compliance & Gap Breakdown */}
      <ExpandableSection
        title="Framework Compliance & Gap Overview"
        subtitle="Compliance percentage and open gaps across all 20 regulatory frameworks (sorted by open gaps)"
        defaultOpen={false}
      >
        <div className="mt-2 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4 max-h-96 overflow-y-auto pr-1">
          {frameworksByGaps.map((fw) => (
            <div key={fw.id} className="rounded-lg border border-gray-700/70 bg-gray-900/50 p-3 hover:border-gray-600 transition-colors">
              <div className="flex items-start justify-between gap-1">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-xs font-semibold text-gray-200">{fw.name}</span>
                    {fw.fictional && (
                      <span className="rounded bg-violet-500/20 px-1 py-0.2 text-[9px] font-bold text-violet-300 border border-violet-500/30">
                        FICTIONAL
                      </span>
                    )}
                    {fw.treatyGrade && (
                      <span className="rounded bg-cyan-500/20 px-1 py-0.2 text-[9px] font-bold text-cyan-300 border border-cyan-500/30">
                        TREATY
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-gray-400 font-mono">ID: {fw.id}</div>
                </div>
                <span className={`font-mono text-xs font-bold ${fw.gapCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {fw.compliancePercent}%
                </span>
              </div>

              <div className="mt-2">
                <ProgressBar
                  value={fw.compliancePercent}
                  color={fw.compliancePercent >= 95 ? 'bg-emerald-500' : fw.compliancePercent >= 90 ? 'bg-indigo-500' : 'bg-amber-500'}
                />
              </div>

              <div className="mt-2 flex items-center justify-between text-[11px] text-gray-400">
                <span>Gaps: {fw.gapCount}</span>
                {fw.criticalGaps.length > 0 ? (
                  <span className="text-red-400 font-medium">Critical Gaps: {fw.criticalGaps.length}</span>
                ) : (
                  <span className="text-emerald-400">No Critical Gaps</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </ExpandableSection>

      {/* Filter Toolbar */}
      <div className="rounded-lg border border-gray-700 bg-gray-800/80 p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-gray-200">
            <Filter className="h-4 w-4 text-indigo-400" />
            <span>Matrix Filters</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={resetFilters}
              className="inline-flex items-center gap-1.5 rounded bg-gray-700 px-2.5 py-1 text-xs text-gray-300 hover:bg-gray-600 transition-colors"
            >
              <RefreshCw className="h-3 w-3" />
              Reset Filters
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-gray-500" />
            <input
              type="text"
              placeholder="Search frameworks / domains..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-md border border-gray-700 bg-gray-900 pl-8 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
            />
          </div>

          {/* Framework Selector */}
          <div>
            <select
              value={frameworkFilter}
              onChange={(e) => setFrameworkFilter(e.target.value)}
              className="w-full rounded-md border border-gray-700 bg-gray-900 px-2.5 py-1.5 text-xs text-gray-200 focus:border-indigo-500 focus:outline-none"
            >
              <option value="ALL">All Frameworks (20)</option>
              {FRAMEWORKS.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name} ({f.id})
                </option>
              ))}
            </select>
          </div>

          {/* Domain Selector */}
          <div>
            <select
              value={domainFilter}
              onChange={(e) => setDomainFilter(e.target.value)}
              className="w-full rounded-md border border-gray-700 bg-gray-900 px-2.5 py-1.5 text-xs text-gray-200 focus:border-indigo-500 focus:outline-none"
            >
              <option value="ALL">All Control Domains (CD-01..10)</option>
              {Array.from(new Set(MATRIX_ROWS.map((r) => r.domainId))).map((dId) => (
                <option key={dId} value={dId}>
                  {dId}
                </option>
              ))}
            </select>
          </div>

          {/* Status Selector */}
          <div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full rounded-md border border-gray-700 bg-gray-900 px-2.5 py-1.5 text-xs text-gray-200 focus:border-indigo-500 focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="COMPLIANT">Compliant (✓)</option>
              <option value="PARTIAL">Partial (~)</option>
              <option value="NON_COMPLIANT">Non-Compliant (✗)</option>
              <option value="PENDING">Pending (?)</option>
              <option value="NOT_APPLICABLE">Not Applicable (—)</option>
            </select>
          </div>

          {/* Risk Selector */}
          <div>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="w-full rounded-md border border-gray-700 bg-gray-900 px-2.5 py-1.5 text-xs text-gray-200 focus:border-indigo-500 focus:outline-none"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>
        </div>

        {/* Toggles bar */}
        <div className="flex flex-wrap items-center gap-4 pt-1 text-xs text-gray-300">
          <label className="inline-flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={onlyGaps}
              onChange={(e) => setOnlyGaps(e.target.checked)}
              className="rounded border-gray-700 bg-gray-900 text-indigo-500 focus:ring-indigo-500"
            />
            <span className={onlyGaps ? 'text-amber-400 font-medium' : ''}>Only gaps (Partial / Non-Compliant)</span>
          </label>

          <label className="inline-flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={onlyCriticalFrameworks}
              onChange={(e) => setOnlyCriticalFrameworks(e.target.checked)}
              className="rounded border-gray-700 bg-gray-900 text-indigo-500 focus:ring-indigo-500"
            />
            <span className={onlyCriticalFrameworks ? 'text-indigo-400 font-medium' : ''}>Only critical frameworks</span>
          </label>

          <label className="inline-flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={treatyGradeOnly}
              onChange={(e) => setTreatyGradeOnly(e.target.checked)}
              className="rounded border-gray-700 bg-gray-900 text-cyan-400 focus:ring-cyan-500"
            />
            <span className={treatyGradeOnly ? 'text-cyan-400 font-medium' : ''}>Treaty-grade only</span>
          </label>
        </div>
      </div>

      {/* Compliance Matrix Table */}
      <div className="relative rounded-lg border border-gray-700 bg-gray-950 overflow-hidden shadow-xl">
        <div className="overflow-x-auto overflow-y-auto max-h-[600px] scrollbar-thin">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="sticky top-0 z-20 bg-gray-900 border-b border-gray-700 shadow">
                {/* Sticky Top-Left Header Cell */}
                <th className="sticky left-0 z-30 min-w-[240px] max-w-[280px] bg-gray-900 p-3 text-left font-mono font-bold text-gray-300 border-r border-gray-700 shadow-md">
                  Control Domain \ Framework
                </th>

                {/* Framework Columns */}
                {filteredFrameworks.map((fw) => (
                  <th
                    key={fw.id}
                    className="min-w-[130px] p-2.5 text-center font-medium text-gray-300 border-r border-gray-800 bg-gray-900/95"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center justify-center gap-1 flex-wrap">
                        <span className="font-semibold text-gray-200">{fw.name}</span>
                        {fw.fictional && (
                          <span className="rounded bg-violet-500/20 px-1 py-0.2 text-[9px] font-bold text-violet-300 border border-violet-500/30">
                            FICTIONAL
                          </span>
                        )}
                        {fw.treatyGrade && (
                          <span className="rounded bg-cyan-500/20 px-1 py-0.2 text-[9px] font-bold text-cyan-300 border border-cyan-500/30">
                            TREATY
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-[10px] text-gray-400">
                        {fw.compliancePercent}% compliant
                      </div>
                    </div>
                  </th>
                ))}
              </tr>
            </thead>

            <tbody>
              {filteredRows.map((row) => (
                <tr key={row.id} className="border-b border-gray-800/60 hover:bg-gray-900/30">
                  {/* Sticky First Column */}
                  <td
                    className={`sticky left-0 z-10 bg-gray-950 p-2.5 border-r border-gray-700 font-medium ${
                      row.isSubControl ? 'pl-7 text-[11px] text-gray-400' : 'text-gray-200 font-semibold'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-indigo-400 text-[11px] shrink-0">{row.id}</span>
                      <span className="truncate" title={row.name}>
                        {row.name}
                      </span>
                    </div>
                  </td>

                  {/* Matrix Cells */}
                  {filteredFrameworks.map((fw) => {
                    const cell = getCell(row.id, fw.id);
                    const status: ComplianceStatus = cell ? cell.status : 'NOT_APPLICABLE';
                    const matches = isCellMatchingFilters(cell);
                    const bgClass = getCellBgClass(status, matches);

                    return (
                      <td
                        key={`${row.id}-${fw.id}`}
                        onClick={() => cell && matches && setSelectedCell(cell)}
                        className={`p-2 text-center border-r border-gray-800/40 cursor-pointer transition-all ${bgClass}`}
                        title={
                          cell
                            ? `${row.id} × ${fw.name}: ${cell.status} (${cell.riskLevel} Risk)\nRef: ${cell.frameworkArticleRef}`
                            : 'Not Applicable'
                        }
                      >
                        <div className="flex flex-col items-center justify-center gap-0.5">
                          {renderCellGlyph(status)}
                          <span className="text-[10px] font-mono uppercase tracking-wider">{status.replace('_', ' ')}</span>
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* DetailDrawer for Cell Click */}
      <DetailDrawer
        open={!!selectedCell}
        onClose={() => setSelectedCell(null)}
        title={selectedCell ? `${selectedCell.frameworkName} — ${selectedCell.rowId}` : ''}
        subtitle={selectedCell ? `OSCAL Control ID: ${selectedCell.oscalControlId}` : ''}
      >
        {selectedCell && (
          <div className="space-y-5">
            {/* Header badges */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 pb-3">
              <div className="flex items-center gap-2">
                <StatusBadge variant={selectedCell.status} label={selectedCell.status} />
                <span
                  className={`rounded px-2 py-0.5 text-xs font-mono font-bold ${
                    selectedCell.riskLevel === 'CRITICAL' || selectedCell.riskLevel === 'HIGH'
                      ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                      : selectedCell.riskLevel === 'MEDIUM'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  }`}
                >
                  {selectedCell.riskLevel} RISK
                </span>
              </div>
              <span className="text-xs text-gray-400 font-mono">
                Assessed: {selectedCell.assessmentTimestamp.replace('T', ' ').replace('Z', ' UTC')}
              </span>
            </div>

            {/* Key Value Pairs */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <KV label="Framework Reference Article" value={selectedCell.frameworkArticleRef} />
              <KV label="OSCAL 1.1.2 Control Schema" value={selectedCell.oscalControlId} mono />
            </div>

            {/* Remediation Plan callout if gap */}
            {(selectedCell.status === 'PARTIAL' || selectedCell.status === 'NON_COMPLIANT' || selectedCell.remediationPlan) && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-950/30 p-3.5 space-y-1">
                <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
                  <CircleAlert className="h-4 w-4 shrink-0 text-amber-400" />
                  <span>Remediation Action Required</span>
                </div>
                <p className="text-xs text-amber-200/90 leading-relaxed">
                  {selectedCell.remediationPlan ??
                    'Formal gap remediation workflow initialized. Re-attestation and evidence submission required before cycle closure.'}
                </p>
              </div>
            )}

            {/* Evidence Artefacts */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-400 flex items-center gap-1.5">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                Evidence Artefact Hashes (2026 Audit Trail)
              </h4>
              <div className="space-y-2">
                {selectedCell.evidenceArtefacts.map((art) => (
                  <div key={art.id} className="rounded-md border border-gray-800 bg-gray-900/80 p-2.5 text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-gray-200">{art.name}</span>
                      <span className="text-[10px] text-gray-400">{art.type}</span>
                    </div>
                    <div className="flex items-center justify-between font-mono text-[11px] text-gray-400">
                      <span className="text-indigo-300">{truncateHash(art.hash, 12, 8)}</span>
                      <span>{art.timestamp.replace('T', ' ').replace('Z', '')}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Representative OPA-Rego Policy */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-400 flex items-center gap-1.5">
                <Shield className="h-4 w-4 text-indigo-400" />
                Executed OPA-Rego Policy Snippet
              </h4>
              <CodeBlock code={selectedCell.opaRegoSnippet} language="rego" />
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
