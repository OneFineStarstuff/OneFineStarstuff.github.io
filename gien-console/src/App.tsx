import { useMemo, useState, useEffect, type ReactNode } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Bell,
  ChevronRight,
  Clock,
  Database,
  Download,
  FileSearch,
  FileText,
  Gauge,
  LayoutDashboard,
  Moon,
  ShieldCheck,
  Sun,
  Workflow
} from "lucide-react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { Navigate, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { FairnessHeatmap } from "./components/FairnessHeatmap";
import { MetricCard } from "./components/MetricCard";
import {
  demoAlerts,
  demoComplianceRecords,
  demoFairnessCells,
  demoRagSources,
  demoRiskMetrics,
  demoRiskTrend
} from "./data/demoTelemetry";
import { alertsToCsv, alertsToJson, formatMetricValue } from "./lib/telemetry";
import { useToast } from "./providers/ToastProvider";
import type { AlertRecord } from "./types/governance";

const navigation = [
  { to: "/dashboard", label: "Supervisory overview", icon: LayoutDashboard },
  { to: "/risk-indices", label: "Risk telemetry", icon: Gauge },
  { to: "/compliance", label: "Compliance matrix", icon: ShieldCheck },
  { to: "/rag-audit", label: "RAG data audit", icon: Database },
  { to: "/alerts", label: "Alert history", icon: Bell },
  { to: "/submission-packages", label: "Submission packages", icon: FileText }
];

const titleByPath: Record<string, { title: string; subtitle: string }> = {
  "/dashboard": { title: "Supervisory overview", subtitle: "Evidence status, risk telemetry and control follow-up in one view." },
  "/risk-indices": { title: "Risk telemetry", subtitle: "Project-defined GIEN indicators with explicit source status and thresholds." },
  "/compliance": { title: "Compliance matrix", subtitle: "Map obligations to owners and evidence without implying conformity." },
  "/rag-audit": { title: "RAG data audit", subtitle: "Inspect source lineage, citation coverage and authorization state." },
  "/alerts": { title: "Alert history", subtitle: "Review example supervisory events and export the current demonstration dataset." },
  "/submission-packages": { title: "Submission packages", subtitle: "Prepare traceable evidence bundles for accountable human review." }
};

type Theme = "dark" | "light";

/** Convert text content into a browser download with an explicit MIME type. */
function downloadText(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

/** Format an ISO timestamp in UTC for presentation in the console. */
function formatUtc(value: string) {
  return `${new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC"
  }).format(new Date(value))} UTC`;
}

/** Render the evidence-source state using a stable status-specific class. */
function SourceBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase().replaceAll("_", "-");
  return <span className={`source-badge source-${normalized}`}>{status.replaceAll("_", " ")}</span>;
}

/** Render a section heading and its optional action control. */
function SectionTitle({ eyebrow, title, action }: { eyebrow: string; title: string; action?: ReactNode }) {
  return (
    <div className="section-title-row">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h2>{title}</h2>
      </div>
      {action}
    </div>
  );
}

/** Wrap related console content in the standard panel surface. */
function Panel({ className = "", children }: { className?: string; children: ReactNode }) {
  return <section className={`panel ${className}`}>{children}</section>;
}

/** Render the persistent navigation and prototype control-posture panel. */
function Sidebar({ pathname }: { pathname: string }) {
  return (
<aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-symbol"><ShieldCheck size={23} strokeWidth={1.8} /></div>
          <div>
            <div className="brand-name">GIEN <span>CONTROL</span></div>
            <div className="brand-subtitle">OMNI-SENTINEL · PHASE VI-δ</div>
          </div>
        </div>

        <div className="sidebar-label">SUPERVISORY WORKSPACE</div>
        <nav className="primary-nav" aria-label="Primary navigation">
          {navigation.map(item => {
            const Icon = item.icon;
            return (
              <NavLink className={({ isActive }) => `nav-link ${isActive ? "nav-link-active" : ""}`} to={item.to} key={item.to}>
                <Icon size={18} strokeWidth={1.8} />
                <span>{item.label}</span>
                {pathname === item.to && <ChevronRight size={15} className="nav-chevron" />}
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-spacer" />
        <div className="sidebar-runtime-card">
          <div className="runtime-card-top"><span className="source-dot source-dot-pending" /> INTERVENTION CONTROL</div>
          <strong>NOT CONNECTED</strong>
          <p>No runtime stop actuator is configured in this prototype. No stop command can be executed here.</p>
        </div>
        <div className="sidebar-footer">
          <span>Console build</span>
          <code>0.1.0-draft</code>
        </div>
  );
}

/** Render the page breadcrumb, reporting boundary and theme control. */
function Topbar({ currentTitle, theme, onToggleTheme }: {
  currentTitle: string;
  theme: Theme;
  onToggleTheme: () => void;
}) {
  return (
<header className="topbar">
          <div className="breadcrumb">
            <span>Governance</span><ChevronRight size={14} /><strong>{currentTitle}</strong>
          </div>
          <div className="topbar-actions">
            <div className="window-pill"><Clock size={14} /><span>Reporting boundary: 09:00 UTC</span></div>
            <button
              className="icon-button theme-toggle"
              onClick={onToggleTheme}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              title="Toggle theme"
            >
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
            </button>
            <div className="role-pill"><span className="role-dot" /> REVIEW MODE</div>
          </div>
  );
}

/** Render the current page heading, evidence banner, route body and footer. */
function WorkspaceContent({ current }: { current: { title: string; subtitle: string } }) {
  return (
<div className="workspace">
            <div className="page-heading">
              <div>
                <div className="eyebrow">GIEN / SUPERVISORY CONTROL PLANE</div>
                <h1>{current.title}</h1>
                <p>{current.subtitle}</p>
              </div>
              <div className="heading-meta">
                <span className="phase-badge">PHASE VI-δ</span>
                <span className="report-time">Sample window · 16 Oct 2026</span>
              </div>
            </div>

            <div className="demonstration-banner" role="status">
              <div className="demo-banner-icon"><AlertTriangle size={18} /></div>
              <div>
                <strong>DEMONSTRATION DATA · NOT LIVE TELEMETRY</strong>
                <p>All values and records in this starter are synthetic. No regulatory conclusion, hardware attestation, proof verification or production safety state is asserted.</p>
              </div>
            </div>

            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/risk-indices" element={<RiskTelemetryPage />} />
              <Route path="/compliance" element={<CompliancePage />} />
              <Route path="/rag-audit" element={<RagAuditPage />} />
              <Route path="/alerts" element={<AlertsPage />} />
              <Route path="/submission-packages" element={<SubmissionPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Routes>

            <footer className="app-footer">
              <span>Sentinel AI Governance Stack v2.4 · Omni-Sentinel Mesh v4.0</span>
              <span><span className="footer-dot" /> Evidence-qualified prototype</span>
            </footer>
          </div>
  );
}

/** Render the route shell, navigation, theme controls, and evidence banner. */
function PageLayout() {
  const { pathname } = useLocation();
  const current = titleByPath[pathname] ?? titleByPath["/dashboard"];
  const [theme, setTheme] = useState<Theme>("dark");
  const { notify } = useToast();
  const toggleTheme = () => {
    const nextTheme: Theme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    notify(`Theme switched to ${nextTheme} mode.`, "success");
  };


  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  return (
    <div className={`app-shell theme-${theme}`}>
      <Sidebar pathname={pathname} />

      <div className="main-column">
        <Topbar currentTitle={current.title} theme={theme} onToggleTheme={toggleTheme} />

        <main id="main-content" tabIndex={-1}>
          <WorkspaceContent current={current} />
        </main>
      </div>
    </div>
  );
}

/** Present the top-level demonstration telemetry and review actions. */
function DashboardPage() {
  const metrics = demoRiskMetrics.slice(0, 4);
  const { notify } = useToast();
  return (
    <div className="page-content">
      <div className="metric-grid">
        {metrics.map((metric, index) => <MetricCard metric={metric} index={index} key={metric.id} />)}
      </div>

      <div className="dashboard-grid dashboard-grid-wide">
        <Panel>
          <SectionTitle eyebrow="SYSTEMIC-RISK TELEMETRY" title="Illustrative trend · 24 hours" action={<SourceBadge status="SYNTHETIC" />} />
          <div className="chart-legend-copy">Project-defined scores · normalized index · synthetic time series</div>
          <RiskTrendPlot />
          <div className="chart-footnote"><InfoBullet />Trend lines demonstrate display behavior only. No connected telemetry source was found.</div>
        </Panel>

        <Panel className="control-posture-panel">
          <SectionTitle eyebrow="EVIDENCE POSTURE" title="Control-plane status" />
          <div className="posture-list">
            <PostureRow icon={<Database size={17} />} label="Telemetry connector" status="EVIDENCE PENDING" detail="Live query source not configured" />
            <PostureRow icon={<ShieldCheck size={17} />} label="TEE / vTPM attestation" status="EVIDENCE PENDING" detail="No verified attestation record" />
            <PostureRow icon={<Workflow size={17} />} label="OPA policy decision" status="EVIDENCE PENDING" detail="No trusted policy endpoint connected" />
            <PostureRow icon={<FileSearch size={17} />} label="RAG provenance" status="SYNTHETIC" detail="Example documents only" />
          </div>
          <button className="text-action" onClick={() => notify("Live sources remain unconfigured. No external source was queried.", "info")}>
            Review source readiness <ArrowRight size={15} />
          </button>
        </Panel>
      </div>

      <div className="dashboard-grid dashboard-grid-wide">
        <Panel>
          <SectionTitle eyebrow="FAIRNESS & PARITY" title="Group-metric heatmap" action={<SourceBadge status="SYNTHETIC" />} />
          <FairnessHeatmap data={demoFairnessCells} />
          <div className="chart-footnote"><InfoBullet />The groups and values are invented examples. No protected-group data or actual model results are shown.</div>
        </Panel>
        <Panel>
          <SectionTitle eyebrow="PRIORITY FOLLOW-UP" title="Open evidence tasks" />
          <div className="task-list">
            <TaskRow number="01" title="Connect authenticated telemetry" detail="Assign source owner, query contract and freshness SLO." state="BLOCKING" />
            <TaskRow number="02" title="Verify source provenance" detail="Retain versions, hashes, access decisions and timestamps." state="OPEN" />
            <TaskRow number="03" title="Review regulatory applicability" detail="Confirm system scope with legal and compliance owners." state="OPEN" />
          </div>
        </Panel>
      </div>
    </div>
  );
}

/** Isolate the nested SVG chart configuration from the dashboard layout. */
function RiskTrendPlot() {
  return (
<div className="line-chart-wrap">
            <ResponsiveContainer width="100%" height={272}>
              <LineChart data={demoRiskTrend} margin={{ top: 10, right: 12, left: -18, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--grid-line)" />
                <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: "var(--muted)", fontSize: 11 }} />
                <YAxis domain={[0, 0.5]} tickLine={false} axisLine={false} tick={{ fill: "var(--muted)", fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "var(--panel-raised)", border: "1px solid var(--border)", borderRadius: 12, color: "var(--text)" }} />
                <Legend wrapperStyle={{ fontSize: 11, color: "var(--muted)" }} />
                <Line type="monotone" dataKey="system" name="S_sys (demo)" stroke="#58d6c3" strokeWidth={2.5} dot={false} />
                <Line type="monotone" dataKey="cascade" name="C-SRI (demo)" stroke="#8f9dff" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="governance" name="CGR-I (demo)" stroke="#e5b665" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
  );
}

function RiskMetricsTable() {
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr><th>Metric</th><th>Example value</th><th>Project threshold</th><th>Assessment</th><th>Source / method</th><th>Limitation</th></tr></thead>
        <tbody>{demoRiskMetrics.map(metric => <RiskMetricRow key={metric.id} metric={metric} />)}</tbody>
      </table>
    </div>
  );
}

function ComplianceTable() {
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr><th>Framework</th><th>Requirement focus</th><th>Accountable owner</th><th>Assessment</th><th>Evidence</th><th>Next review</th></tr></thead>
        <tbody>{demoComplianceRecords.map(record => <ComplianceRow key={record.id} record={record} />)}</tbody>
      </table>
    </div>
  );
}

function RagSourcesTable() {
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr><th>Source ID</th><th>Document / version</th><th>Last accessed</th><th>Source state</th><th>Citation coverage</th><th>Access decision</th></tr></thead>
        <tbody>{demoRagSources.map(source => <RagSourceRow key={source.id} source={source} />)}</tbody>
      </table>
    </div>
  );
}

function AlertsTable({ alerts, onAcknowledge }: { alerts: AlertRecord[]; onAcknowledge: (id: string) => void }) {
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr><th>Alert ID</th><th>Alert</th><th>Severity</th><th>Occurred (UTC)</th><th>Owner</th><th>State</th><th>Action</th></tr></thead>
        <tbody>{alerts.map(alert => <AlertTableRow key={alert.id} alert={alert} onAcknowledge={onAcknowledge} />)}</tbody>
      </table>
    </div>
  );
}

function RiskMetricRow({ metric }: { metric: (typeof demoRiskMetrics)[number] }) {
  return (
    <tr>
      <td><strong>{metric.id}</strong><span className="table-subtitle">{metric.name}</span></td>
      <td className="numeric">{formatMetricValue(metric)} <span className="unit-text">{metric.unit}</span></td>
      <td className="numeric">{metric.thresholdDirection === "MAXIMUM" ? "≤" : "≥"} {metric.threshold}</td>
      <td><span className="assessment-chip assessment-pending">NOT ASSESSED</span></td>
      <td><code>{metric.sourceRef}</code><span className="table-subtitle">{metric.methodVersion}</span></td>
      <td className="limitation-cell">{metric.limitation}</td>
    </tr>
  );
}

function ComplianceRow({ record }: { record: (typeof demoComplianceRecords)[number] }) {
  return (
    <tr>
      <td><strong>{record.framework}</strong><span className="table-subtitle">{record.id}</span></td>
      <td>{record.obligation}</td>
      <td>{record.owner}</td>
      <td><span className={`assessment-chip assessment-${record.assessment === "IN REVIEW" ? "review" : "pending"}`}>{record.assessment}</span></td>
      <td>{record.evidenceCount} linked record{record.evidenceCount === 1 ? "" : "s"}</td>
      <td>{record.nextReview}</td>
    </tr>
  );
}

function RagSourceRow({ source }: { source: (typeof demoRagSources)[number] }) {
  return (
    <tr>
      <td><code>{source.id}</code></td>
      <td><strong>{source.document}</strong><span className="table-subtitle">{source.version}</span></td>
      <td>{formatUtc(source.accessedAt)}</td>
      <td><SourceBadge status={source.sourceStatus} /></td>
      <td>{source.citationCoverage === null ? "Not available" : `${Math.round(source.citationCoverage * 100)}% (demo)`}</td>
      <td>{source.accessDecision}</td>
    </tr>
  );
}

function AlertTableRow({ alert, onAcknowledge }: {
  alert: AlertRecord;
  onAcknowledge: (id: string) => void;
}) {
  return (
    <tr>
      <td><code>{alert.id}</code></td>
      <td><strong>{alert.title}</strong><span className="table-subtitle">Evidence: {alert.evidenceRef}</span></td>
      <td><span className={`severity severity-${alert.severity.toLowerCase()}`}>{alert.severity}</span></td>
      <td>{formatUtc(alert.occurredAt)}</td>
      <td>{alert.owner}</td>
      <td>{alert.state}</td>
      <td>{alert.state === "OPEN" ? <button className="table-action" onClick={() => onAcknowledge(alert.id)}>Acknowledge</button> : <span className="muted">No action</span>}</td>
    </tr>
  );
}

/** Render project-defined risk indices with source and assessment status. */
function RiskTelemetryPage() {
  return (
    <div className="page-content">
      <Panel>
        <SectionTitle eyebrow="METRIC REGISTER" title="GIEN project-defined indices" action={<SourceBadge status="SYNTHETIC" />} />
        <p className="panel-description">Thresholds shown below are project parameters only. Synthetic values are not assessed as live risk states.</p>

        <RiskMetricsTable />
      </Panel>
      <Panel>
        <SectionTitle eyebrow="ASSESSMENT RULE" title="Why synthetic values do not produce a risk verdict" />
        <div className="info-grid">
          <InfoTile title="Source status" body="Only LIVE or independently verified EXTERNAL_ATTESTED records can enter the threshold assessment in this starter." />
          <InfoTile title="Missing or stale data" body="A missing source is EVIDENCE_PENDING, not zero, low risk, healthy, or compliant." />
          <InfoTile title="Project thresholds" body="Thresholds require an approved definition, accountable owner, calibration and an explicit scope before operational use." />
        </div>
      </Panel>
    </div>
  );
}

/** Present framework-to-control mappings without asserting conformity. */
function CompliancePage() {
  return (
    <div className="page-content">
      <div className="callout callout-amber"><AlertTriangle size={18} /><div><strong>Crosswalk ≠ compliance determination</strong><p>Applicability and conformity are not inferred from a framework name or a populated control row.</p></div></div>
      <Panel>
        <SectionTitle eyebrow="OBLIGATION / CONTROL REGISTER" title="Cross-jurisdictional compliance matrix" />

        <ComplianceTable />
      </Panel>
      <Panel>
        <SectionTitle eyebrow="PROJECT-DEFINED" title="GIEN constitutional controls" />
        <div className="info-grid">
          <InfoTile title="CFE-1.0" body="Project-defined invariant catalogue. Specification, model-checker output and reviewer evidence are pending." />
          <InfoTile title="Protocol SGR-028" body="Fictional supervisory protocol. It is not represented as public law or regulator-issued guidance." />
          <InfoTile title="HumanMeaningConstitution" body="Ethical constraints require ownership, exception handling, review records and clear separation from statutory obligations." />
        </div>
      </Panel>
    </div>
  );
}

/** Render the retrieval provenance register and its evidence limitations. */
function RagAuditPage() {
  return (
    <div className="page-content">
      <div className="metric-grid metric-grid-three">
        <MetricCard metric={demoRiskMetrics[0]} index={0} />
        <div className="stat-card"><span className="stat-label">RAG sources in example set</span><strong>{demoRagSources.length}</strong><span className="stat-hint">Synthetic fixture records</span></div>
        <div className="stat-card"><span className="stat-label">Verified live sources</span><strong>0</strong><span className="stat-hint">No connector configured</span></div>
      </div>
      <Panel>
        <SectionTitle eyebrow="SOURCE → RETRIEVAL → OUTPUT" title="Provenance register" action={<SourceBadge status="SYNTHETIC" />} />

        <RagSourcesTable />
      </Panel>
      <Panel>
        <SectionTitle eyebrow="MINIMUM LINEAGE" title="Evidence required for each answer" />
        <div className="lineage-steps">
          {["Authorized source", "Document/chunk version", "Retrieval and prompt IDs", "Model/output reference", "Citations and policy result", "Human review / downstream action"].map((label, i) => (
            <div className="lineage-step" key={label}><span>{String(i + 1).padStart(2, "0")}</span><strong>{label}</strong></div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/** Display the synthetic alert history and export affordances. */
function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertRecord[]>(demoAlerts);
  const [filter, setFilter] = useState("ALL");
  const { notify } = useToast();
  const filteredAlerts = useMemo(() => filter === "ALL" ? alerts : alerts.filter(alert => alert.state === filter), [alerts, filter]);

  /** Export the currently filtered synthetic alert records as a local file. */
  const exportAlerts = (format: "csv" | "json") => {
    const content = format === "csv" ? alertsToCsv(filteredAlerts) : alertsToJson(filteredAlerts);
    downloadText(`gien-alerts-demonstration.${format}`, content, format === "csv" ? "text/csv;charset=utf-8" : "application/json");
    notify(`Exported ${filteredAlerts.length} demonstration alerts. Server-side export auditing is not configured.`, "success");
  };

  /** Update only the local demonstration state for an open alert. */
  const acknowledge = (id: string) => {
    setAlerts(current => current.map(alert => alert.id === id && alert.state === "OPEN" ? { ...alert, state: "ACKNOWLEDGED" } : alert));
    notify("Local demonstration state updated. No server-side alert record was changed.", "info");
  };

  return (
    <div className="page-content">
      <Panel>
        <SectionTitle
          eyebrow="EVENT HISTORY"
          title="Supervisory alerts"
          action={<div className="button-row"><button className="button button-secondary" onClick={() => exportAlerts("csv")}><Download size={15} /> Export CSV</button><button className="button button-secondary" onClick={() => exportAlerts("json")}><Download size={15} /> Export JSON</button></div>}
        />
        <div className="table-toolbar">
          <label htmlFor="alert-filter">Filter by state</label>
          <select id="alert-filter" value={filter} onChange={event => setFilter(event.target.value)}>
            <option value="ALL">All states</option><option value="OPEN">Open</option><option value="ACKNOWLEDGED">Acknowledged</option><option value="RESOLVED">Resolved</option>
          </select>
          <span className="row-count">{filteredAlerts.length} records · demo fixture</span>
        </div>

        <AlertsTable alerts={filteredAlerts} onAcknowledge={acknowledge} />

        <div className="panel-footnote">Exports contain only these synthetic example records. A production service must enforce row-level authorization, create export audit events, preserve provenance and apply retention policy.</div>
      </Panel>
    </div>
  );
}

/** Present a draft evidence-package manifest for human review. */
function SubmissionPage() {
  const { notify } = useToast();
  const pendingControls = demoComplianceRecords.filter(record => record.assessment !== "IN REVIEW").length;
  const manifest = {
    schemaVersion: "0.1-demo",
    packageId: "GIEN-SUBMISSION-DEMO-001",
    generatedAt: new Date().toISOString(),
    classification: "DEMONSTRATION DATA",
    evaluationWindow: { start: "2026-10-15T09:00:00Z", end: "2026-10-16T09:00:00Z" },
    evidenceState: "EVIDENCE_PENDING",
    metrics: demoRiskMetrics.map(metric => ({ id: metric.id, sourceStatus: metric.sourceStatus, sourceRef: metric.sourceRef })),
    note: "Example manifest only. No regulatory submission was made and no assurance claim is confirmed."
  };
  return (
    <div className="page-content">
      <div className="callout callout-amber"><FileText size={19} /><div><strong>Draft package only</strong><p>Exports do not transmit information to regulators and do not certify regulatory compliance.</p></div></div>
      <div className="metric-grid metric-grid-three">
        <div className="stat-card"><span className="stat-label">Assessment rows</span><strong>{demoComplianceRecords.length}</strong><span className="stat-hint">Synthetic examples</span></div>
        <div className="stat-card"><span className="stat-label">Rows awaiting evidence</span><strong>{pendingControls}</strong><span className="stat-hint">Not assessed or evidence required</span></div>
        <div className="stat-card"><span className="stat-label">Verified assurance claims</span><strong>0</strong><span className="stat-hint">No independent assurance linked</span></div>
      </div>
      <Panel>
        <SectionTitle eyebrow="AAP-1 CLAIM REGISTER" title="Submission package readiness" />
        <div className="task-list">
          <TaskRow number="01" title="Freeze scope and applicable framework versions" detail="Require system owner and legal/compliance sign-off." state="PENDING" />
          <TaskRow number="02" title="Bind each finding to an evidence reference" detail="Record source, version, assessment method, limitation and reviewer." state="PENDING" />
          <TaskRow number="03" title="Validate manifest and dossier schema" detail="Run schema validation and integrity checks before external use." state="PENDING" />
        </div>
        <div className="submission-actions">
          <button className="button button-primary" onClick={() => { downloadText("gien-submission-manifest-demo.json", JSON.stringify(manifest, null, 2), "application/json"); notify("Downloaded a demonstration manifest. It is not a regulator submission.", "success"); }}><Download size={16} /> Download demo manifest</button>
        </div>
      </Panel>
    </div>
  );
}

/** Render a non-authoritative message for unknown console routes. */
function NotFoundPage() {
  return <Panel><h2>Route not found</h2><p className="panel-description">Select a governance view from the navigation.</p><NavLink className="button button-primary" to="/dashboard">Return to overview</NavLink></Panel>;
}

/** Show one governance-control posture and its supporting detail. */
function PostureRow({ icon, label, status, detail }: { icon: ReactNode; label: string; status: string; detail: string }) {
  return <div className="posture-row"><div className="posture-icon">{icon}</div><div className="posture-main"><strong>{label}</strong><span>{detail}</span></div><span className="posture-status">{status}</span></div>;
}

/** Display a follow-up task and its current workflow state. */
function TaskRow({ number, title, detail, state }: { number: string; title: string; detail: string; state: string }) {
  return <div className="task-row"><span className="task-number">{number}</span><div className="task-copy"><strong>{title}</strong><span>{detail}</span></div><span className={`task-state ${state === "BLOCKING" ? "task-state-blocking" : ""}`}>{state}</span></div>;
}

/** Render a compact titled explanation within the console. */
function InfoTile({ title, body }: { title: string; body: string }) {
  return <div className="info-tile"><strong>{title}</strong><p>{body}</p></div>;
}

/** Render the small visual marker used in explanatory lists. */
function InfoBullet() {
  return <span className="info-bullet" aria-hidden="true">i</span>;
}

/** Mount the route shell for the isolated GIEN governance console. */
export default function App() {
  return <PageLayout />;
}
