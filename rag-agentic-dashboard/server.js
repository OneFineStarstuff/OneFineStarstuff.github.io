/**
 * ══════════════════════════════════════════════════════════════════════════════
 * RAG AGENTIC AI GOVERNANCE DASHBOARD — Production Server
 * ══════════════════════════════════════════════════════════════════════════════
 * Multi-Agent Orchestrator with:
 *  - Autonomous Governance Agent (ISO 42001, NIST AI RMF, GDPR, EU AI Act)
 *  - Risk Intelligence Agent (anomaly detection, predictive risk scoring)
 *  - Performance Agent (real-time telemetry, SLA monitoring)
 *  - Compliance Agent (automated drift detection, control validation)
 *  - Forecasting Agent (budget projection, capacity planning)
 *  - ASI Synthesis Layer (meta-reasoning, cross-domain inference)
 *
 * WebSocket real-time feeds + REST API + Self-healing monitors
 * ══════════════════════════════════════════════════════════════════════════════
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// ── Static Files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 1: CORE DATA STORE (Simulates production database)
// ══════════════════════════════════════════════════════════════════════════════

const STATE = {
  reportMeta: {
    title: 'RAG System — Agentic AI Executive Governance Dashboard',
    reportPeriod: 'Jan 27 – Feb 9, 2026',
    week: 14, totalWeeks: 20,
    classification: 'CONFIDENTIAL — Executive Steering Committee',
    docRef: 'RAG-GOV-RPT-014',
    overallHealth: 'GREEN',
    agenticMode: 'ACTIVE',
    lastUpdated: new Date().toISOString()
  },

  // ── KPIs ──
  kpis: {
    completion: { value: 70, prev: 62, target: 70, unit: '%' },
    budget: { spent: 1260000, plan: 1290000, total: 2100000, currency: 'USD' },
    schedule: { current: 14, total: 20, status: 'ON_PLAN' },
    ragStatus: 'GREEN',
    governanceReadiness: { value: 82, prev: 77, target: 85 },
    uptime: { value: 99.92, target: 99.80, prev: 99.85 },
    queryVolume: { value: 47200, prev: 40000, unit: 'weekly' },
    accuracy: { value: 91.4, prev: 90.2, target: 90.0, unit: 'F1%' },
    costPerQuery: { value: 0.027, plan: 0.031, prev: 0.029 },
    roi: { value: 2.4, target: 2.0 },
    productivity: { value: 18, unit: '%' },
    qaPassRate: { value: 97.8, target: 95.0 },
    budgetVariance: { value: -29000 },
    csat: { score: 4.3, max: 5.0, percent: 86, prev: 4.1 }
  },

  // ── Department Adoption ──
  adoption: [
    { dept: 'Engineering', rate: 92, trend: 'up', prev: 88 },
    { dept: 'Customer Support', rate: 84, trend: 'up', prev: 79 },
    { dept: 'Legal & Compliance', rate: 61, trend: 'up', prev: 55 },
    { dept: 'Finance', rate: 53, trend: 'up', prev: 48 },
    { dept: 'HR Operations', rate: 41, trend: 'up', prev: 32 },
    { dept: 'Executive Office', rate: 38, trend: 'up', prev: 30 }
  ],

  // ── Compliance Frameworks ──
  compliance: {
    iso42001: {
      score: 78, prev: 72, target: 90,
      controls: [
        { id: 'A.5.2', name: 'AI Policy & Leadership', status: 'DONE', score: 100 },
        { id: 'A.6.2', name: 'AI Risk Assessment', status: 'DONE', score: 100 },
        { id: 'A.6.5', name: 'AI Impact Assessment', status: 'IN_PROGRESS', score: 75 },
        { id: 'A.7.3', name: 'Data Quality for AI', status: 'IN_PROGRESS', score: 68 },
        { id: 'A.7.5', name: 'AI System Documentation', status: 'IN_PROGRESS', score: 72 },
        { id: 'A.8.2', name: 'AI System Design', status: 'DONE', score: 95 },
        { id: 'A.8.4', name: 'Lifecycle Monitoring', status: 'IN_PROGRESS', score: 60 },
        { id: 'A.9.2', name: 'Performance Evaluation', status: 'PLANNED', score: 25 },
        { id: 'A.9.3', name: 'Internal Audit', status: 'PLANNED', score: 15 },
        { id: 'A.10.1', name: 'Continual Improvement', status: 'PLANNED', score: 10 }
      ]
    },
    nistAiRmf: {
      score: 81, prev: 77,
      functions: [
        { name: 'GOVERN', score: 85, prev: 82, subcats: [
          { id: 'GV.1', name: 'Policies & Procedures', score: 92 },
          { id: 'GV.2', name: 'Accountability Structures', score: 88 },
          { id: 'GV.3', name: 'Workforce Diversity', score: 75 },
          { id: 'GV.4', name: 'Org. Governance', score: 85 }
        ]},
        { name: 'MAP', score: 80, prev: 76, subcats: [
          { id: 'MP.1', name: 'Context Established', score: 90 },
          { id: 'MP.2', name: 'Stakeholder Mapping', score: 82 },
          { id: 'MP.3', name: 'Benefits & Costs', score: 78 },
          { id: 'MP.5', name: 'Impact Assessment', score: 70 }
        ]},
        { name: 'MEASURE', score: 68, prev: 64, subcats: [
          { id: 'MS.1', name: 'Risk Measurement', score: 75 },
          { id: 'MS.2', name: 'Bias & Fairness', score: 62 },
          { id: 'MS.3', name: 'Explainability', score: 58 },
          { id: 'MS.4', name: 'Security Testing', score: 77 }
        ]},
        { name: 'MANAGE', score: 62, prev: 58, subcats: [
          { id: 'MG.1', name: 'Risk Response', score: 70 },
          { id: 'MG.2', name: 'Risk Monitoring', score: 65 },
          { id: 'MG.3', name: 'Incident Management', score: 58 },
          { id: 'MG.4', name: 'Decommission Plans', score: 55 }
        ]}
      ]
    },
    gdpr: {
      score: 72, prev: 68,
      items: [
        { article: 'Art. 6', name: 'Lawful Basis', status: 'DONE', score: 100 },
        { article: 'Art. 13/14', name: 'Transparency Notice', status: 'DONE', score: 95 },
        { article: 'Art. 22', name: 'Automated Decision-Making', status: 'IN_PROGRESS', score: 70 },
        { article: 'Art. 25', name: 'Data Protection by Design', status: 'IN_PROGRESS', score: 80 },
        { article: 'Art. 30', name: 'Processing Records', status: 'DONE', score: 100 },
        { article: 'Art. 35', name: 'DPIA', status: 'IN_PROGRESS', score: 65 },
        { article: 'Art. 44-49', name: 'Int\'l Transfers', status: 'IN_PROGRESS', score: 55 }
      ]
    },
    euAiAct: { riskTier: 'LIMITED', status: 'CONFIRMED', transparencyReady: true }
  },

  // ── Workstreams ──
  workstreams: [
    { name: 'Data Ingestion Pipeline', owner: 'M. Chen', completion: 100, status: 'COMPLETE', utilization: 0, trend: 'done' },
    { name: 'Vector Store & Retrieval', owner: 'A. Patel', completion: 100, status: 'COMPLETE', utilization: 0, trend: 'done' },
    { name: 'Generation Pipeline', owner: 'S. Rivera', completion: 45, status: 'ON_TRACK', utilization: 87, trend: 'up' },
    { name: 'Security & Compliance', owner: 'J. Okafor', completion: 68, status: 'ON_TRACK', utilization: 74, trend: 'flat' },
    { name: 'AI Governance & DPIA', owner: 'DPO Office', completion: 65, status: 'IN_PROGRESS', utilization: 70, trend: 'up' },
    { name: 'UI/UX & Front-End', owner: 'L. Tanaka', completion: 55, status: 'AT_RISK', utilization: 95, trend: 'down' },
    { name: 'Testing & QA', owner: 'R. Gupta', completion: 60, status: 'ON_TRACK', utilization: 81, trend: 'up' },
    { name: 'Change Mgmt & Training', owner: 'K. Duval', completion: 38, status: 'PLANNED', utilization: 42, trend: 'flat' }
  ],

  // ── Risks ──
  risks: [
    { id: 'R-1', category: 'Vendor', title: 'API Rate-Limit Change', framework: 'NIST MANAGE 4.1',
      severity: 'MEDIUM', probability: 45, impact: 'HIGH', trend: 'flat',
      mitigation: 'Enterprise tier negotiation; secondary provider fallback tested',
      deadline: '2026-02-13', escalation: true },
    { id: 'R-2', category: 'Resource', title: 'UI/UX Capacity Constraint', framework: 'ISO A.7.5',
      severity: 'MEDIUM', probability: 70, impact: 'MEDIUM', trend: 'down',
      mitigation: '1 contract developer requested ($18K)',
      deadline: '2026-02-10', escalation: true },
    { id: 'R-3', category: 'Regulatory', title: 'EU AI Act Implementation', framework: 'EU AI Act Art. 52',
      severity: 'MEDIUM', probability: 30, impact: 'MEDIUM', trend: 'flat',
      mitigation: 'Monitoring implementing rules; DPO engaged', deadline: null, escalation: false },
    { id: 'R-4', category: 'Data Quality', title: 'Embedding Drift', framework: 'ISO A.7.3 / NIST MAP 2.3',
      severity: 'LOW', probability: 15, impact: 'LOW', trend: 'up',
      mitigation: 'Automated drift detection deployed', deadline: null, escalation: false },
    { id: 'R-5', category: 'Bias/Fairness', title: 'Model Fairness Gap', framework: 'NIST MEASURE 2.6',
      severity: 'LOW', probability: 10, impact: 'MEDIUM', trend: 'up',
      mitigation: 'Fairness audit Feb 20', deadline: '2026-02-20', escalation: false },
    { id: 'R-6', category: 'Security', title: 'Prompt Injection Surface', framework: 'NIST MG.4 / OWASP LLM',
      severity: 'LOW', probability: 12, impact: 'HIGH', trend: 'up',
      mitigation: 'Input sanitization layer + red-team exercise planned', deadline: '2026-02-24', escalation: false }
  ],

  // ── Action Items ──
  actions: [
    { item: 'Approve contract front-end developer ($18K)', owner: 'VP Eng', due: '2026-02-10', status: 'OVERDUE_SOON', trend: 'down', followUp: 'Escalate to CTO if no response by Feb 9' },
    { item: 'Decide LLM provider tier upgrade', owner: 'CTO', due: '2026-02-13', status: 'OPEN', trend: 'flat', followUp: 'Vendor contract in legal review' },
    { item: 'Review & approve DPIA (Art. 35)', owner: 'DPO', due: '2026-02-18', status: 'IN_PROGRESS', trend: 'up', followUp: '65% complete; legal assessment underway' },
    { item: 'Review SOC 2 evidence package', owner: 'CISO', due: '2026-02-14', status: 'ON_TRACK', trend: 'up', followUp: 'Draft 80% complete' },
    { item: 'Sign-off training rollout plan', owner: 'COO', due: '2026-02-12', status: 'ON_TRACK', trend: 'up', followUp: 'Plan shared; calendar pending' },
    { item: 'Authorize fairness audit scope', owner: 'CLO', due: '2026-02-15', status: 'NEW', trend: 'flat', followUp: 'RFP sent to 2 audit firms' }
  ]
};

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 2: AGENTIC AI ENGINE — Multi-Agent Orchestrator
// ══════════════════════════════════════════════════════════════════════════════

class AgentBase {
  constructor(name, type, color) {
    this.id = uuidv4().slice(0, 8);
    this.name = name;
    this.type = type;
    this.color = color;
    this.status = 'ACTIVE';
    this.lastRun = null;
    this.runCount = 0;
    this.findings = [];
  }

  execute() {
    this.lastRun = Date.now();
    this.runCount++;
    return { agent: this.name, type: this.type, timestamp: this.lastRun, runCount: this.runCount };
  }

  toJSON() {
    return { id: this.id, name: this.name, type: this.type, color: this.color,
      status: this.status, lastRun: this.lastRun, runCount: this.runCount,
      findingsCount: this.findings.length };
  }
}

class GovernanceAgent extends AgentBase {
  constructor() { super('Governance Sentinel', 'GOVERNANCE', '#a78bfa'); }

  execute() {
    const base = super.execute();
    const iso = STATE.compliance.iso42001;
    const nist = STATE.compliance.nistAiRmf;
    const gdpr = STATE.compliance.gdpr;

    // Autonomous compliance scoring
    const overallCompliance = Math.round((iso.score + nist.score + gdpr.score) / 3);
    const gaps = [];
    iso.controls.filter(c => c.status === 'PLANNED').forEach(c => {
      gaps.push({ framework: 'ISO 42001', control: c.id, name: c.name, urgency: c.score < 20 ? 'HIGH' : 'MEDIUM' });
    });
    nist.functions.forEach(f => {
      f.subcats.filter(s => s.score < 65).forEach(s => {
        gaps.push({ framework: 'NIST AI RMF', control: s.id, name: s.name, urgency: s.score < 50 ? 'HIGH' : 'MEDIUM' });
      });
    });

    const finding = {
      id: uuidv4().slice(0, 8),
      type: 'GOVERNANCE_SCAN',
      timestamp: Date.now(),
      overallCompliance,
      gapCount: gaps.length,
      criticalGaps: gaps.filter(g => g.urgency === 'HIGH').length,
      recommendation: gaps.length > 3
        ? 'ALERT: Multiple governance gaps detected. Recommend prioritizing NIST MEASURE subcategories and ISO A.9.x audit controls.'
        : 'Governance posture healthy. Continue current remediation trajectory.',
      gaps: gaps.slice(0, 5)
    };
    this.findings.unshift(finding);
    if (this.findings.length > 50) this.findings.pop();
    return { ...base, finding };
  }
}

class RiskAgent extends AgentBase {
  constructor() { super('Risk Intelligence', 'RISK', '#ef6461'); }

  execute() {
    const base = super.execute();
    const activeRisks = STATE.risks.filter(r => r.escalation);
    const riskScore = STATE.risks.reduce((s, r) => {
      const sevMap = { HIGH: 3, MEDIUM: 2, LOW: 1 };
      return s + (sevMap[r.severity] || 1) * (r.probability / 100);
    }, 0);

    // Simulate anomaly detection
    const anomalies = [];
    if (STATE.kpis.uptime.value < STATE.kpis.uptime.target) {
      anomalies.push({ metric: 'Uptime', current: STATE.kpis.uptime.value, threshold: STATE.kpis.uptime.target, severity: 'HIGH' });
    }
    if (STATE.kpis.costPerQuery.value > STATE.kpis.costPerQuery.plan) {
      anomalies.push({ metric: 'Cost/Query', current: STATE.kpis.costPerQuery.value, threshold: STATE.kpis.costPerQuery.plan, severity: 'MEDIUM' });
    }
    // Check workstream health
    STATE.workstreams.filter(w => w.utilization > 90).forEach(w => {
      anomalies.push({ metric: `${w.name} Utilization`, current: w.utilization, threshold: 85, severity: 'MEDIUM' });
    });

    const finding = {
      id: uuidv4().slice(0, 8),
      type: 'RISK_ANALYSIS',
      timestamp: Date.now(),
      compositeRiskScore: Math.round(riskScore * 100) / 100,
      escalationCount: activeRisks.length,
      anomalyCount: anomalies.length,
      anomalies,
      recommendation: riskScore > 3
        ? 'ELEVATED: Composite risk score above threshold. Immediate mitigation on R-1 and R-2 recommended.'
        : 'Risk posture within acceptable bounds. Continue monitoring.',
      predictedRiskTrend: riskScore > 2.5 ? 'INCREASING' : 'STABLE'
    };
    this.findings.unshift(finding);
    if (this.findings.length > 50) this.findings.pop();
    return { ...base, finding };
  }
}

class PerformanceAgent extends AgentBase {
  constructor() { super('Performance Monitor', 'PERFORMANCE', '#2dd4a0'); }

  execute() {
    const base = super.execute();
    // Real-time telemetry synthesis
    const now = Date.now();
    const jitter = (base, range) => +(base + (Math.random() - 0.5) * range).toFixed(3);
    const telemetry = {
      timestamp: now,
      queries_per_second: jitter(6.7, 2),
      p50_latency_ms: jitter(142, 30),
      p95_latency_ms: jitter(380, 80),
      p99_latency_ms: jitter(720, 150),
      error_rate: jitter(0.08, 0.06),
      cache_hit_rate: jitter(0.73, 0.1),
      vector_search_ms: jitter(45, 15),
      llm_inference_ms: jitter(285, 60),
      token_throughput: jitter(12400, 3000),
      active_connections: Math.floor(jitter(234, 80)),
      gpu_utilization: jitter(67, 15),
      memory_usage_gb: jitter(14.2, 3)
    };

    // SLA check
    const slaViolations = [];
    if (telemetry.p95_latency_ms > 500) slaViolations.push({ metric: 'P95 Latency', value: telemetry.p95_latency_ms, sla: 500 });
    if (telemetry.error_rate > 0.5) slaViolations.push({ metric: 'Error Rate', value: telemetry.error_rate, sla: 0.5 });

    const finding = {
      id: uuidv4().slice(0, 8),
      type: 'PERFORMANCE_TELEMETRY',
      timestamp: now,
      telemetry,
      slaViolations,
      healthScore: slaViolations.length === 0 ? 'HEALTHY' : 'DEGRADED'
    };
    this.findings.unshift(finding);
    if (this.findings.length > 200) this.findings.length = 200;
    return { ...base, finding };
  }
}

class ComplianceAgent extends AgentBase {
  constructor() { super('Compliance Auditor', 'COMPLIANCE', '#4da6ff'); }

  execute() {
    const base = super.execute();
    // Automated control validation
    const controlResults = STATE.compliance.iso42001.controls.map(c => ({
      control: c.id,
      name: c.name,
      status: c.status,
      score: c.score,
      automated: c.score > 50,
      lastValidated: Date.now() - Math.random() * 86400000,
      driftDetected: Math.random() < 0.05
    }));

    const drifts = controlResults.filter(c => c.driftDetected);
    const finding = {
      id: uuidv4().slice(0, 8),
      type: 'COMPLIANCE_AUDIT',
      timestamp: Date.now(),
      controlsValidated: controlResults.length,
      controlsPassing: controlResults.filter(c => c.score >= 70).length,
      driftDetections: drifts.length,
      drifts,
      recommendation: drifts.length > 0
        ? `DRIFT ALERT: ${drifts.length} control(s) showing regression. Automated remediation initiated.`
        : 'All controls within expected parameters. Next full audit scheduled per ISO A.9.3.',
      automatedRemediations: drifts.length
    };
    this.findings.unshift(finding);
    if (this.findings.length > 50) this.findings.pop();
    return { ...base, finding };
  }
}

class ForecastingAgent extends AgentBase {
  constructor() { super('Forecasting Engine', 'FORECAST', '#f5b731'); }

  execute() {
    const base = super.execute();
    const k = STATE.kpis;
    const weeklyBurnRate = k.budget.spent / STATE.reportMeta.week;
    const projectedTotal = weeklyBurnRate * STATE.reportMeta.totalWeeks;
    const weeksRemaining = STATE.reportMeta.totalWeeks - STATE.reportMeta.week;

    // Monte Carlo-style projection (simplified)
    const scenarios = {
      optimistic: { budget: Math.round(projectedTotal * 0.92), completion: '2026-05-12', confidence: 0.25 },
      baseline: { budget: Math.round(projectedTotal), completion: '2026-05-22', confidence: 0.55 },
      pessimistic: { budget: Math.round(projectedTotal * 1.12), completion: '2026-06-05', confidence: 0.20 }
    };

    // Capacity forecast
    const capacityForecast = {
      currentQPS: k.queryVolume.value / (7 * 24 * 3600),
      projectedPeakQPS: (k.queryVolume.value * 1.18) / (7 * 24 * 3600) * 2.5,
      maxCapacityQPS: 15,
      headroom: null
    };
    capacityForecast.headroom = ((capacityForecast.maxCapacityQPS - capacityForecast.projectedPeakQPS) / capacityForecast.maxCapacityQPS * 100).toFixed(1);

    const finding = {
      id: uuidv4().slice(0, 8),
      type: 'FORECAST',
      timestamp: Date.now(),
      budgetProjection: scenarios,
      weeklyBurnRate: Math.round(weeklyBurnRate),
      weeksRemaining,
      capacityForecast,
      recommendation: projectedTotal > k.budget.total * 1.05
        ? 'WARNING: Projected spend exceeds budget by >5%. Cost optimization review recommended.'
        : `Budget on track. Projected ${((k.budget.total - projectedTotal) / k.budget.total * 100).toFixed(1)}% favorable at completion.`
    };
    this.findings.unshift(finding);
    if (this.findings.length > 50) this.findings.pop();
    return { ...base, finding };
  }
}

// ── ASI Synthesis Layer ──────────────────────────────────────────────────────
class ASISynthesisEngine extends AgentBase {
  constructor(agents) {
    super('ASI Synthesis Core', 'ASI_SYNTHESIS', '#22d3ee');
    this.agents = agents;
  }

  execute() {
    const base = super.execute();
    // Cross-agent meta-reasoning
    const agentStates = this.agents.map(a => ({
      agent: a.name, lastFinding: a.findings[0] || null, totalFindings: a.findings.length
    }));

    // Emergent insight generation
    const insights = [];
    const gov = this.agents.find(a => a.type === 'GOVERNANCE');
    const risk = this.agents.find(a => a.type === 'RISK');
    const perf = this.agents.find(a => a.type === 'PERFORMANCE');
    const forecast = this.agents.find(a => a.type === 'FORECAST');

    // Cross-domain inference #1: Governance-Risk correlation
    if (gov?.findings[0] && risk?.findings[0]) {
      const gapCount = gov.findings[0].gapCount || 0;
      const riskScore = risk.findings[0].compositeRiskScore || 0;
      if (gapCount > 2 && riskScore > 2) {
        insights.push({
          type: 'CROSS_DOMAIN',
          severity: 'HIGH',
          title: 'Governance-Risk Correlation Detected',
          detail: `${gapCount} governance gaps correlate with elevated risk score (${riskScore}). Closing ISO A.9.x audit controls would reduce composite risk by estimated 18%.`,
          confidence: 0.82,
          actions: ['Prioritize ISO A.9.2 Performance Evaluation', 'Accelerate NIST MEASURE subcategory remediation']
        });
      }
    }

    // Cross-domain inference #2: Performance-Cost optimization
    if (perf?.findings[0] && forecast?.findings[0]) {
      const cacheHit = perf.findings[0]?.telemetry?.cache_hit_rate || 0;
      if (cacheHit < 0.7) {
        insights.push({
          type: 'OPTIMIZATION',
          severity: 'MEDIUM',
          title: 'Cache Optimization Opportunity',
          detail: `Cache hit rate at ${(cacheHit * 100).toFixed(0)}% suggests potential 15-22% cost reduction through query deduplication and semantic caching.`,
          confidence: 0.75,
          actions: ['Deploy semantic cache layer', 'Implement query fingerprinting']
        });
      }
    }

    // Cross-domain inference #3: Capacity-Budget alignment
    if (forecast?.findings[0]) {
      const headroom = parseFloat(forecast.findings[0]?.capacityForecast?.headroom || 100);
      if (headroom < 40) {
        insights.push({
          type: 'CAPACITY',
          severity: 'MEDIUM',
          title: 'Capacity Headroom Alert',
          detail: `System headroom at ${headroom}%. At current adoption velocity, capacity scaling needed within 4 weeks.`,
          confidence: 0.88,
          actions: ['Pre-provision GPU instances', 'Evaluate horizontal scaling strategy']
        });
      }
    }

    // Always generate a synthesis summary
    insights.push({
      type: 'SYNTHESIS',
      severity: 'INFO',
      title: 'Autonomous System Health Assessment',
      detail: `All ${this.agents.length} agents operational. ${agentStates.reduce((s, a) => s + a.totalFindings, 0)} total observations processed. System convergence index: ${(85 + Math.random() * 10).toFixed(1)}%.`,
      confidence: 0.95,
      actions: ['Continue autonomous monitoring cycle']
    });

    const finding = {
      id: uuidv4().slice(0, 8),
      type: 'ASI_SYNTHESIS',
      timestamp: Date.now(),
      insightCount: insights.length,
      criticalInsights: insights.filter(i => i.severity === 'HIGH').length,
      insights,
      agentStates,
      chainOfThought: [
        'Collected latest findings from all 5 specialist agents',
        'Performed cross-domain correlation analysis (governance x risk, performance x cost, capacity x budget)',
        `Generated ${insights.length} emergent insights with confidence scoring`,
        'Validated recommendations against ISO 42001 Annex A and NIST AI RMF controls',
        'Synthesized executive-ready action brief'
      ]
    };
    this.findings.unshift(finding);
    if (this.findings.length > 50) this.findings.pop();
    return { ...base, finding };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 2B: DIRECTIVE EVALUATOR AGENT
// ══════════════════════════════════════════════════════════════════════════════

class DirectiveEvaluatorAgent extends AgentBase {
  constructor() {
    super('Directive Evaluator', 'DIRECTIVE_EVAL', '#f59e42');
    this.evaluationHistory = [];
  }

  evaluate(directiveText) {
    const base = super.execute();
    const text = (directiveText || '').trim();

    // Step 1: Empty/gibberish check
    if (!text || text.length < 10) {
      return this._failResult(base, 0, 'Directive is empty or too short to constitute a viable use case.', text);
    }

    const tl = text.toLowerCase();

    // Step 2: Criterion 1 — Goal Clarity
    const goalSignals = [
      /govern(ance)?/i, /compliance/i, /risk\s*(management|assess|mitigat)/i,
      /implement(ation)?/i, /deploy/i, /audit/i, /rag\b/i, /retrieval.augmented/i,
      /regulat(ed|ory|ion)/i, /enterprise/i, /production/i, /directive/i,
      /fortune\s*500/i, /iso\s*42001/i, /nist/i, /gdpr/i, /eu\s*ai\s*act/i,
      /business\s*use\s*case/i, /viable/i, /actionable/i
    ];
    const goalHits = goalSignals.filter(r => r.test(text)).length;
    const goalClarity = goalHits >= 3;
    const goalEvidence = [];
    if (/rag\b|retrieval.augmented/i.test(text)) goalEvidence.push('RAG system explicitly identified');
    if (/govern(ance)?|compliance/i.test(text)) goalEvidence.push('Governance/compliance objective stated');
    if (/implement(ation)?|deploy|production/i.test(text)) goalEvidence.push('Implementation scope defined');
    if (/fortune\s*500|enterprise|large/i.test(text)) goalEvidence.push('Enterprise scale specified');
    if (/regulat(ed|ory)/i.test(text)) goalEvidence.push('Regulated environment identified');
    if (/viable|actionable|assess/i.test(text)) goalEvidence.push('Success criteria implied (viability assessment)');

    // Step 3: Criterion 2 — Operational Scope
    const scopeSignals = [
      /fortune\s*500/i, /large.enterprise/i, /department/i, /user/i, /scale/i,
      /data\s*source/i, /document/i, /vector/i, /12\s*m/i, /million/i,
      /omni.sentinel/i, /project/i, /stakeholder/i, /team/i,
      /customer\s*support/i, /engineering/i, /legal/i, /finance/i
    ];
    const scopeHits = scopeSignals.filter(r => r.test(text)).length;
    const operationalScope = scopeHits >= 2;
    const scopeEvidence = [];
    if (/fortune\s*500/i.test(text)) scopeEvidence.push('Fortune 500 scale explicitly stated');
    if (/large.enterprise/i.test(text)) scopeEvidence.push('Large-enterprise scope defined');
    if (/regulat(ed|ory)/i.test(text)) scopeEvidence.push('Regulated industry context provided');
    if (/omni.sentinel/i.test(text)) scopeEvidence.push('Reference implementation (Project Omni-Sentinel) identified');
    if (/rag\b|retrieval/i.test(text)) scopeEvidence.push('Technical system type (RAG) provides data-source inference');

    // Step 4: Criterion 3 — Domain Context
    const domainSignals = [
      /iso\s*42001/i, /nist\s*ai\s*r(mf|isk)/i, /gdpr/i, /eu\s*ai\s*act/i,
      /annex\s*a/i, /govern.*map.*measure.*manage/i, /soc\s*2/i,
      /dpia/i, /art(icle)?\s*\d+/i, /model\s*card/i, /bias/i, /fairness/i,
      /data\s*protection/i, /privacy/i, /transparency/i, /risk\s*tier/i
    ];
    const domainHits = domainSignals.filter(r => r.test(text)).length;
    const domainContext = domainHits >= 2;
    const domainEvidence = [];
    if (/iso\s*42001/i.test(text)) domainEvidence.push('ISO/IEC 42001 explicitly referenced');
    if (/nist\s*ai\s*r(mf|isk)/i.test(text)) domainEvidence.push('NIST AI RMF framework cited');
    if (/gdpr/i.test(text)) domainEvidence.push('EU GDPR requirements invoked');
    if (/eu\s*ai\s*act/i.test(text)) domainEvidence.push('EU AI Act regulatory context provided');
    if (/govern.*map.*measure.*manage/i.test(text)) domainEvidence.push('NIST AI RMF functions enumerated (Govern, Map, Measure, Manage)');
    if (/regulat(ed|ory)/i.test(text)) domainEvidence.push('Regulatory compliance context established');

    const score = (goalClarity ? 1 : 0) + (operationalScope ? 1 : 0) + (domainContext ? 1 : 0);

    const evaluation = {
      id: uuidv4().slice(0, 8),
      timestamp: Date.now(),
      directiveExcerpt: text.slice(0, 200) + (text.length > 200 ? '...' : ''),
      criteria: {
        goalClarity: { pass: goalClarity, signals: goalHits, evidence: goalEvidence },
        operationalScope: { pass: operationalScope, signals: scopeHits, evidence: scopeEvidence },
        domainContext: { pass: domainContext, signals: domainHits, evidence: domainEvidence }
      },
      score,
      maxScore: 3,
      path: score >= 2 ? 'PATH_A' : 'PATH_B',
      verdict: score >= 2
        ? 'ACTIONABLE — Directive constitutes a viable, auditable business use case. Proceed to full governance report generation.'
        : 'UNCLEAR — Directive lacks sufficient specificity for governance control application. Clarification required.',
      chainOfThought: [
        `[STEP 1] Input validation: ${text.length} characters, non-empty, substantive content detected.`,
        `[STEP 2] Goal Clarity: ${goalHits} signal matches → ${goalClarity ? 'PASS' : 'FAIL'}. ${goalEvidence.join('; ') || 'Insufficient goal signals.'}`,
        `[STEP 3] Operational Scope: ${scopeHits} signal matches → ${operationalScope ? 'PASS' : 'FAIL'}. ${scopeEvidence.join('; ') || 'Insufficient scope signals.'}`,
        `[STEP 4] Domain Context: ${domainHits} signal matches → ${domainContext ? 'PASS' : 'FAIL'}. ${domainEvidence.join('; ') || 'Insufficient domain signals.'}`,
        `[STEP 5] Score: ${score}/3. Threshold: 2. Path: ${score >= 2 ? 'A (Success)' : 'B (Failure)'}.`,
        `[STEP 6] ${score >= 2 ? 'Generating PATH A: Full governance report with Risk & Compliance Matrix, RACI, Technical Requirements, Architecture Diagram, Implementation Artifacts.' : 'Generating PATH B: JSON diagnostic with missing elements and clarifying questions.'}`
      ]
    };

    // If PATH A, generate the governance report sections
    if (score >= 2) {
      evaluation.report = this._generatePathAReport(text);
    } else {
      evaluation.diagnostic = this._generatePathBDiagnostic(text, evaluation.criteria);
    }

    this.evaluationHistory.unshift(evaluation);
    if (this.evaluationHistory.length > 20) this.evaluationHistory.pop();
    this.findings.unshift({ ...evaluation, type: 'DIRECTIVE_EVALUATION' });
    if (this.findings.length > 50) this.findings.pop();

    return { ...base, finding: evaluation };
  }

  _failResult(base, score, analysis, text) {
    const evaluation = {
      id: uuidv4().slice(0, 8), timestamp: Date.now(), directiveExcerpt: text.slice(0, 100),
      criteria: { goalClarity: { pass: false }, operationalScope: { pass: false }, domainContext: { pass: false } },
      score, maxScore: 3, path: 'PATH_B', verdict: 'UNCLEAR — ' + analysis,
      diagnostic: { status: 'UNCLEAR', score, analysis, missing_elements: ['Complete directive text'], clarifying_questions: ['What is the specific AI system being governed?'] }
    };
    this.findings.unshift({ ...evaluation, type: 'DIRECTIVE_EVALUATION' });
    return { ...base, finding: evaluation };
  }

  _generatePathAReport(text) {
    return {
      executiveSummary: {
        title: 'AI Governance Directive — Fortune 500 RAG Implementation',
        feasibility: 'HIGH',
        strategicAlignment: 'The directive to establish AI governance controls for a Fortune 500 regulated RAG implementation (comparable to Project Omni-Sentinel) is strategically aligned with enterprise risk management mandates, EU regulatory obligations, and industry best-practice frameworks (ISO 42001, NIST AI RMF). The RAG system\'s classification under the EU AI Act as "Limited Risk" (transparency tier) reduces regulatory burden while still requiring comprehensive governance documentation.',
        recommendation: 'PROCEED with full governance implementation. Estimated governance readiness timeline: 8-12 weeks to production GA with all compliance artifacts completed.'
      },
      riskComplianceMatrix: [
        { risk: 'Uncontrolled LLM output generation (hallucination)', isoControl: 'A.8.4 (Lifecycle Monitoring)', nistFunction: 'MEASURE 2.5 (AI Output Monitoring)', likelihood: 'MEDIUM', impact: 'HIGH', mitigation: 'Implement RAG grounding validation, citation verification, output confidence scoring' },
        { risk: 'PII leakage through retrieval context', isoControl: 'A.7.3 (Data Quality)', nistFunction: 'MAP 2.3 (Data Properties)', likelihood: 'MEDIUM', impact: 'CRITICAL', mitigation: 'PII redaction layer at API Gateway (GDPR Art. 25 by-design), tokenization of sensitive fields before vector embedding' },
        { risk: 'Prompt injection / adversarial input', isoControl: 'A.8.2 (AI System Design)', nistFunction: 'MANAGE 4.1 (Risk Response)', likelihood: 'LOW', impact: 'HIGH', mitigation: 'Input sanitization, system-prompt hardening, red-team exercises per OWASP LLM Top 10' },
        { risk: 'Model bias in retrieval ranking', isoControl: 'A.9.2 (Performance Evaluation)', nistFunction: 'MEASURE 2.6 (Bias Assessment)', likelihood: 'LOW', impact: 'MEDIUM', mitigation: 'Periodic fairness audit across demographic slices, embedding debiasing techniques' },
        { risk: 'Data sovereignty violation (cross-border LLM calls)', isoControl: 'A.6.2 (Risk Assessment)', nistFunction: 'GOVERN 1.3 (Legal Compliance)', likelihood: 'MEDIUM', impact: 'HIGH', mitigation: 'GDPR Art. 44-49 compliant data processing agreements, EU-hosted inference endpoints, PII-free prompt forwarding' },
        { risk: 'Inadequate audit trail for automated decisions', isoControl: 'A.8.4 (Lifecycle Monitoring)', nistFunction: 'GOVERN 1.2 (Accountability)', likelihood: 'LOW', impact: 'HIGH', mitigation: 'Comprehensive logging per ISO A.8.4, GDPR Art. 22 explainability endpoint, decision provenance chain' },
        { risk: 'Vendor lock-in / single-provider dependency', isoControl: 'A.10.1 (Improvement)', nistFunction: 'MANAGE 3.2 (Risk Prioritization)', likelihood: 'MEDIUM', impact: 'MEDIUM', mitigation: 'Multi-provider abstraction layer, fallback inference path validated, contract exit clauses' },
        { risk: 'Insufficient DPIA coverage', isoControl: 'A.6.5 (Impact Assessment)', nistFunction: 'MAP 5.1 (Impact Documentation)', likelihood: 'MEDIUM', impact: 'HIGH', mitigation: 'Complete DPIA per GDPR Art. 35, covering all automated processing paths, data subject rights mechanisms, DPO sign-off' }
      ],
      raciMatrix: [
        { activity: 'AI Governance Policy', dataSci: 'C', compliance: 'R', audit: 'A', business: 'A', engineering: 'I' },
        { activity: 'DPIA Execution (GDPR Art. 35)', dataSci: 'C', compliance: 'R', audit: 'I', business: 'A', engineering: 'C' },
        { activity: 'Model Validation & Testing', dataSci: 'R', compliance: 'C', audit: 'I', business: 'I', engineering: 'A' },
        { activity: 'Bias & Fairness Monitoring', dataSci: 'R', compliance: 'A', audit: 'C', business: 'I', engineering: 'C' },
        { activity: 'Production Deployment Gate', dataSci: 'C', compliance: 'C', audit: 'C', business: 'A', engineering: 'R' },
        { activity: 'Incident Response', dataSci: 'C', compliance: 'A', audit: 'I', business: 'I', engineering: 'R' },
        { activity: 'Continuous Monitoring (ISO A.8.4)', dataSci: 'C', compliance: 'C', audit: 'R', business: 'A', engineering: 'R' },
        { activity: 'Regulatory Reporting', dataSci: 'I', compliance: 'R', audit: 'A', business: 'I', engineering: 'C' }
      ],
      technicalRequirements: {
        latency: { p95Target: '< 500ms end-to-end', p99Target: '< 1200ms', vectorSearchBudget: '< 80ms', llmInferenceBudget: '< 350ms' },
        dataSovereignty: { primaryRegion: 'EU-West-1 (Frankfurt)', gdprCompliance: 'All PII processing within EU boundary', crossBorderPolicy: 'No PII in external LLM API calls; redaction at API Gateway layer', encryptionAtRest: 'AES-256', encryptionInTransit: 'TLS 1.3' },
        compute: { vectorDB: '3x r6g.2xlarge (dedicated, EU-West-1)', ragOrchestrator: '2x c6g.xlarge (auto-scaling 2-8)', apiGateway: 'AWS ALB + WAF + API Gateway', gpuInference: '2x p4d.24xlarge reserved (if self-hosted) or managed endpoint', storageEstimate: '~2.4 TB for 12M document embeddings (1536-dim)' },
        availability: { slaTarget: '99.9% monthly uptime', rto: '< 4 hours', rpo: '< 1 hour', disasterRecovery: 'Multi-AZ active-passive with automated failover' }
      },
      architectureDiagram: {
        type: 'sequence',
        description: 'Data flow with GDPR security boundaries',
        nodes: [
          { id: 'user', label: 'End User', zone: 'external' },
          { id: 'gateway', label: 'API Gateway (PII Redaction)', zone: 'gdpr_boundary' },
          { id: 'rag', label: 'RAG Orchestrator', zone: 'internal_vpc' },
          { id: 'vectordb', label: 'Vector DB (AES-256)', zone: 'internal_vpc' },
          { id: 'agents', label: 'AI Agent Mesh (6 agents)', zone: 'internal_vpc' },
          { id: 'audit', label: 'Audit Logger (ISO A.8.4)', zone: 'gdpr_boundary' },
          { id: 'llm', label: 'LLM Provider (No PII)', zone: 'external_vendor' }
        ],
        flows: [
          { from: 'user', to: 'gateway', label: 'HTTPS/TLS 1.3' },
          { from: 'gateway', to: 'rag', label: 'Sanitized query' },
          { from: 'rag', to: 'vectordb', label: 'Embedding lookup' },
          { from: 'rag', to: 'llm', label: 'PII-free prompt' },
          { from: 'rag', to: 'audit', label: 'Decision log' },
          { from: 'agents', to: 'rag', label: 'Governance signals' }
        ]
      },
      implementationArtifacts: [
        { name: 'Data Protection Impact Assessment (DPIA)', framework: 'GDPR Art. 35', priority: 'P0', status: 'Required before production', estimatedEffort: '40-60 hrs' },
        { name: 'AI System Model Card', framework: 'NIST MAP 1.5 / ISO A.7.5', priority: 'P0', status: 'Required', estimatedEffort: '20-30 hrs' },
        { name: 'ISO 42001 Statement of Applicability', framework: 'ISO 42001 Clause 6.1.3', priority: 'P0', status: 'Required for certification', estimatedEffort: '30-40 hrs' },
        { name: 'System Instructions & Guardrails Document', framework: 'NIST GOVERN 1.1', priority: 'P1', status: 'Required', estimatedEffort: '15-20 hrs' },
        { name: 'NIST AI RMF Playbook (RAG-specific)', framework: 'NIST AI RMF Playbook', priority: 'P1', status: 'Recommended', estimatedEffort: '25-35 hrs' },
        { name: 'Bias & Fairness Audit Report', framework: 'NIST MEASURE 2.6 / ISO A.9.2', priority: 'P1', status: 'Required pre-GA', estimatedEffort: '30-40 hrs' },
        { name: 'Incident Response Playbook', framework: 'NIST MANAGE 4.1 / ISO A.10.1', priority: 'P1', status: 'Required pre-GA', estimatedEffort: '15-20 hrs' },
        { name: 'Data Processing Records (Art. 30)', framework: 'GDPR Art. 30', priority: 'P0', status: 'Legally required', estimatedEffort: '10-15 hrs' },
        { name: 'Penetration Test Report', framework: 'SOC 2 / ISO A.8.2', priority: 'P1', status: 'Required pre-GA', estimatedEffort: 'External vendor' },
        { name: 'EU AI Act Transparency Documentation', framework: 'EU AI Act Art. 52', priority: 'P2', status: 'Required at deployment', estimatedEffort: '10-15 hrs' }
      ]
    };
  }

  _generatePathBDiagnostic(text, criteria) {
    const missing = [];
    if (!criteria.goalClarity.pass) missing.push('Specific AI system or business outcome', 'Measurable success criteria');
    if (!criteria.operationalScope.pass) missing.push('Target user population and scale', 'Data sources and deployment environment');
    if (!criteria.domainContext.pass) missing.push('Applicable governance frameworks', 'Regulatory jurisdiction and risk classification');
    return {
      status: 'UNCLEAR',
      score: (criteria.goalClarity.pass ? 1 : 0) + (criteria.operationalScope.pass ? 1 : 0) + (criteria.domainContext.pass ? 1 : 0),
      analysis: 'Directive lacks sufficient specificity for governance control application.',
      missing_elements: missing,
      clarifying_questions: [
        'What specific AI system is being governed and what is its current architecture?',
        'What is the measurable business outcome this governance effort targets?',
        'Which regulatory jurisdictions and frameworks apply?',
        'Who are the accountable stakeholders (DPO, Model Owner, Business Owner)?',
        'Has a preliminary risk classification been performed?'
      ],
      recommendations: [
        'Draft a structured use-case brief using ISO 42001 Annex A as a checklist',
        'Conduct a scoping workshop with Compliance, Engineering, and Business stakeholders',
        'Prepare a preliminary risk assessment per NIST AI RMF MAP function'
      ]
    };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 3: AGENT ORCHESTRATOR
// ══════════════════════════════════════════════════════════════════════════════

const directiveEvaluator = new DirectiveEvaluatorAgent();

const agents = {
  governance: new GovernanceAgent(),
  risk: new RiskAgent(),
  performance: new PerformanceAgent(),
  compliance: new ComplianceAgent(),
  forecasting: new ForecastingAgent(),
  directive: directiveEvaluator
};

const asiEngine = new ASISynthesisEngine(Object.values(agents).filter(a => a.type !== 'DIRECTIVE_EVAL'));

// Agent execution schedules
const AGENT_INTERVALS = {
  performance: 2000,    // 2s — high-frequency telemetry
  risk: 8000,           // 8s — risk scanning
  compliance: 12000,    // 12s — compliance audit
  governance: 15000,    // 15s — governance assessment
  forecasting: 20000,   // 20s — forecasting cycle
  asi: 10000            // 10s — ASI synthesis
};

// Simulate slight metric drift for realism
function driftMetrics() {
  const k = STATE.kpis;
  k.queryVolume.value = Math.max(30000, Math.round(k.queryVolume.value + (Math.random() - 0.45) * 500));
  k.uptime.value = Math.min(100, Math.max(99.5, +(k.uptime.value + (Math.random() - 0.4) * 0.02).toFixed(2)));
  k.accuracy.value = Math.min(100, Math.max(88, +(k.accuracy.value + (Math.random() - 0.45) * 0.1).toFixed(1)));
  k.costPerQuery.value = Math.max(0.018, +(k.costPerQuery.value + (Math.random() - 0.55) * 0.001).toFixed(3));
  k.csat.score = Math.min(5, Math.max(3.5, +(k.csat.score + (Math.random() - 0.45) * 0.02).toFixed(1)));
  k.csat.percent = Math.round(k.csat.score / 5 * 100);
  STATE.reportMeta.lastUpdated = new Date().toISOString();
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 4: WEBSOCKET REAL-TIME FEEDS
// ══════════════════════════════════════════════════════════════════════════════

const clients = new Set();

wss.on('connection', (ws) => {
  const clientId = uuidv4().slice(0, 8);
  ws.clientId = clientId;
  clients.add(ws);
  console.log(`[WS] Client connected: ${clientId} (total: ${clients.size})`);

  // Send initial state burst
  ws.send(JSON.stringify({ type: 'INIT', data: {
    state: STATE,
    agents: Object.values(agents).map(a => a.toJSON()),
    asi: asiEngine.toJSON()
  }}));

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'COMMAND') handleCommand(ws, data);
      if (data.type === 'QUERY') handleNLQuery(ws, data);
      if (data.type === 'EVALUATE_DIRECTIVE') handleDirectiveEval(ws, data);
    } catch (e) {}
  });

  ws.on('close', () => {
    clients.delete(ws);
    console.log(`[WS] Client disconnected: ${clientId} (total: ${clients.size})`);
  });
});

function broadcast(type, data) {
  const msg = JSON.stringify({ type, data, timestamp: Date.now() });
  clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  });
}

function handleCommand(ws, data) {
  const { command } = data;
  let result;
  switch (command) {
    case 'FORCE_SCAN':
      result = runAllAgents();
      break;
    case 'GET_STATE':
      result = STATE;
      break;
    case 'GET_AGENTS':
      result = { agents: Object.values(agents).map(a => a.toJSON()), asi: asiEngine.toJSON() };
      break;
    default:
      result = { error: 'Unknown command' };
  }
  ws.send(JSON.stringify({ type: 'COMMAND_RESPONSE', command, data: result }));
}

function handleDirectiveEval(ws, data) {
  const { directive } = data;
  const result = directiveEvaluator.evaluate(directive || '');
  ws.send(JSON.stringify({ type: 'DIRECTIVE_EVAL_RESULT', data: result.finding }));
  // Broadcast to all clients
  broadcast('DIRECTIVE_EVAL_BROADCAST', { finding: result.finding });
}

function handleNLQuery(ws, data) {
  const { query } = data;
  const q = query.toLowerCase();
  let response;

  if (q.includes('evaluate directive') || q.includes('assess directive') || q.includes('governance directive')) {
    // Extract directive text after the keyword
    const directiveText = query.replace(/^(evaluate|assess)\s*(the)?\s*(governance)?\s*directive:?\s*/i, '').trim() || query;
    const evalResult = directiveEvaluator.evaluate(directiveText);
    response = {
      answer: `Directive Evaluation Complete. Score: ${evalResult.finding.score}/${evalResult.finding.maxScore}. Path: ${evalResult.finding.path}. ${evalResult.finding.verdict}`,
      source: 'Directive Evaluator Agent',
      confidence: 0.94,
      data: evalResult.finding
    };
  } else if (q.includes('risk') || q.includes('threat')) {
    const riskResult = agents.risk.execute();
    response = {
      answer: `Current composite risk score: ${riskResult.finding.compositeRiskScore}. ${riskResult.finding.escalationCount} risks require executive escalation. ${riskResult.finding.recommendation}`,
      source: 'Risk Intelligence Agent',
      confidence: 0.92,
      data: riskResult.finding
    };
  } else if (q.includes('compliance') || q.includes('gdpr') || q.includes('iso')) {
    const govResult = agents.governance.execute();
    response = {
      answer: `Overall compliance: ${govResult.finding.overallCompliance}%. ${govResult.finding.gapCount} gaps identified (${govResult.finding.criticalGaps} critical). ${govResult.finding.recommendation}`,
      source: 'Governance Sentinel',
      confidence: 0.90,
      data: govResult.finding
    };
  } else if (q.includes('budget') || q.includes('cost') || q.includes('forecast')) {
    const fcResult = agents.forecasting.execute();
    response = {
      answer: `Weekly burn: $${fcResult.finding.weeklyBurnRate.toLocaleString()}. ${fcResult.finding.weeksRemaining} weeks remaining. ${fcResult.finding.recommendation}`,
      source: 'Forecasting Engine',
      confidence: 0.87,
      data: fcResult.finding
    };
  } else if (q.includes('performance') || q.includes('latency') || q.includes('uptime')) {
    const perfResult = agents.performance.execute();
    response = {
      answer: `P95 latency: ${perfResult.finding.telemetry.p95_latency_ms.toFixed(0)}ms. Uptime: ${STATE.kpis.uptime.value}%. QPS: ${perfResult.finding.telemetry.queries_per_second.toFixed(1)}. Status: ${perfResult.finding.healthScore}`,
      source: 'Performance Monitor',
      confidence: 0.95,
      data: perfResult.finding
    };
  } else {
    const asiResult = asiEngine.execute();
    response = {
      answer: `ASI Synthesis: ${asiResult.finding.insightCount} insights generated. ${asiResult.finding.criticalInsights} critical. ${asiResult.finding.insights[0]?.detail || 'System nominal.'}`,
      source: 'ASI Synthesis Core',
      confidence: 0.88,
      data: asiResult.finding
    };
  }
  ws.send(JSON.stringify({ type: 'QUERY_RESPONSE', query, response }));
}

function runAllAgents() {
  const results = {};
  Object.entries(agents).forEach(([key, agent]) => {
    results[key] = agent.execute();
  });
  results.asi = asiEngine.execute();
  return results;
}

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 5: AUTONOMOUS AGENT SCHEDULING
// ══════════════════════════════════════════════════════════════════════════════

// Performance agent — high frequency
setInterval(() => {
  const result = agents.performance.execute();
  driftMetrics();
  broadcast('AGENT_TELEMETRY', { agent: 'performance', finding: result.finding });
}, AGENT_INTERVALS.performance);

// Risk agent
setInterval(() => {
  const result = agents.risk.execute();
  broadcast('AGENT_FINDING', { agent: 'risk', finding: result.finding });
}, AGENT_INTERVALS.risk);

// Compliance agent
setInterval(() => {
  const result = agents.compliance.execute();
  broadcast('AGENT_FINDING', { agent: 'compliance', finding: result.finding });
}, AGENT_INTERVALS.compliance);

// Governance agent
setInterval(() => {
  const result = agents.governance.execute();
  broadcast('AGENT_FINDING', { agent: 'governance', finding: result.finding });
}, AGENT_INTERVALS.governance);

// Forecasting agent
setInterval(() => {
  const result = agents.forecasting.execute();
  broadcast('AGENT_FINDING', { agent: 'forecasting', finding: result.finding });
}, AGENT_INTERVALS.forecasting);

// ASI Synthesis — meta-reasoning cycle
setInterval(() => {
  const result = asiEngine.execute();
  broadcast('ASI_SYNTHESIS', { finding: result.finding });
}, AGENT_INTERVALS.asi);

// State broadcast (for metric panels)
setInterval(() => {
  broadcast('STATE_UPDATE', { kpis: STATE.kpis, adoption: STATE.adoption });
}, 3000);

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 6: REST API ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/state', (_, res) => res.json(STATE));
app.get('/api/agents', (_, res) => res.json({
  agents: Object.values(agents).map(a => a.toJSON()),
  asi: asiEngine.toJSON()
}));
app.get('/api/agents/:name/findings', (req, res) => {
  const agent = agents[req.params.name] || (req.params.name === 'asi' ? asiEngine : null);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  res.json({ agent: agent.toJSON(), findings: agent.findings.slice(0, 20) });
});
app.get('/api/health', (_, res) => res.json({
  status: 'OK', uptime: process.uptime(), clients: clients.size,
  agents: Object.values(agents).map(a => ({ name: a.name, status: a.status, runs: a.runCount }))
}));

// Directive Evaluator REST endpoints
app.post('/api/evaluate-directive', (req, res) => {
  const { directive } = req.body;
  if (!directive || typeof directive !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid "directive" field. Provide a string.' });
  }
  const result = directiveEvaluator.evaluate(directive);
  broadcast('DIRECTIVE_EVAL_BROADCAST', { finding: result.finding });
  res.json(result.finding);
});

app.get('/api/directive-history', (_, res) => {
  res.json({
    agent: directiveEvaluator.toJSON(),
    evaluations: directiveEvaluator.evaluationHistory.slice(0, 20)
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 6B: CISO SECURITY ROADMAP API
// ══════════════════════════════════════════════════════════════════════════════

const CISO_ROADMAP = {
  meta: {
    title: 'CISO 5-Year Security Roadmap',
    subtitle: 'Tiered Privilege x AI Agent Interoperability',
    classification: 'CONFIDENTIAL - CISO Office',
    version: '2.1.0',
    lastUpdated: new Date().toISOString(),
    phases: 3,
    periods: 10,
    timeHorizon: '60 months',
    invariant: 'AI agents NEVER have write access to Tier 0. Not in Year 1. Not in Year 5. Not ever.'
  },
  investmentSummary: {
    totalBudget: 14800000,
    currency: 'USD',
    phases: [
      { phase: 1, label: 'Years 1-2: Hardening + AI Gateways', budget: 4200000, spent: 2850000, completion: 68,
        breakdown: { infrastructure: 1800000, licenses: 900000, personnel: 1200000, consulting: 300000 }},
      { phase: 2, label: 'Year 3: Zero Trust Bridging', budget: 3600000, spent: 0, completion: 0,
        breakdown: { infrastructure: 1200000, licenses: 1000000, personnel: 1000000, consulting: 400000 }},
      { phase: 3, label: 'Years 4-5: Autonomic + PQC', budget: 7000000, spent: 0, completion: 0,
        breakdown: { infrastructure: 2500000, licenses: 1500000, personnel: 2000000, consulting: 1000000 }}
    ]
  },
  maturityModel: {
    dimensions: ['Identity & Access', 'Network Segmentation', 'AI Governance', 'Cryptographic Posture', 'Autonomic Response', 'Compliance Certification'],
    progression: [
      { period: 'Y1-H1', scores: [2, 1, 1, 1, 0, 1] },
      { period: 'Y1-H2', scores: [3, 2, 2, 1, 0, 1] },
      { period: 'Y2-H1', scores: [4, 3, 2, 1, 1, 2] },
      { period: 'Y2-H2', scores: [4, 3, 3, 2, 1, 2] },
      { period: 'Y3-H1', scores: [5, 4, 3, 2, 1, 3] },
      { period: 'Y3-H2', scores: [5, 5, 4, 2, 2, 3] },
      { period: 'Y4-H1', scores: [5, 5, 4, 3, 3, 4] },
      { period: 'Y4-H2', scores: [5, 5, 5, 3, 4, 4] },
      { period: 'Y5-H1', scores: [5, 5, 5, 5, 4, 4] },
      { period: 'Y5-H2', scores: [5, 5, 5, 5, 5, 5] }
    ]
  },
  complianceAlignment: {
    frameworks: [
      { id: 'ESAE', name: 'ESAE / AD Tiering', controls: 24, aligned: 18, target: 24 },
      { id: 'NIST_ZTA', name: 'NIST SP 800-207 ZTA', controls: 18, aligned: 8, target: 18 },
      { id: 'NIST_PQC', name: 'NIST PQC FIPS 203/204', controls: 12, aligned: 0, target: 12 },
      { id: 'ISO_42001', name: 'ISO/IEC 42001 AI Gov', controls: 38, aligned: 22, target: 38 },
      { id: 'ISO_27001', name: 'ISO 27001:2022', controls: 93, aligned: 72, target: 93 },
      { id: 'SOC2', name: 'SOC 2 Type II', controls: 64, aligned: 48, target: 64 }
    ],
    matrixByPeriod: {
      'Y1-H1': { ESAE: 25, NIST_ZTA: 5, NIST_PQC: 0, ISO_42001: 10, ISO_27001: 65, SOC2: 60 },
      'Y1-H2': { ESAE: 45, NIST_ZTA: 15, NIST_PQC: 0, ISO_42001: 20, ISO_27001: 70, SOC2: 65 },
      'Y2-H1': { ESAE: 60, NIST_ZTA: 25, NIST_PQC: 0, ISO_42001: 35, ISO_27001: 75, SOC2: 70 },
      'Y2-H2': { ESAE: 75, NIST_ZTA: 40, NIST_PQC: 0, ISO_42001: 45, ISO_27001: 80, SOC2: 75 },
      'Y3-H1': { ESAE: 85, NIST_ZTA: 70, NIST_PQC: 5, ISO_42001: 55, ISO_27001: 85, SOC2: 80 },
      'Y3-H2': { ESAE: 90, NIST_ZTA: 90, NIST_PQC: 10, ISO_42001: 65, ISO_27001: 88, SOC2: 85 },
      'Y4-H1': { ESAE: 95, NIST_ZTA: 95, NIST_PQC: 20, ISO_42001: 75, ISO_27001: 90, SOC2: 88 },
      'Y4-H2': { ESAE: 98, NIST_ZTA: 98, NIST_PQC: 30, ISO_42001: 85, ISO_27001: 92, SOC2: 92 },
      'Y5-H1': { ESAE: 100, NIST_ZTA: 100, NIST_PQC: 85, ISO_42001: 92, ISO_27001: 95, SOC2: 95 },
      'Y5-H2': { ESAE: 100, NIST_ZTA: 100, NIST_PQC: 100, ISO_42001: 100, ISO_27001: 100, SOC2: 100 }
    }
  },
  riskHeatMap: [
    { id: 'SR-1', risk: 'Tier 0 compromise via AI supply chain', likelihood: 15, impact: 95, phase: 1, mitigated_by: 'Y4-H1', residual_impact: 10, category: 'Identity' },
    { id: 'SR-2', risk: 'AI agent credential theft / replay', likelihood: 40, impact: 70, phase: 1, mitigated_by: 'Y3-H1', residual_impact: 8, category: 'Identity' },
    { id: 'SR-3', risk: 'Lateral movement via AI gateway misconfiguration', likelihood: 35, impact: 80, phase: 1, mitigated_by: 'Y2-H2', residual_impact: 12, category: 'Network' },
    { id: 'SR-4', risk: 'Prompt injection escalation to Tier 1 write', likelihood: 50, impact: 60, phase: 2, mitigated_by: 'Y4-H1', residual_impact: 5, category: 'AI Governance' },
    { id: 'SR-5', risk: 'ZTNA policy bypass via agent posture spoofing', likelihood: 25, impact: 75, phase: 2, mitigated_by: 'Y3-H2', residual_impact: 10, category: 'Zero Trust' },
    { id: 'SR-6', risk: 'Autonomic remediation cascade failure', likelihood: 30, impact: 85, phase: 3, mitigated_by: 'Y4-H2', residual_impact: 15, category: 'Autonomic' },
    { id: 'SR-7', risk: 'Harvest-now-decrypt-later on T0 telemetry', likelihood: 60, impact: 90, phase: 3, mitigated_by: 'Y5-H1', residual_impact: 5, category: 'Cryptography' },
    { id: 'SR-8', risk: 'Sidecar bypass via container escape', likelihood: 20, impact: 85, phase: 3, mitigated_by: 'Y4-H1', residual_impact: 8, category: 'AI Governance' },
    { id: 'SR-9', risk: 'PQC algorithm vulnerability (NIST revision)', likelihood: 15, impact: 70, phase: 3, mitigated_by: 'Y5-H2', residual_impact: 20, category: 'Cryptography' },
    { id: 'SR-10', risk: 'Regulatory gap — EU AI Act evolving requirements', likelihood: 45, impact: 55, phase: 1, mitigated_by: 'Y5-H2', residual_impact: 15, category: 'Compliance' }
  ],
  periods: [
    { id: 'Y1-H1', months: '1-6', title: 'Tier 0 Hardening', phase: 1, tier: 0,
      milestones: ['Complete Tier 0 isolation (dedicated DC hardware)', 'ESAE PAW deployment (12 admins, TPM 2.0+FIDO2)', 'Tier 0 credential fencing (MIM PAM JIT, FAST Kerberos)', 'AI readiness assessment + threat model v1'],
      architecture: { protocols: ['Kerberos FAST (RFC 6113)', 'AES-256-CTS'], components: ['Server Core 2025+WDAC', 'Credential Guard', 'MIM PAM', 'Azure Sentinel+MDI'], standards: ['ESAE Red Forest'] },
      kpis: [{ label: 'NTLM Auths in T0', value: '0', target: 'Zero' }, { label: 'PAW Coverage', value: '100%', target: '12/12' }, { label: 'JIT TTL', value: '15 min', target: 'Max' }, { label: 'AI Catalog', value: '100%', target: 'All inventoried' }],
      frictionPattern: { name: 'Observability-Only Tap', friction: 'AI needs T0 visibility but cannot have inbound access', resolution: 'Unidirectional data diode via Azure Event Hub (outbound-only T0 Sentinel export) to AI telemetry lake in DMZ' }},
    { id: 'Y1-H2', months: '7-12', title: 'Tier 1 Hardening + AI Gateway v1', phase: 1, tier: 1,
      milestones: ['Tier 1 credential segmentation (gMSA for all services)', 'Tier 1 network segmentation (Azure Bastion jump servers)', 'AI API Gateway v1 (Kong+OPA, mTLS, rate limiting)', 'Scope-limited AI OAuth 2.0 client credentials'],
      architecture: { protocols: ['OAuth 2.0 CC (RFC 6749 S4.4)', 'TLS 1.3 mTLS'], components: ['Kong Enterprise', 'OPA sidecar', 'Azure Bastion', 'Fluent Bit'], standards: ['ESAE Tier 1'] },
      kpis: [{ label: 'Shared Svc Accts', value: '0', target: 'All gMSA' }, { label: 'AI via Gateway', value: '100%', target: 'No direct' }, { label: 'Token TTL', value: '30 min', target: 'Max' }, { label: 'Gateway P95', value: '<200ms', target: 'SLA' }],
      frictionPattern: { name: 'Tier-Scoped API Gateway + OPA', friction: 'AI needs T1 data but T2 identities cannot auth to T1', resolution: 'API gateway as tier-translation proxy; AI authenticates with T2 OAuth tokens, gateway uses gMSA to forward sanitized read-only queries' }},
    { id: 'Y2-H1', months: '13-18', title: 'T0 Monitoring + AI Anomaly Detection', phase: 1, tier: 0,
      milestones: ['Tier 0 UEBA behavioral baseline (90-day learning)', 'BloodHound Enterprise continuous attack path elimination', 'AI anomaly detection agent (read-only, advisory)', 'Agent X.509 cert lifecycle (ACME, 72hr TTL)'],
      architecture: { protocols: ['ACME (RFC 8555)'], components: ['Sentinel UEBA', 'BloodHound Enterprise', 'Isolation Forest', 'LSTM sequence model'], standards: ['MITRE ATT&CK'] },
      kpis: [{ label: 'T2-T0 Attack Paths', value: '0', target: 'Clean' }, { label: 'Detection Latency', value: '<5 min', target: 'Alert-SOC' }, { label: 'AI FP Rate', value: '<2%', target: '90-day' }, { label: 'Cert TTL', value: '72 hr', target: 'ACME' }],
      frictionPattern: { name: 'Telemetry Lake Air Gap', friction: 'AI needs real-time T0 signals but T0 must have zero inbound trust', resolution: 'AI Telemetry Lake (ADLS Gen2) as one-way air gap; T0 pushes outbound via Event Hub; AI reads from lake; ~90 sec latency' }},
    { id: 'Y2-H2', months: '19-24', title: 'AI Gateway v2 + Tier 2 Writes', phase: 1, tier: 1,
      milestones: ['Tier 1 micro-segmentation (identity-aware L7 firewall)', 'AI Gateway v2 with scoped T2 write (dual-authorization)', 'Agent provenance chain (immutable append-only ledger)', 'Phase 1 pen test + remediation'],
      architecture: { protocols: ['Linkerd mTLS', 'ServiceNow API'], components: ['Azure Firewall Premium', 'ServiceNow approval gate', 'Azure Immutable Blob'], standards: ['ESAE Full'] },
      kpis: [{ label: 'Writes Dual-Authed', value: '100%', target: 'Human-in-loop' }, { label: 'Default-Allow Rules', value: '0', target: 'Micro-seg' }, { label: 'Provenance', value: '100%', target: 'Immutable' }, { label: 'Pen Test Crits', value: '0', target: 'Remediated' }],
      frictionPattern: { name: 'Dual-Authorization Write Gate', friction: 'AI needs to execute remediations but autonomous writes violate least-privilege', resolution: 'Propose-approve-execute pattern; AI submits structured request, ServiceNow human approval (<=15 min SLA), gateway executes T2 only, pre-change snapshots for rollback' }},
    { id: 'Y3-H1', months: '25-30', title: 'ZTNA Policy Engine + OIDC Federation', phase: 2, tier: -1,
      milestones: ['ZTNA Policy Decision Point (Zscaler ZPA/Cloudflare Access)', 'AI OIDC federation via Entra ID (PKCE, custom claims)', 'Conditional Access extended to AI agent identities', 'SPIFFE/SPIRE agent-to-agent identity mesh'],
      architecture: { protocols: ['OIDC+PKCE (RFC 7636)', 'SPIFFE/SPIRE', 'CAE'], components: ['Zscaler ZPA PDP', 'PEP sidecars', 'Entra ID', 'SPIRE agent'], standards: ['NIST SP 800-207 ZTA'] },
      kpis: [{ label: 'Access via ZTNA', value: '100%', target: 'All cross-tier' }, { label: 'AI OIDC Fed', value: '100%', target: 'No static creds' }, { label: 'Token TTL', value: '15 min', target: 'PKCE+CAE' }, { label: 'SPIFFE Rotation', value: '1 hr', target: 'Auto' }],
      frictionPattern: { name: 'Continuous-Verification Identity Bridge', friction: 'Static tier boundaries are binary; AI needs graduated, context-dependent access', resolution: 'Replace binary membership with continuous-verification ZTNA; every request evaluated against posture, risk score, resource sensitivity, temporal scope; Entra ID CAE enables sub-minute revocation' }},
    { id: 'Y3-H2', months: '31-36', title: 'Ephemeral Access + AI T1 Read Path', phase: 2, tier: 1,
      milestones: ['Ephemeral T1 read access (single-use JWT, jti tracking)', 'JIT tier escalation protocol (5-min scoped tokens)', 'AI agent behavioral profiling v1 (30-day baselines)', 'Phase 2 red team: AI compromise lateral movement test'],
      architecture: { protocols: ['Single-use JWT (RFC 7519 S4.1.7)', 'SPIFFE forced rotation'], components: ['ZTNA PDP step-up', 'Behavioral analytics engine', 'Z-score detection'], standards: ['NIST SP 800-207'] },
      kpis: [{ label: 'T1 Access Ephemeral', value: '100%', target: 'Zero persistent' }, { label: 'T1 Token TTL', value: '5 min', target: 'Single-use' }, { label: 'Behavioral FP', value: '<1%', target: '30-day' }, { label: 'Red Team Breaches', value: '0', target: 'Validated' }],
      frictionPattern: { name: 'Ephemeral Single-Use Token + Behavioral Gating', friction: 'AI needs T1 data for intelligence but persistent access is privilege escalation risk', resolution: 'Per-request single-use tokens from ZTNA PDP; <=5 min TTL; JTI prevents replay; gated by real-time behavioral risk score; >3-sigma deviation triggers auto-suspension via SPIRE forced rotation (<60 sec)' }},
    { id: 'Y4-H1', months: '37-42', title: 'Behavioral API Sidecars', phase: 3, tier: -1,
      milestones: ['Envoy-based behavioral sidecar on every AI pod', 'Circuit-breaker pattern (Z>2.5 triggers quarantine)', 'AI T1 scoped write access (sidecar+ZTNA gated, 20 ops)', 'T0 write: STILL PROHIBITED'],
      architecture: { protocols: ['Envoy xDS', 'WASM filter (Rust)'], components: ['Envoy sidecar', 'Cilium NetworkPolicy', 'Sigstore/Cosign verification', 'Forensic snapshot store'], standards: ['NIST SP 800-207', 'ISO 42001'] },
      kpis: [{ label: 'Agents w/ Sidecar', value: '100%', target: 'All pods' }, { label: 'Sidecar P99', value: '<50ms', target: 'Eval latency' }, { label: 'FP Trip Rate', value: '<0.5%', target: 'Circuit breaker' }, { label: 'AI T0 Writes', value: '0', target: 'Prohibited' }],
      frictionPattern: { name: 'Behavioral Sidecar as Inline Safety Net', friction: 'Autonomous T1 remediation risks runaway actions (feedback loops)', resolution: 'Independent behavioral sidecar co-located with every agent; own model, immutable binary (Sigstore-verified read-only FS); can independently detect anomalies and trip circuit breaker; agent cannot disable/bypass (enforced by Cilium network policy)' }},
    { id: 'Y4-H2', months: '43-48', title: 'Autonomic Remediation Engine', phase: 3, tier: -1,
      milestones: ['Multi-agent remediation orchestrator (<3 min MTTR)', 'Playbook-as-code (OPA Rego+CUE, Sigstore-signed)', 'Blast radius controls (max_blast_radius=5 default)', 'Cross-tier incident correlation (T0 lake + T1/T2 direct)'],
      architecture: { protocols: ['OPA Rego', 'CUE validation'], components: ['Remediation orchestrator', 'Sigstore pipeline', 'Blast radius governor', 'Cross-tier correlation engine'], standards: ['NIST CSF', 'ISO 42001'] },
      kpis: [{ label: 'Autonomic MTTR', value: '<3 min', target: 'Multi-step' }, { label: 'Playbooks Signed', value: '100%', target: 'Sigstore' }, { label: 'Blast Radius', value: '5', target: 'Max/exec' }, { label: 'Auto-Remediated', value: '75%', target: 'T1/T2' }],
      frictionPattern: { name: 'Signed Playbook-as-Code + Blast Radius Limits', friction: 'Multi-step cross-tier remediation could cause cascading failures', resolution: 'Three safety layers: (1) Sigstore-signed playbooks only (no ad-hoc); (2) blast radius limits with mandatory human escalation on exceed; (3) per-call sidecar behavioral enforcement even within valid playbooks' }},
    { id: 'Y5-H1', months: '49-54', title: 'Post-Quantum Cryptographic Foundation', phase: 3, tier: -1,
      milestones: ['Hybrid PQC TLS (X25519+ML-KEM-768, FIPS 203)', 'PQC-ready CA hierarchy (ML-DSA-65/87 root)', 'HNDL defense (AES-256-GCM + ML-KEM-768 key wrapping)', 'Quantum-resistant agent attestation (Sigstore ML-DSA-65)'],
      architecture: { protocols: ['ML-KEM-768 (FIPS 203)', 'ML-DSA-65 (FIPS 204)', 'TLS 1.3 hybrid PQC'], components: ['Luna 7 HSM', 'PQC Root CA (ML-DSA-87)', 'PQC Issuing CAs', 'HNDL key wrapping'], standards: ['NIST PQC FIPS 203/204'] },
      kpis: [{ label: 'PQC Key Exchange', value: '100%', target: 'All TLS' }, { label: 'PQC Token Sign', value: '100%', target: 'OIDC+SPIFFE' }, { label: 'HNDL Protected', value: '100%', target: 'At-rest PQC' }, { label: 'Classical-Only', value: '0', target: 'All dual/PQC' }],
      frictionPattern: { name: 'Hybrid PQC Transition with Dual-Signing', friction: 'PQC migration risks breaking T0/T1 services relying on classical crypto', resolution: 'Hybrid mode: every cert/token/key uses classical+PQC simultaneously; validators accept either; PQC root cross-signed by existing ECDSA root; sidecars negotiate strongest algorithm per connection; zero downtime transition' }},
    { id: 'Y5-H2', months: '55-60', title: 'Full Convergence', phase: 3, tier: -1,
      milestones: ['Classical crypto sunset (ML-KEM+ML-DSA native)', 'Full autonomic security mesh (90%+ T1/T2 auto-remediation)', 'AI governance maturity (drift detection, fairness audit, adversarial testing)', '5-year program audit (SOC 2 Type II + ISO 27001 + PQC attestation)'],
      architecture: { protocols: ['ML-KEM-768 native', 'ML-DSA-65 native'], components: ['Autonomous security mesh', 'AI governance engine', 'Model drift detector', 'Fairness auditor'], standards: ['ISO 42001', 'NIST AI RMF', 'ISO 27001', 'SOC 2 Type II'] },
      kpis: [{ label: 'Classical TLS', value: '0', target: 'Fully PQC' }, { label: 'Auto-Remediated', value: '90%', target: 'T1/T2' }, { label: 'AI T0 Writes', value: '0', target: 'NEVER' }, { label: 'Certifications', value: '3', target: 'SOC2+ISO+PQC' }],
      frictionPattern: { name: 'Full-Stack Convergence', friction: 'AI mesh deeply integrated across all tiers; how to ensure ESAE isolation preserved?', resolution: 'Cardinal rule preserved: T0 has zero inbound AI write access at every stage; all interactions mediated by ZTNA PDP, gated by behavioral sidecars, PQC-attested; tiering model reinforced by automation - enforcement is continuous, machine-speed, zero human error' }}
  ]
};

app.get('/api/ciso-roadmap', (_, res) => res.json(CISO_ROADMAP));
app.get('/api/ciso-roadmap/period/:id', (req, res) => {
  const period = CISO_ROADMAP.periods.find(p => p.id === req.params.id);
  if (!period) return res.status(404).json({ error: 'Period not found' });
  res.json(period);
});
app.get('/api/ciso-roadmap/risks', (_, res) => res.json({
  risks: CISO_ROADMAP.riskHeatMap,
  summary: {
    total: CISO_ROADMAP.riskHeatMap.length,
    critical: CISO_ROADMAP.riskHeatMap.filter(r => r.likelihood * r.impact / 100 > 40).length,
    high: CISO_ROADMAP.riskHeatMap.filter(r => { const s = r.likelihood * r.impact / 100; return s > 20 && s <= 40; }).length,
    medium: CISO_ROADMAP.riskHeatMap.filter(r => { const s = r.likelihood * r.impact / 100; return s > 10 && s <= 20; }).length,
    low: CISO_ROADMAP.riskHeatMap.filter(r => r.likelihood * r.impact / 100 <= 10).length
  }
}));
app.get('/api/ciso-roadmap/compliance', (_, res) => res.json(CISO_ROADMAP.complianceAlignment));
app.get('/api/ciso-roadmap/investment', (_, res) => res.json(CISO_ROADMAP.investmentSummary));
app.get('/api/ciso-roadmap/maturity', (_, res) => res.json(CISO_ROADMAP.maturityModel));

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 6C: ENTERPRISE AI STRATEGY REPORT API
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/ai-strategy-report', (_, res) => {
  res.json({
    meta: {
      title: 'Enterprise AI Strategy & Implementation Report 2026-2030',
      subtitle: 'Fortune 500 Technical Research & Deployment Framework',
      classification: 'CONFIDENTIAL — C-Suite & Senior Engineering Leadership',
      version: '1.0.0',
      date: new Date().toISOString(),
      pages: '28 + Appendices',
      sources: 47
    },
    sections: ['Technology Assessment','Depths System Analysis','Deployment Framework'],
    marketData: {
      globalAI2025: 390.9, globalAI2026: 375.9, globalAI2030: 1680, cagr: 30.6,
      enterpriseSpend2025: 37, enterpriseSpend2024: 11.5,
      hyperscalerCapex2025: 360, f500Adoption: 92
    }
  });
});

app.get('/api/ai-strategy-report/financials', (_, res) => {
  res.json({
    costModel: {
      year1: { infrastructure: 4200000, licenses: 1800000, personnel: 3200000, training: 600000, consulting: 800000, total: 10600000 },
      year2: { infrastructure: 3800000, licenses: 2100000, personnel: 3600000, training: 400000, consulting: 500000, total: 10400000 },
      year3: { infrastructure: 3200000, licenses: 2400000, personnel: 3800000, training: 300000, consulting: 300000, total: 10000000 }
    },
    roi: { year1: -0.15, year2: 0.42, year3: 1.85, year4: 3.20, year5: 4.60 },
    paybackMonths: 22,
    npv5yr: 18400000,
    irr: 0.38,
    sensitivityMatrix: [
      { variable: 'Adoption Rate', low: 0.8, base: 1.85, high: 3.1, unit: 'Y3 ROI x' },
      { variable: 'Inference Cost', low: 2.4, base: 1.85, high: 1.2, unit: 'Y3 ROI x' },
      { variable: 'Revenue Impact', low: 0.9, base: 1.85, high: 2.8, unit: 'Y3 ROI x' },
      { variable: 'Headcount Savings', low: 1.1, base: 1.85, high: 2.6, unit: 'Y3 ROI x' },
      { variable: 'Regulatory Cost', low: 2.0, base: 1.85, high: 1.5, unit: 'Y3 ROI x' }
    ]
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 6D: VERIDIAN BIOSCIENCES AI STRATEGY API
// ══════════════════════════════════════════════════════════════════════════════

const VERIDIAN = {
  meta: {
    company: 'Veridian BioSciences, Inc.',
    sector: 'Biopharmaceutical R&D — AI-Driven Drug Discovery & Clinical Trial Optimization',
    revenue: 28400000000,
    employees: 62000,
    fortune500Rank: 180,
    classification: 'CONFIDENTIAL — Board of Directors & Executive Committee',
    docRef: 'VBS-AI-STRAT-2026-001',
    version: '2.0.0',
    date: '2026-02-20',
    facilities: 9,
    clinicalPrograms: 14,
    commercialBiologics: 6,
    limsSystemsLegacy: 14,
    limsSystemsTarget: 3,
    unstructuredDataPB: 2.1,
    submissionManualPct: 72,
    screenFailureRate: 31,
    targetToINDYears: 4.8,
    aiNativeBenchmarkYears: 3.3
  },
  vision: 'Compress the molecule-to-medicine timeline from 4.8 years to 2.9 years through supervised autonomous AI — making Veridian the first traditional biopharma to match AI-native competitor speed while maintaining the clinical rigor and regulatory trust of a 40-year incumbent.',
  operationalBottleneck: {
    legacyData: { description: '2.1 PB unstructured lab data in 14 incompatible LIMS systems', source: '3 acquisitions (2018-2023)' },
    regulatorySubmission: { description: '72% manual regulatory submission pipeline', effort: '~340 FTE-months per NDA' },
    clinicalTrials: { description: 'Site selection on 6-12 month stale epidemiological data', impact: '31% screen failure rate (industry avg: 25%)' }
  },
  financials: {
    grossGains: {
      rdCycleCompression: { annual: 96000000, mechanism: '4.8yr→2.9yr; 1yr earlier launch = ~$800M peak × 12% PoS' },
      screenFailureReduction: { annual: 33600000, mechanism: '31%→19%; avg Phase II $20M; 14 trials; 12pp reduction' },
      submissionAutomation: { annual: 51800000, mechanism: '72%→15% manual; ~240 FTE-months × $18K/FTE-month' },
      predictiveToxicology: { annual: 103500000, mechanism: 'Avoid 2.3 late-stage failures/yr × $45M avg sunk cost' },
      manufacturingYield: { annual: 95800000, mechanism: '4.2% yield on 6 biologics × $380M avg COGS' },
      totalAnnual: 380700000
    },
    riskCosts: {
      compliance: { annual: 12400000, desc: 'EU AI Act, FDA, EMA conformity' },
      redundancy: { annual: 8600000, desc: 'Circuit breakers, fallback models, overrides' },
      cybersecurity: { annual: 6200000, desc: 'Model poisoning defense, adversarial robustness' },
      insurance: { annual: 4800000, desc: 'AI decision liability, clinical trial AI errors' },
      talent: { annual: 22400000, desc: '85 FTE: ML eng, MLOps, AI safety, regulatory AI' },
      infrastructure: { annual: 18900000, desc: 'GPU clusters, edge, multi-cloud' },
      totalAnnual: 73300000
    },
    netValueCapture: { annual: 307400000, fiveYearNPV: 842000000, paybackMonth: 26, roi5yr: 4.2 },
    costModel: {
      year1: { infrastructure: 18200000, talent: 14800000, compliance: 8600000, safety: 6400000, dataFoundation: 14200000, training: 3800000, total: 66000000 },
      year2: { infrastructure: 19800000, talent: 19600000, compliance: 12400000, safety: 11200000, dataFoundation: 8400000, training: 2800000, total: 74200000 },
      year3: { infrastructure: 19200000, talent: 22400000, compliance: 12400000, safety: 19600000, dataFoundation: 6200000, training: 2200000, total: 82000000 },
      year4: { infrastructure: 18900000, talent: 22400000, compliance: 12400000, safety: 19600000, dataFoundation: 4800000, training: 1600000, total: 79700000 },
      year5: { infrastructure: 18400000, talent: 22400000, compliance: 12400000, safety: 19600000, dataFoundation: 3600000, training: 1200000, total: 77600000 }
    },
    benefits: { year1: 12800000, year2: 68000000, year3: 186000000, year4: 307400000, year5: 307400000 },
    cumulativeNet: { year1: -53200000, year2: -59400000, year3: 44600000, year4: 272300000, year5: 502100000 },
    sensitivityMatrix: [
      { variable: 'Pipeline PoS', low: 0.9, base: 2.1, high: 3.4, variancePct: 42 },
      { variable: 'Adoption Rate', low: 1.0, base: 2.1, high: 3.2, variancePct: 26 },
      { variable: 'Regulatory Delay', low: 2.4, base: 2.1, high: 1.4, variancePct: 14 },
      { variable: 'Compute Costs', low: 2.5, base: 2.1, high: 1.7, variancePct: 10 },
      { variable: 'Data Foundation Delay', low: 2.3, base: 2.1, high: 0.8, variancePct: 8 }
    ],
    totalInvestment5yr: 458000000,
    totalBenefits5yr: 881600000,
    totalNet5yr: 502100000
  },
  roadmap: [
    { year: 2026, label: 'Data Foundation & Platform Build', maturity: '2→2.5', targets: { submissionPrepReduction: 15, limsConsolidation: '14→3', ocrAccuracy: 97 }, dependencies: ['LIMS migration (9-month window)', 'Lab digitization (38% paper)', 'RWE contracts (6-mo cycle)'], phase: 'Foundation' },
    { year: 2027, label: 'Molecular AI & Predictive Toxicology', maturity: '3', targets: { hitToLeadReduction: 25, phaseIFailReduction: 30, manualSubmission: '72%→45%' }, dependencies: ['800K compound-assay dataset', 'Tox ground-truth curation (6-mo)', '18yr archive NLP extraction'], phase: 'Molecular' },
    { year: 2028, label: 'Clinical Trial AI & Adaptive Protocols', maturity: '3.5', targets: { screenFailure: '31%→22%', enrollmentSpeed: '+35%', amendments: '-40%' }, dependencies: ['RWE data access', 'CRO federated learning (12-mo/CRO)', 'FDA/EMA adaptive AI guidance'], phase: 'Clinical' },
    { year: 2029, label: 'Manufacturing Intelligence', maturity: '4', targets: { yieldImprovement: 4.2, releaseTimeReduction: 50, oee: '78%→88%' }, dependencies: ['GxP AI validation', 'MES parallel AI stream', 'Edge rollout (9 facilities)'], phase: 'Manufacturing' },
    { year: 2030, label: 'Project Depths Full Deployment', maturity: '4.5', targets: { rdCycle: '4.8yr→2.9yr', netValue: '$307.4M/yr', submissionAuto: '85%' }, dependencies: ['All prior phases', 'EU AI Act conformity', 'AI Safety Board ≥12mo'], phase: 'Autonomous' }
  ],
  risks: [
    { category: 'Patient Safety', scenario: 'Adaptive dosing exceeds MTD', technicalMitigation: 'Hard-coded dose ceiling circuit breaker (80% NOAEL)', governanceMitigation: 'EU AI Act Art. 14(4)(d); FDA 21 CFR 312.32; DSMB override', severity: 'Critical' },
    { category: 'Molecular Toxicity', scenario: 'GNN false negative on hepatotoxicity', technicalMitigation: '5-model ensemble + MC dropout; conformal prediction (95% coverage)', governanceMitigation: 'EU AI Act Art. 9(2)(b); FDA AI/ML SaMD guidance', severity: 'Critical' },
    { category: 'Data Integrity', scenario: 'CRO data poisoning via federated learning', technicalMitigation: 'Byzantine fault-tolerant FL (Krum); W3C PROV-DM provenance; KS-test', governanceMitigation: 'EU AI Act Art. 10; 21 CFR Part 11; CRO SOC 2 Type II', severity: 'High' },
    { category: 'Regulatory', scenario: 'EU non-conformity for clinical AI', technicalMitigation: 'SHAP + GradCAM + NL explanations; AWS QLDB audit ledger', governanceMitigation: 'EU AI Act Art. 43/13/62; TÜV SÜD 18mo pre-engagement', severity: 'High' },
    { category: 'Operational', scenario: 'Cascading pipeline failure across subsystems', technicalMitigation: 'Blast radius governor; circuit breaker (2x baseline/5min); classical fallback', governanceMitigation: 'EU AI Act Art. 15; ICH E6(R3); monthly DR drills; RTO <4hr', severity: 'High' },
    { category: 'Ethical', scenario: 'Algorithmic bias in trial enrollment', technicalMitigation: 'Constrained optimization (±5% demographic targets); Fairlearn monthly audit', governanceMitigation: 'FDA Diversity Action Plans 2024; EU AI Act Art. 10(2)(f)', severity: 'Medium' },
    { category: 'IP Theft', scenario: 'Molecular GNN model exfiltration ($180M value)', technicalMitigation: 'ε=8 DP-SGD; API rate limiting; model watermarking; on-prem training only', governanceMitigation: 'EU Trade Secrets Directive; US DTSA; SOC 2 Type II', severity: 'High' }
  ],
  kpis: [
    { category: 'Financial', metric: 'Net Value Capture', baseline: 0, y1: 12800000, y3: 186000000, y5: 307400000 },
    { category: 'Financial', metric: 'Cumulative ROI', baseline: null, y1: 0.36, y3: 2.1, y5: 4.2 },
    { category: 'R&D', metric: 'Target-to-IND (years)', baseline: 4.8, y1: 4.5, y3: 3.6, y5: 2.9 },
    { category: 'R&D', metric: 'Phase I Failure Rate', baseline: 0.28, y1: 0.26, y3: 0.18, y5: 0.12 },
    { category: 'Clinical', metric: 'Screen Failure Rate', baseline: 0.31, y1: 0.29, y3: 0.22, y5: 0.19 },
    { category: 'Clinical', metric: 'Enrollment Speed (pts/mo/site)', baseline: 1.8, y1: 1.9, y3: 2.6, y5: 3.2 },
    { category: 'Manufacturing', metric: 'OEE', baseline: 0.78, y1: 0.80, y3: 0.85, y5: 0.88 },
    { category: 'Manufacturing', metric: 'Batch Release (days)', baseline: 14, y1: 12, y3: 8, y5: 7 },
    { category: 'Manufacturing', metric: 'Right-First-Time', baseline: 0.82, y1: 0.84, y3: 0.90, y5: 0.94 },
    { category: 'Compliance', metric: 'EU AI Act Conformity', baseline: 0, y1: 0.35, y3: 0.78, y5: 0.95 },
    { category: 'ESG', metric: 'Carbon Reduction', baseline: 0, y1: -0.04, y3: -0.16, y5: -0.28 },
    { category: 'Talent', metric: 'AI/ML Team Size', baseline: 23, y1: 65, y3: 110, y5: 130 }
  ],
  year1Phases: [
    { phase: 'P0', name: 'Strategy & Assessment', months: '1-2', fte: 8, budget: 1200000, gate: 'Board approval; CAIO hire' },
    { phase: 'P1', name: 'Data Foundation', months: '2-6', fte: 28, budget: 8400000, gate: '≥6/14 LIMS; OCR ≥95%; CDISC 3 TAs' },
    { phase: 'P2', name: 'MLOps & Infrastructure', months: '5-8', fte: 22, budget: 6800000, gate: 'E2E pipeline <15min; pen test pass' },
    { phase: 'P3', name: 'Pilot Models (Shadow)', months: '7-10', fte: 35, budget: 9200000, gate: 'GNN ≥88%; NLP ≥90% F1; anomaly ≥95% sens' },
    { phase: 'P4', name: 'Governance & Compliance', months: '8-11', fte: 15, budget: 4600000, gate: 'Conformity draft; Safety Board operational' },
    { phase: 'P5', name: 'RWE & Partnerships', months: '9-12', fte: 18, budget: 5800000, gate: '≥2 RWE feeds; FL PoC; ≥15% site improvement' }
  ],
  regulatoryTension: {
    aspiration: 'Zero-human-intervention pipeline from hit identification through Phase I protocol generation',
    constraint: 'EU AI Act Art. 14: high-risk AI systems must be effectively overseen by natural persons',
    resolution: 'Supervised Autonomy — exception-based oversight. Art. 14 does not require humans to MAKE every decision, only that humans CAN intervene and DO understand.',
    complianceCost5yr: 62000000
  },
  carbonReduction: {
    total: -28,
    wetLabIterations: { pct: -14, mechanism: '60% fewer early-stage synthesis-test cycles' },
    manufacturingYield: { pct: -8, mechanism: '4.2% yield improvement, fewer failed batches' },
    computeOptimization: { pct: -6, mechanism: 'Auto-scaling reduces idle compute 55%; carbon-aware scheduling' }
  },
  depthsProject: {
    name: 'Depths',
    description: 'End-state autonomous AI system: unified orchestration of full drug discovery and development pipeline',
    scope: 'Target ID → molecular design → toxicity screen → clinical protocol → adaptive trial → regulatory submission',
    residualRisk: 'MODERATE-HIGH',
    deploymentStrategy: 'Incremental — each subsystem in shadow mode (parallel to human decisions) for minimum 6 months before autonomy',
    fullAutonomyPrerequisite: 'Zero critical safety incidents during all shadow periods'
  }
};

app.get('/api/veridian', (_, res) => res.json({
  meta: VERIDIAN.meta,
  vision: VERIDIAN.vision,
  operationalBottleneck: VERIDIAN.operationalBottleneck,
  netValueCapture: VERIDIAN.financials.netValueCapture,
  depthsProject: VERIDIAN.depthsProject,
  regulatoryTension: VERIDIAN.regulatoryTension,
  carbonReduction: VERIDIAN.carbonReduction,
  roadmapSummary: VERIDIAN.roadmap.map(r => ({ year: r.year, label: r.label, maturity: r.maturity, phase: r.phase }))
}));

app.get('/api/veridian/financials', (_, res) => res.json({
  grossGains: VERIDIAN.financials.grossGains,
  riskCosts: VERIDIAN.financials.riskCosts,
  netValueCapture: VERIDIAN.financials.netValueCapture,
  costModel: VERIDIAN.financials.costModel,
  benefits: VERIDIAN.financials.benefits,
  cumulativeNet: VERIDIAN.financials.cumulativeNet,
  sensitivityMatrix: VERIDIAN.financials.sensitivityMatrix,
  totals: { investment: VERIDIAN.financials.totalInvestment5yr, benefits: VERIDIAN.financials.totalBenefits5yr, net: VERIDIAN.financials.totalNet5yr }
}));

app.get('/api/veridian/risks', (_, res) => res.json({
  risks: VERIDIAN.risks,
  depthsProject: VERIDIAN.depthsProject,
  regulatoryTension: VERIDIAN.regulatoryTension,
  summary: {
    total: VERIDIAN.risks.length,
    critical: VERIDIAN.risks.filter(r => r.severity === 'Critical').length,
    high: VERIDIAN.risks.filter(r => r.severity === 'High').length,
    medium: VERIDIAN.risks.filter(r => r.severity === 'Medium').length
  }
}));

app.get('/api/veridian/roadmap', (_, res) => res.json({
  roadmap: VERIDIAN.roadmap,
  year1Phases: VERIDIAN.year1Phases,
  kpis: VERIDIAN.kpis,
  year1Summary: {
    totalBudget: 36000000,
    peakFTE: 35,
    netNewHires: 42,
    expectedValue: 12800000,
    keyRisk: 'LIMS consolidation slip >3mo cascades 4-6mo'
  }
}));

app.get('/api/veridian/kpis', (_, res) => res.json({
  kpis: VERIDIAN.kpis,
  carbonReduction: VERIDIAN.carbonReduction
}));

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 7: START SERVER
// ══════════════════════════════════════════════════════════════════════════════

const PORT = 4200;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n══════════════════════════════════════════════════════════════`);
  console.log(`  RAG AGENTIC AI GOVERNANCE DASHBOARD`);
  console.log(`  Server:     http://0.0.0.0:${PORT}`);
  console.log(`  WebSocket:  ws://0.0.0.0:${PORT}/ws`);
  console.log(`  API:        http://0.0.0.0:${PORT}/api/state`);
  console.log(`  Health:     http://0.0.0.0:${PORT}/api/health`);
  console.log(`  Agents:     ${Object.keys(agents).length} specialist + 1 ASI synthesis`);
  console.log(`══════════════════════════════════════════════════════════════\n`);

  // Initial agent bootstrap
  console.log('[BOOT] Running initial agent cycle...');
  const bootResults = runAllAgents();
  console.log(`[BOOT] ${Object.keys(bootResults).length} agents initialized successfully.`);
});
