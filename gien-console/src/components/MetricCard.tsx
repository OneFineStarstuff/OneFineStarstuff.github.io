import { ArrowDownRight, ArrowUpRight, ShieldAlert } from "lucide-react";
import { assessMetric, formatMetricValue } from "../lib/telemetry";
import type { RiskMetric } from "../types/governance";

/** Render a risk metric with assessment and explicit synthetic provenance. */
export function MetricCard({ metric, index = 0 }: { metric: RiskMetric; index?: number }) {
  const assessment = assessMetric(metric);
  return (
    <article className="metric-card" style={{ animationDelay: `${index * 45}ms` }}>
      <div className="metric-card-head">
        <span className="metric-label">{metric.name}</span>
        <span className="metric-id">{metric.id}</span>
      </div>
      <div className="metric-value-row">
        <strong className="metric-value">{formatMetricValue(metric)}</strong>
        <span className="metric-unit">{metric.unit}</span>
      </div>
      <div className="metric-card-foot">
        <span className={`assessment-chip assessment-${assessment === "NOT ASSESSED" ? "pending" : assessment === "BREACH" ? "breach" : "ok"}`}>
          {assessment === "NOT ASSESSED" ? <ShieldAlert size={13} /> : assessment === "BREACH" ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />}
          {assessment}
        </span>
        <span className="threshold-copy">
          Threshold {metric.thresholdDirection === "MAXIMUM" ? "≤" : "≥"} {metric.threshold}
        </span>
      </div>
      <div className="metric-evidence">
        <span className="source-dot source-dot-synthetic" />
        SYNTHETIC · {metric.sourceRef}
      </div>
    </article>
  );
}
