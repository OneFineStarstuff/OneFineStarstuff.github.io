import type { AlertRecord, RiskMetric, SourceStatus } from "../types/governance";

export type MetricAssessment = "NOT ASSESSED" | "BREACH" | "WITHIN THRESHOLD";

export function assessMetric(metric: RiskMetric): MetricAssessment {
  const trustworthySource: SourceStatus[] = ["LIVE", "EXTERNAL_ATTESTED"];
  if (!trustworthySource.includes(metric.sourceStatus) || metric.threshold === undefined) {
    return "NOT ASSESSED";
  }

  const breach = metric.thresholdDirection === "MAXIMUM"
    ? metric.value > metric.threshold
    : metric.value < metric.threshold;

  return breach ? "BREACH" : "WITHIN THRESHOLD";
}

export function formatMetricValue(metric: RiskMetric): string {
  if (metric.unit === "probability") return metric.value.toExponential(2);
  return metric.value.toFixed(3);
}

export function escapeCsvCell(input: unknown): string {
  const value = String(input ?? "");
  const normalized = value.replace(/^[\s\uFEFF]+/, "");
  const safeValue = /^[=+@\-\t\r]/.test(normalized) ? `'${value}` : value;
  return `"${safeValue.replace(/"/g, '""')}"`;
}

export function alertsToCsv(alerts: AlertRecord[]): string {
  const headers = ["id", "title", "severity", "state", "occurredAt", "owner", "sourceStatus", "evidenceRef"];
  const rows = alerts.map(alert => headers.map(key => escapeCsvCell(alert[key as keyof AlertRecord])).join(","));
  return [headers.join(","), ...rows].join("\r\n");
}

export function alertsToJson(alerts: AlertRecord[]): string {
  return JSON.stringify({
    schemaVersion: "1.0",
    exportType: "DEMONSTRATION_DATA",
    exportedAt: new Date().toISOString(),
    count: alerts.length,
    records: alerts
  }, null, 2);
}
