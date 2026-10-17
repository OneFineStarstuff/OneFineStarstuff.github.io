import { describe, expect, it } from "vitest";
import {
  alertsToCsv,
  alertsToJson,
  assessMetric,
  escapeCsvCell
} from "./telemetry";
import type { AlertRecord, RiskMetric } from "../types/governance";

function metric(overrides: Partial<RiskMetric> = {}): RiskMetric {
  return {
    id: "S_sys",
    name: "Systemic risk",
    value: 0.2,
    unit: "index",
    threshold: 0.35,
    thresholdDirection: "MAXIMUM",
    sourceStatus: "SYNTHETIC",
    sourceRef: "DEMO-001",
    observedAt: "2026-10-17T08:00:00Z",
    methodVersion: "demo-v1",
    limitation: "Synthetic test fixture.",
    ...overrides
  };
}

const alert: AlertRecord = {
  id: "DEMO-ALERT-1",
  title: "Evidence pending",
  severity: "HIGH",
  state: "OPEN",
  occurredAt: "2026-10-17T08:00:00Z",
  owner: "AI Risk",
  sourceStatus: "SYNTHETIC",
  evidenceRef: "DEMO-EVD-1"
};

describe("assessMetric", () => {
  it("does not treat synthetic values as a live risk verdict", () => {
    expect(assessMetric(metric({ value: 0.1, sourceStatus: "SYNTHETIC" }))).toBe("NOT ASSESSED");
  });

  it("assesses a live value within a maximum threshold", () => {
    expect(assessMetric(metric({ value: 0.2, sourceStatus: "LIVE" }))).toBe("WITHIN THRESHOLD");
  });

  it("flags a live value above a maximum threshold", () => {
    expect(assessMetric(metric({ value: 0.4, sourceStatus: "LIVE" }))).toBe("BREACH");
  });

  it("supports a verified external source for a minimum threshold", () => {
    expect(assessMetric(metric({
      id: "availability",
      value: 0.95,
      threshold: 0.9,
      thresholdDirection: "MINIMUM",
      sourceStatus: "EXTERNAL_ATTESTED"
    }))).toBe("WITHIN THRESHOLD");
  });

  it("does not assess a metric without a threshold", () => {
    expect(assessMetric(metric({ threshold: undefined, sourceStatus: "LIVE" }))).toBe("NOT ASSESSED");
  });
});

describe("CSV safety", () => {
  it.each(["=cmd()", "+SUM(A1:A2)", "-1+1", "@SUM(A1:A2)", "\t=cmd()", "\r=cmd()"])(
    "neutralizes formula-leading input %s",
    value => {
      expect(escapeCsvCell(value)).toContain("'");
    }
  );

  it("escapes embedded quotes and encloses values in quotes", () => {
    expect(escapeCsvCell('A "quoted" value')).toBe('"A ""quoted"" value"');
  });

  it("exports alert rows with formula protection", () => {
    const malicious = { ...alert, title: "=HYPERLINK(\"https://example.invalid\")" };
    const csv = alertsToCsv([malicious]);
    expect(csv).toContain('"'=HYPERLINK(""https://example.invalid"")"');
    expect(csv.split("\r\n")).toHaveLength(2);
  });
});

describe("JSON export contract", () => {
  it("labels the export as demonstration data and includes a count", () => {
    const parsed = JSON.parse(alertsToJson([alert])) as {
      schemaVersion: string;
      exportType: string;
      count: number;
      records: AlertRecord[];
    };
    expect(parsed.schemaVersion).toBe("1.0");
    expect(parsed.exportType).toBe("DEMONSTRATION_DATA");
    expect(parsed.count).toBe(1);
    expect(parsed.records[0].sourceStatus).toBe("SYNTHETIC");
  });
});
