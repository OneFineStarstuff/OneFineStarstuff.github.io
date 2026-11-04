/**
 * Route and payload types derived from api/openapi.json (schema of record).
 *
 * Schema-first rule (WP-087 control C1): this file mirrors the OpenAPI 3.1
 * components. Structural changes are classified by the drift gate
 * (src/drift-gate.mjs) against api/snapshots/openapi.baseline.json. The spec
 * is the single source of truth; hand-edits here must follow an approved
 * spec change, never precede one.
 *
 * Fictional governance-simulation artefact: all data is simulated.
 */

export type HealthStatus = {
  status: 'ok';
  service?: string;
  simulation: boolean;
  uptimeSeconds?: number;
};

export type SupervisoryWindowTelemetry = {
  s_sys: number;
  g_sri: number;
  c_sri: number;
  g_sri_vii: number;
  a_sri: number;
  p_sri: number;
  cgr_i: number;
  ccr_i: number;
  p_doom: number;
  p_doom_kernel: number;
  delta_drift: number;
  delta_oscal: number;
};

export type SupervisoryWindowEvidence = {
  merkleRoot: string;
  artefactsSealed?: number;
};

export type SupervisoryWindow = {
  windowId: string;
  windowCloseUtc: string;
  simulation: boolean;
  telemetry: SupervisoryWindowTelemetry;
  evidence?: SupervisoryWindowEvidence;
};

export type ComplianceRegime = {
  framework: string;
  result: 'PASS' | 'FAIL';
};

export type ComplianceSummary = {
  catalogRevision: number;
  simulation?: boolean;
  regimes: ComplianceRegime[];
};

export type IncidentRecord = {
  incidentId: string;
  openedUtc: string;
  classification: string;
  status: 'open' | 'contained' | 'closed';
  wormSealed?: boolean;
};
