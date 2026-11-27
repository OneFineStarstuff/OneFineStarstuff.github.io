import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { evaluateRelease, type ReleaseEvaluationInput } from "./domain/release.ts";
import { classifyChange, type ChangeSignals } from "./domain/change.ts";

const HOST = process.env.HOST ?? "127.0.0.1";
const PORT = Number(process.env.PORT ?? "8080");
const MAX_BODY_BYTES = 64 * 1024;

async function readJson(request: any): Promise<unknown> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = typeof chunk === "string" ? new TextEncoder().encode(chunk) : new Uint8Array(chunk);
    total += bytes.byteLength;
    if (total > MAX_BODY_BYTES) throw new Error("BODY_TOO_LARGE");
    chunks.push(bytes);
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder().decode(joined));
}
function isRecord(value: unknown): value is Record<string, any> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function hasExactKeys(value: Record<string, any>, required: string[], optional: string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}
function isReleaseInput(value: unknown): value is ReleaseEvaluationInput {
  if (!isRecord(value)) return false;
  if (!hasExactKeys(value, ["releaseId", "imageDigest", "schema", "contracts", "build", "signature", "sbom", "vulnerabilityScan", "admission", "freeze", "change"], ["breakGlass"])) return false;
  const groups = ["schema", "contracts", "build", "signature", "sbom", "vulnerabilityScan", "admission", "freeze", "change"];
  if (typeof value.releaseId !== "string" || value.releaseId.length < 1 || value.releaseId.length > 128) return false;
  if (typeof value.imageDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value.imageDigest)) return false;
  if (!groups.every((key) => isRecord(value[key]))) return false;
  if (!hasExactKeys(value.schema, ["compatible"]) || !hasExactKeys(value.contracts, ["productionCompatible"])) return false;
  if (!hasExactKeys(value.build, ["provenanceVerified", "slsaLevel", "subjectDigest", "sourceRevision", "expectedSourceRevision", "builderId", "expectedBuilderId"])) return false;
  if (!hasExactKeys(value.signature, ["verified", "signer", "expectedSigner", "subjectDigest"])) return false;
  if (!hasExactKeys(value.sbom, ["policyPassed", "subjectDigest"])) return false;
  if (!hasExactKeys(value.vulnerabilityScan, ["policyPassed", "subjectDigest", "reportSha256"])) return false;
  if (!hasExactKeys(value.admission, ["policyEnforced", "decision"])) return false;
  if (!hasExactKeys(value.freeze, ["active", "exceptionApproved"], ["exceptionId", "exceptionScope", "exceptionExpiresAt"])) return false;
  if (!hasExactKeys(value.change, ["classification", "approved", "riskApprovals"])) return false;
  if (typeof value.schema.compatible !== "boolean" || typeof value.contracts.productionCompatible !== "boolean") return false;
  if (typeof value.build.provenanceVerified !== "boolean" || !Number.isInteger(value.build.slsaLevel) || typeof value.build.subjectDigest !== "string" || typeof value.build.sourceRevision !== "string" || typeof value.build.expectedSourceRevision !== "string" || typeof value.build.builderId !== "string" || typeof value.build.expectedBuilderId !== "string") return false;
  if (typeof value.signature.verified !== "boolean" || typeof value.signature.signer !== "string" || typeof value.signature.expectedSigner !== "string" || typeof value.signature.subjectDigest !== "string") return false;
  if (typeof value.sbom.policyPassed !== "boolean" || typeof value.sbom.subjectDigest !== "string") return false;
  if (typeof value.vulnerabilityScan.policyPassed !== "boolean" || typeof value.vulnerabilityScan.subjectDigest !== "string" || !/^[a-f0-9]{64}$/.test(value.vulnerabilityScan.reportSha256)) return false;
  if (typeof value.admission.policyEnforced !== "boolean" || !["ALLOW", "DENY"].includes(value.admission.decision)) return false;
  if (typeof value.freeze.active !== "boolean" || typeof value.freeze.exceptionApproved !== "boolean") return false;
  if (value.freeze.exceptionApproved && (typeof value.freeze.exceptionId !== "string" || typeof value.freeze.exceptionScope !== "string" || typeof value.freeze.exceptionExpiresAt !== "string")) return false;
  if (!Number.isInteger(value.change.classification) || value.change.classification < 0 || value.change.classification > 3 || typeof value.change.approved !== "boolean" || !Number.isInteger(value.change.riskApprovals) || value.change.riskApprovals < 0) return false;
  if (value.breakGlass !== undefined) {
    const bg = value.breakGlass;
    if (!isRecord(bg) || !hasExactKeys(bg, ["incidentId", "requestedBy", "approvers", "expiresAt", "scope", "authorized"])) return false;
    if (typeof bg.incidentId !== "string" || typeof bg.requestedBy !== "string" || typeof bg.expiresAt !== "string" || typeof bg.scope !== "string" || typeof bg.authorized !== "boolean" || !Array.isArray(bg.approvers)) return false;
    if (!bg.approvers.every((a: unknown) => isRecord(a) && hasExactKeys(a, ["id", "role"]) && typeof a.id === "string" && typeof a.role === "string")) return false;
  }
  return true;
}
function send(response: any, status: number, payload: unknown, requestId: string): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "x-request-id": requestId });
  response.end(JSON.stringify(payload));
}
const server = createServer(async (request: any, response: any) => {
  const requestId = randomUUID();
  const method = request.method ?? "GET";
  const pathname = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`).pathname;
  try {
    if (method === "GET" && pathname === "/healthz") { send(response, 200, { status: "ok", requestId }, requestId); return; }
    if (method === "GET" && pathname === "/readyz") { send(response, 200, { status: "ready", externalDependenciesChecked: false, requestId }, requestId); return; }
    if (method === "POST" && pathname === "/v1/changes/classify") {
      const body = await readJson(request);
      const allowedSignals = ["changesPurpose", "changesModel", "changesDataProcessing", "changesSecurityBoundary", "changesCriticalSafetyControl", "operationalImpact"];
      if (!isRecord(body) || Object.keys(body).some((key) => !allowedSignals.includes(key)) || Object.values(body).some((value) => typeof value !== "boolean")) { send(response, 400, { error: "INVALID_INPUT", requestId }, requestId); return; }
      send(response, 200, { requestId, ...classifyChange(body as ChangeSignals) }, requestId); return;
    }
    if (method === "POST" && pathname === "/v1/release/evaluate") {
      const body = await readJson(request);
      if (!isReleaseInput(body)) { send(response, 400, { error: "INVALID_INPUT", requestId }, requestId); return; }
      send(response, 200, { requestId, ...evaluateRelease(body) }, requestId); return;
    }
    send(response, 404, { error: "NOT_FOUND", requestId }, requestId);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    const status = message === "BODY_TOO_LARGE" ? 413 : 400;
    send(response, status, { error: status === 413 ? "BODY_TOO_LARGE" : "INVALID_JSON", requestId }, requestId);
  } finally { console.log(JSON.stringify({ requestId, method, path: pathname, at: new Date().toISOString() })); }
});
server.on("error", (error: Error) => { console.error(JSON.stringify({ level: "error", message: error.message })); process.exit(1); });
server.listen(PORT, HOST, () => console.log(JSON.stringify({ level: "info", message: "GIEN reference API listening", host: HOST, port: PORT })));
