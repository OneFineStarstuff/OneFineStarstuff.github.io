/**
 * GIEN Governance Telemetry API server (zero runtime dependencies).
 *
 * WP-089 — executes WP-087 rollout phase P1 (schema-first development).
 * Route and payload shapes come from api/openapi.json via src/types.ts.
 * Data is seeded from the GIEN-DOSSIER-2026-308 sealed baselines and is
 * deterministic by construction.
 *
 * Fictional governance-simulation artefact: all data is simulated.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { ComplianceSummary, HealthStatus, IncidentRecord, SupervisoryWindow } from './types.js';

const PORT = Number(process.env.PORT ?? 4183);

const latestWindow: SupervisoryWindow = {
  windowId: '2026-308',
  windowCloseUtc: '2026-11-04T09:00:00Z',
  simulation: true,
  telemetry: {
    s_sys: 0.185,
    g_sri: 26.8,
    c_sri: 17.2,
    g_sri_vii: 29.4,
    a_sri: 20.4,
    p_sri: 15.7,
    cgr_i: 20.2,
    ccr_i: 18.8,
    p_doom: 0.0021,
    p_doom_kernel: 0.0006,
    delta_drift: 0.0,
    delta_oscal: 0,
  },
  evidence: {
    merkleRoot: '0xa3f6c81d9b4e27505fae3c19d86b0742ef5a9c31b8d04f2c7e6a95d3f8b21c04',
    artefactsSealed: 26,
  },
};

const compliance: ComplianceSummary = {
  catalogRevision: 1164,
  simulation: true,
  regimes: [
    { framework: 'EU AI Act', result: 'PASS' },
    { framework: 'NIST AI RMF 1.0 / AI 600-1', result: 'PASS' },
    { framework: 'ISO/IEC 42001', result: 'PASS' },
    { framework: 'Basel III/IV', result: 'PASS' },
    { framework: 'SR 11-7', result: 'PASS' },
    { framework: 'SR 26-2', result: 'PASS' },
    { framework: 'DORA', result: 'PASS' },
    { framework: 'NIS2', result: 'PASS' },
    { framework: 'FCA SMCR & Consumer Duty', result: 'PASS' },
    { framework: 'HKMA Fintech 2030 AI2', result: 'PASS' },
    { framework: 'SEC Rule 17a-4', result: 'PASS' },
    { framework: 'FCRA/ECOA', result: 'PASS' },
    { framework: 'ICGC/GASO', result: 'PASS' },
    { framework: 'Interstellar AI Governance Accord', result: 'PASS' },
    { framework: 'Galactic Treaty Framework', result: 'PASS' },
    { framework: 'GDPR', result: 'PASS' },
  ],
};

const incidents: IncidentRecord[] = [
  {
    incidentId: 'GIEN-INC-2026-308-01',
    openedUtc: '2026-11-03T14:02:00Z',
    classification: 'asa-drift-contained',
    status: 'contained',
    wormSealed: true,
  },
];

function sendJson(res: ServerResponse, statusCode: number, body: unknown): void {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-GIEN-Simulation': 'true',
  });
  res.end(JSON.stringify(body));
}

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  const url = (req.url ?? '/').split('?')[0];

  if (req.method !== 'GET') {
    sendJson(res, 405, { error: 'method not allowed', method: req.method });
    return;
  }

  if (url === '/healthz') {
    const health: HealthStatus = {
      status: 'ok',
      service: 'gien-governance-telemetry-api',
      simulation: true,
      uptimeSeconds: Math.round(process.uptime()),
    };
    sendJson(res, 200, health);
    return;
  }

  if (url === '/v1/window/latest') {
    sendJson(res, 200, latestWindow);
    return;
  }

  const windowMatch = /^\/v1\/window\/([0-9]{4}-[0-9]{3})$/.exec(url);
  if (windowMatch) {
    if (windowMatch[1] === latestWindow.windowId) {
      sendJson(res, 200, latestWindow);
      return;
    }
    sendJson(res, 404, { error: 'unknown window', windowId: windowMatch[1] });
    return;
  }

  if (url === '/v1/compliance') {
    sendJson(res, 200, compliance);
    return;
  }

  if (url === '/v1/incidents') {
    sendJson(res, 200, incidents);
    return;
  }

  sendJson(res, 404, { error: 'not found', path: url });
});

server.listen(PORT, () => {
  console.log(`GIEN governance telemetry API listening on port ${PORT} (fictional simulation data)`);
});
