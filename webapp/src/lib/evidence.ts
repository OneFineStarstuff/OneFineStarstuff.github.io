// WP-096 evidence-drawer contract validation + Merkle verification helpers.
// The validator mirrors webapp/phase1/evidence-drawer.schema.json (draft 2020-12 subset).
import { EvidencePayload } from '../types/gien';

const INDEX_IDS = new Set([
  'p_doom', 'p_doom_kernel', 's_sys', 'g_sri', 'c_sri', 'a_sri',
  'p_sri', 'cgr_i', 'ccr_i', 'g_sri_vii', 'drift', 'oscal_drift'
]);
const BANDS = new Set(['GREEN', 'AMBER', 'RED']);
const LAYERS = new Set(['real', 'simulation']);
const HEX64 = /^0x[0-9a-f]{64}$/;
const HEX64_96 = /^0x[0-9a-f]{64,96}$/;
const DOSSIER_ID = /^GIEN-DOSSIER-[0-9]{4}-[0-9]{3}$/;
const CONTROL_ID = /^[A-Z]+-[0-9]{2}$/;

function isStr(v: unknown): boolean { return typeof v === 'string'; }
function isNum(v: unknown): boolean { return typeof v === 'number' && Number.isFinite(v); }

export function validateEvidencePayload(p: unknown): string[] {
  const errs: string[] = [];
  if (!p || typeof p !== 'object' || Array.isArray(p)) return ['payload is not an object'];
  const o = p as Record<string, unknown>;
  for (const k of ['index', 'current', 'controls', 'artifacts', 'verification']) {
    if (!(k in o)) errs.push('missing required field: ' + k);
  }
  const allowed = new Set(['index', 'current', 'series', 'controls', 'artifacts', 'verification']);
  for (const k of Object.keys(o)) if (!allowed.has(k)) errs.push('unexpected field: ' + k);

  const ix = o.index as Record<string, unknown> | undefined;
  if (ix && typeof ix === 'object') {
    if (!INDEX_IDS.has(String(ix.id))) errs.push('index.id outside the WP-096 enum: ' + String(ix.id));
    if (!isStr(ix.name) || !isStr(ix.semantics)) errs.push('index.name / index.semantics must be strings');
  }
  const cur = o.current as Record<string, unknown> | undefined;
  if (cur && typeof cur === 'object') {
    if (!isNum(cur.value)) errs.push('current.value must be a number');
    if (!isStr(cur.unit)) errs.push('current.unit must be a string');
    if (!BANDS.has(String(cur.band))) errs.push('current.band outside GREEN/AMBER/RED');
    if (!DOSSIER_ID.test(String(cur.window_id))) errs.push('current.window_id fails the dossier-id pattern');
    if ('delta_24h' in cur && !isNum(cur.delta_24h)) errs.push('current.delta_24h must be a number');
  }
  const ctrls = o.controls;
  if (!Array.isArray(ctrls) || ctrls.length < 1) errs.push('controls must be a non-empty array');
  else for (const c of ctrls) {
    const cc = c as Record<string, unknown>;
    if (!CONTROL_ID.test(String(cc.control_id))) errs.push('control_id fails the ^[A-Z]+-[0-9]{2}$ pattern: ' + String(cc.control_id));
    if (!LAYERS.has(String(cc.layer))) errs.push('control.layer must be real|simulation');
  }
  const arts = o.artifacts;
  if (!Array.isArray(arts) || arts.length < 1) errs.push('artifacts must be a non-empty array');
  else for (const a of arts) {
    const aa = a as Record<string, unknown>;
    if (!isStr(aa.type)) errs.push('artifact.type must be a string');
    if (!DOSSIER_ID.test(String(aa.dossier_id))) errs.push('artifact.dossier_id fails the dossier-id pattern');
    if (!HEX64_96.test(String(aa.digest))) errs.push('artifact.digest fails the 0x + 64..96 hex pattern');
    if (!HEX64.test(String(aa.merkle_root))) errs.push('artifact.merkle_root fails the 0x + 64 hex pattern');
  }
  const ver = o.verification as Record<string, unknown> | undefined;
  if (ver && typeof ver === 'object') {
    if (typeof ver.root_recomputable !== 'boolean') errs.push('verification.root_recomputable must be a boolean');
  }
  return errs;
}

export function validateEvidenceContract(payloads: Record<string, EvidencePayload>): {
  ok: boolean;
  report: Record<string, string[]>;
} {
  const report: Record<string, string[]> = {};
  let ok = true;
  for (const [id, payload] of Object.entries(payloads)) {
    const errs = validateEvidencePayload(payload);
    report[id] = errs;
    if (errs.length > 0) ok = false;
  }
  return { ok, report };
}

// --- Merkle verification (SHA-384, matching the WORM ledger digest algorithm) ---

export async function sha384Hex(input: string): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto subtle digest unavailable (secure context required)');
  }
  const buf = await crypto.subtle.digest('SHA-384', new TextEncoder().encode(input));
  return '0x' + Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Derives a Merkle root from leaf digests: leaves are hashed once, then each
 * internal node is SHA-384 over the concatenation of its two child hex strings
 * (odd tail node is promoted unchanged). Demo-grade tree, documented honestly
 * in the inspector UI: the WORM ledger's canonical tree shape is not exposed
 * in the static corpus.
 */
export async function recomputeMerkleRoot(leafHexes: string[]): Promise<{ root: string; levels: number }> {
  let level = await Promise.all(leafHexes.map((l) => sha384Hex(l)));
  let levels = 1;
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? await sha384Hex(level[i] + level[i + 1]) : level[i]);
    }
    level = next;
    levels += 1;
  }
  return { root: level[0], levels };
}
