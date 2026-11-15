export type Band = 'GREEN' | 'AMBER' | 'RED';

export type Role = 'supervisor' | 'engineer' | 'educational';

export interface IndexReading {
  key: string;
  label: string;
  value: string;
  delta: string;
  band: Band;
  note: string;
  /** WP-096 evidence-drawer contract id, when the index is covered by the contract. */
  evidenceId?: EvidenceIndexId;
}

export interface SealedDossier {
  dossierId: string;
  workPackage: string;
  window: string;
  merkleRoot: string;
  artefacts: number;
  signatures: { algorithm: string; value: string }[];
  indices: IndexReading[];
  domains: { id: string; name: string; status: Band; note: string }[];
  drills: { name: string; outcome: string; note: string }[];
  regimes: string[];
  continuityProtocols: string;
  alertLevel: string;
  omegaGar: { cesi: string; ucsi: string; uci: string; cds: string; infinityPillar: string };
}

// --- WP-096 evidence-drawer contract (webapp/phase1/evidence-drawer.schema.json) ---

export type EvidenceIndexId =
  | 'p_doom' | 'p_doom_kernel' | 's_sys' | 'g_sri' | 'c_sri' | 'a_sri'
  | 'p_sri' | 'cgr_i' | 'ccr_i' | 'g_sri_vii' | 'drift' | 'oscal_drift';

export interface EvidenceControl {
  control_id: string;
  regimes?: string[];
  layer: 'real' | 'simulation';
}

export interface EvidenceArtifact {
  type: string;
  dossier_id: string;
  digest: string;
  merkle_root: string;
  path?: string;
}

export interface EvidenceVerification {
  root_recomputable: boolean;
  walkthrough_steps?: number;
  notes?: string;
}

export interface EvidencePayload {
  index: { id: EvidenceIndexId; name: string; semantics: string };
  current: {
    value: number;
    unit: string;
    band: Band;
    delta_24h?: number;
    window_id: string;
    epoch_trend?: string;
  };
  series?: { ref_url?: string; inline?: number[]; notes?: string };
  controls: EvidenceControl[];
  artifacts: EvidenceArtifact[];
  verification: EvidenceVerification;
}
