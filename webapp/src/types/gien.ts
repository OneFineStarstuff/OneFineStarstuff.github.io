export type Band = 'GREEN' | 'AMBER' | 'RED';

export type Role = 'supervisor' | 'engineer' | 'educational';

export interface IndexReading {
  key: string;
  label: string;
  value: string;
  delta: string;
  band: Band;
  note: string;
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
