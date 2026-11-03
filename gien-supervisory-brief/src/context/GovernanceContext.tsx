import { createContext, useCallback, useContext, useMemo, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { GovernanceAlert, Role } from '../types';

export const EVALUATION_WINDOW = '2026-11-01T09:00:00Z → 2026-11-02T09:00:00Z';
export const GIEN_PHASE = 'Phase VI-δ';
export const FILING_REF = 'SGR-028-CFE-2026-07-001';

export type DisclosureLayer = 'EXECUTIVE' | 'ENGINEERING' | 'CRYPTOGRAPHIC';

export const ROLES: Role[] = ['REGULATOR', 'INSTITUTION', 'EXECUTIVE', 'EDUCATION'];
export const LAYERS: DisclosureLayer[] = ['EXECUTIVE', 'ENGINEERING', 'CRYPTOGRAPHIC'];

const ROLE_LABELS: Record<Role, string> = {
  REGULATOR: 'Regulator / Supervisory Authority',
  INSTITUTION: 'Institution / Governance Engineer',
  EXECUTIVE: 'Executive Leadership',
  EDUCATION: 'Educational / Research',
};

const LAYER_LABELS: Record<DisclosureLayer, string> = {
  EXECUTIVE: 'L1 · Executive summary',
  ENGINEERING: 'L2 · Governance engineering',
  CRYPTOGRAPHIC: 'L3 · Cryptographic specifics',
};

export interface GovernanceContextValue {
  role: Role;
  setRole: (role: Role) => void;
  layer: DisclosureLayer;
  setLayer: (layer: DisclosureLayer) => void;
  roleLabels: typeof ROLE_LABELS;
  layerLabels: typeof LAYER_LABELS;
  phase: string;
  evaluationWindow: string;
  filingRef: string;
  alerts: GovernanceAlert[];
  alertCount: number;
}

const GovernanceContext = createContext<GovernanceContextValue | undefined>(undefined);

const DEFAULT_ALERTS: GovernanceAlert[] = [
  {
    id: 'ALR-2026-11-02-01',
    severity: 'ELEVATED',
    message: 'C-SRI at 0.33 (threshold 0.30) — contagion channel stress persists in G-SIFI cluster 3',
  },
  {
    id: 'ALR-2026-11-02-02',
    severity: 'ELEVATED',
    message: 'A-SRI at 0.48 (threshold 0.45) — Autonomous Supervisory Agent drift watch in effect',
  },
];

export function GovernanceProvider({ children }: { children: ReactNode }) {
  const [params, setParams] = useSearchParams();

  const roleParam = (params.get('role') ?? '').toUpperCase();
  const layerParam = (params.get('layer') ?? '').toUpperCase();
  const role: Role = (ROLES as string[]).includes(roleParam) ? (roleParam as Role) : 'REGULATOR';
  const layer: DisclosureLayer = (LAYERS as string[]).includes(layerParam)
    ? (layerParam as DisclosureLayer)
    : 'ENGINEERING';

  const setParam = useCallback(
    (key: 'role' | 'layer', value: string) => {
      const next = new URLSearchParams(params);
      next.set(key, value.toLowerCase());
      setParams(next, { replace: true });
    },
    [params, setParams]
  );

  const setRole = useCallback((r: Role) => setParam('role', r), [setParam]);
  const setLayer = useCallback((l: DisclosureLayer) => setParam('layer', l), [setParam]);

  const value = useMemo<GovernanceContextValue>(
    () => ({
      role,
      setRole,
      layer,
      setLayer,
      roleLabels: ROLE_LABELS,
      layerLabels: LAYER_LABELS,
      phase: GIEN_PHASE,
      evaluationWindow: EVALUATION_WINDOW,
      filingRef: FILING_REF,
      alerts: DEFAULT_ALERTS,
      alertCount: DEFAULT_ALERTS.length,
    }),
    [role, setRole, layer, setLayer]
  );

  return <GovernanceContext.Provider value={value}>{children}</GovernanceContext.Provider>;
}

export function useGovernance(): GovernanceContextValue {
  const ctx = useContext(GovernanceContext);
  if (!ctx) throw new Error('useGovernance must be used within GovernanceProvider');
  return ctx;
}
