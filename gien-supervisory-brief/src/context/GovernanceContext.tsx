import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';
import type { GovernanceAlert, Role } from '../types';

export const EVALUATION_WINDOW = '2026-10-09T09:00:00Z → 2026-10-10T09:00:00Z';
export const GIEN_PHASE = 'Phase VI-δ';
export const FILING_REF = 'SGR-028-CFE-2026-07-001';

export interface GovernanceContextValue {
  role: Role;
  setRole: (role: Role) => void;
  phase: string;
  evaluationWindow: string;
  filingRef: string;
  alerts: GovernanceAlert[];
  alertCount: number;
}

const GovernanceContext = createContext<GovernanceContextValue | undefined>(undefined);

const DEFAULT_ALERTS: GovernanceAlert[] = [
  {
    id: 'ALR-2026-10-10-01',
    severity: 'ELEVATED',
    message: 'C-SRI at 0.327 (threshold 0.30) — contagion channel stress in G-SIFI cluster 3',
  },
  {
    id: 'ALR-2026-10-10-02',
    severity: 'ELEVATED',
    message: 'A-SRI at 0.463 (threshold 0.45) — Autonomous Supervisory Agent drift watch in effect',
  },
];

export function GovernanceProvider({ children }: { children: ReactNode }) {
  const [role, setRole] = useState<Role>('REGULATOR');

  const value = useMemo<GovernanceContextValue>(
    () => ({
      role,
      setRole,
      phase: GIEN_PHASE,
      evaluationWindow: EVALUATION_WINDOW,
      filingRef: FILING_REF,
      alerts: DEFAULT_ALERTS,
      alertCount: DEFAULT_ALERTS.length,
    }),
    [role]
  );

  return <GovernanceContext.Provider value={value}>{children}</GovernanceContext.Provider>;
}

export function useGovernance(): GovernanceContextValue {
  const ctx = useContext(GovernanceContext);
  if (!ctx) throw new Error('useGovernance must be used within GovernanceProvider');
  return ctx;
}
