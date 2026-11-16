import { Band } from '../types/gien';
import THRESHOLDS from '../data/bands.json';

/**
 * WP-108: shared band/threshold module. One typed definition consumed by the
 * webapp panels, the dossier template, and (via bands.json) the Python
 * telemetry monitors. Never redefine thresholds locally.
 */

interface Range { greenBelow?: number; amberBelow?: number; greenAbove?: number; amberAbove?: number; floor?: number; greenAbs?: number; amberAbs?: number; }

const lower = THRESHOLDS.lowerIsBetter as Record<string, Range>;
const higher = THRESHOLDS.higherIsBetter as Record<string, Range>;
const symmetric = THRESHOLDS.symmetric as Record<string, Range>;

export type IndexKey = keyof typeof THRESHOLDS.lowerIsBetter | keyof typeof THRESHOLDS.higherIsBetter | keyof typeof THRESHOLDS.symmetric;

export function computeBand(key: IndexKey, value: number): Band {
  const r = lower[key] || higher[key] || symmetric[key];
  if (!r) throw new Error('No thresholds registered for index: ' + key);
  if (r.greenBelow !== undefined) return value < r.greenBelow ? 'GREEN' : value < (r.amberBelow as number) ? 'AMBER' : 'RED';
  if (r.greenAbove !== undefined) return value > r.greenAbove ? 'GREEN' : value >= (r.amberAbove as number) ? 'AMBER' : 'RED';
  if (r.greenAbs !== undefined) return Math.abs(value) <= r.greenAbs ? 'GREEN' : Math.abs(value) <= (r.amberAbs as number) ? 'AMBER' : 'RED';
  return 'RED';
}

export function thresholdsFor(key: IndexKey): Range {
  const r = lower[key] || higher[key] || symmetric[key];
  if (!r) throw new Error('No thresholds registered for index: ' + key);
  return r;
}
