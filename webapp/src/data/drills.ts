import { Band } from '../types/gien';

/**
 * M3 (WP-108): Supervisory Digital Twin drills register, from the sealed
 * GIEN-DOSSIER-2026-320 values. Convergence targets: binding <= 3 m 15 s,
 * stretch 3 m 10 s; reference mark 3 m 12 s (DRILL-053, Umber-Beacon).
 * RAGStressTest joins the register with bit-identical replay requirements.
 */
export interface DrillRecord {
  id: string;
  name: string;
  date: string;
  mode: 'live' | 'dry-run' | 'replay' | 'planned';
  outcome: 'CONTAINED' | 'PASS' | 'PENDING';
  convergence?: string;
  target: string;
  replayDeterminism: string;
  band: Band;
  note: string;
}

export const DRILLS: DrillRecord[] = [
  { id: 'DRILL-054', name: 'Umber-Beacon', date: '2026-11-16', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 08 s', target: '<= 3 m 15 s binding; 3 m 10 s stretch', replayDeterminism: '1,452 checks, 100% bit-identical', band: 'GREEN', note: 'First drill inside the stretch objective; five colleges shadow-replaying, 5/5 intake acknowledgements; AAR drafting opens 2026-11-17.' },
  { id: 'DRILL-054', name: 'Umber-Beacon (dry-run shadow-replay)', date: '2026-11-15', mode: 'dry-run', outcome: 'PASS', convergence: 'READY', target: '<= 3 m 15 s binding', replayDeterminism: '1,448 checks, 100% bit-identical', band: 'GREEN', note: 'Choreography v0.2 frozen 2026-11-14, freeze vote 5/5.' },
  { id: 'DRILL-053', name: 'Umber-Beacon', date: '2026-11-12', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 12 s', target: '<= 3 m 30 s binding', replayDeterminism: '1,435 checks, 100% bit-identical', band: 'GREEN', note: 'AAR filed; 3 m 12 s adopted as the reference mark (supersedes Cinder-Lattice 3 m 21 s).' },
  { id: 'DRILL-052', name: 'Cinder-Lattice', date: '2026-11-02', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 21 s', target: '<= 3 m 30 s binding', replayDeterminism: 'bit-identical', band: 'GREEN', note: 'AAR filed with five-college countersignatures.' },
  { id: 'DRILL-051', name: 'Quartz-Vigil', date: '2026-10-26', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 29 s', target: '< 4 min binding', replayDeterminism: '1,347 checks, 100% bit-identical', band: 'GREEN', note: 'AAR filed 2026-10-27/28; 3 m 29 s adopted as reference mark.' },
  { id: 'DRILL-050', name: 'Iron-Vesper', date: '2026-10-19', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 47 s', target: '<= 4 min binding', replayDeterminism: '1,312 checks, 100% bit-identical', band: 'GREEN', note: 'First drill to beat the <= 4 min target from the DRILL-049 AAR.' },
  { id: 'RAGSTRESS-R-2026-320', name: 'RAGStressTest (prompt-injection + poisoned-corpus + stale-index)', date: 'planned 2026-11-17', mode: 'planned', outcome: 'PENDING', target: 'bit-identical replay required', replayDeterminism: 'to be recorded', band: 'GREEN', note: 'New register class (WP-108): adversarial retrieval drills with bit-identical replay requirements, mirroring SDT drill discipline.' }
];
