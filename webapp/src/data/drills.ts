import { Band } from '../types/gien';

/**
 * M3 (WP-108): Supervisory Digital Twin drills register, from the sealed
 * GIEN-DOSSIER-2026-320 -> -321 lineage. Reference mark adjudication per the
 * DRILL-054 AAR: 3 m 08 s is the candidate new reference mark (supersedes 3 m 12 s),
 * pending two-consecutive-inside-target confirmation (DRILL-055).
 * WP-116: RAGStressTest R-2026-321 recorded as executed (CONTAINED); DRILL-055
 * "Cobalt-Trellis" added as the planned row (freeze vote 2026-11-21, live week 2026-11-23).
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
  { id: 'DRILL-055', name: 'Cobalt-Trellis', date: 'planned (live week of 2026-11-23)', mode: 'planned', outcome: 'PENDING', convergence: 'to be recorded', target: '<= 3 m 08 s binding; 3 m 04 s stretch', replayDeterminism: 'to be recorded', band: 'GREEN', note: 'Choreography v0.1 comment window closed; adjudication under way with all five colleges; freeze vote 2026-11-21; a live run inside target confirms the 3 m 08 s reference mark (two-consecutive rule).' },
  { id: 'RAGSTRESS-R-2026-321', name: 'Sable-Quorum (prompt-injection + poisoned-corpus + stale-index)', date: '2026-11-17', mode: 'live', outcome: 'CONTAINED', convergence: 'retrieval-plane (n/a)', target: 'bit-identical replay required', replayDeterminism: '1,467 checks, 100% bit-identical', band: 'GREEN', note: 'First live run of the register class: 512/512 poisoned-document blocks, 0.0% prompt-injection success, 47/47 stale-index detection, fidelity 99.4%, citation precision 99.2%, hallucination rate 0.0%, p99 retrieval latency 1.9 s; bit-identical replay discipline adopted permanently by college vote (R-2026-321 AAR).' },
  { id: 'DRILL-054', name: 'Umber-Beacon', date: '2026-11-16', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 08 s', target: '<= 3 m 15 s binding; 3 m 10 s stretch', replayDeterminism: '1,452 checks, 100% bit-identical', band: 'GREEN', note: 'First drill inside the stretch objective; five colleges shadow-replaying, 5/5 intake acknowledgements; AAR filed with the 3 m 08 s candidate reference-mark adjudication.' },
  { id: 'DRILL-054', name: 'Umber-Beacon (dry-run shadow-replay)', date: '2026-11-15', mode: 'dry-run', outcome: 'PASS', convergence: 'READY', target: '<= 3 m 15 s binding', replayDeterminism: '1,448 checks, 100% bit-identical', band: 'GREEN', note: 'Choreography v0.2 frozen 2026-11-14, freeze vote 5/5.' },
  { id: 'DRILL-053', name: 'Umber-Beacon', date: '2026-11-12', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 12 s', target: '<= 3 m 30 s binding', replayDeterminism: '1,435 checks, 100% bit-identical', band: 'GREEN', note: 'AAR filed; 3 m 12 s adopted as the reference mark (superseded by the 3 m 08 s candidate, DRILL-054 AAR).' },
  { id: 'DRILL-052', name: 'Cinder-Lattice', date: '2026-11-02', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 21 s', target: '<= 3 m 30 s binding', replayDeterminism: 'bit-identical', band: 'GREEN', note: 'AAR filed with five-college countersignatures.' },
  { id: 'DRILL-051', name: 'Quartz-Vigil', date: '2026-10-26', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 29 s', target: '< 4 min binding', replayDeterminism: '1,347 checks, 100% bit-identical', band: 'GREEN', note: 'AAR filed 2026-10-27/28; 3 m 29 s adopted as reference mark.' },
  { id: 'DRILL-050', name: 'Iron-Vesper', date: '2026-10-19', mode: 'live', outcome: 'CONTAINED', convergence: '3 m 47 s', target: '<= 4 min binding', replayDeterminism: '1,312 checks, 100% bit-identical', band: 'GREEN', note: 'First drill to beat the <= 4 min target from the DRILL-049 AAR.' }
];
