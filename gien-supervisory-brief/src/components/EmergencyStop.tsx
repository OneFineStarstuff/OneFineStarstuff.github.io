import { OctagonAlert, RotateCcw } from 'lucide-react';
import { useState } from 'react';
import { useToast } from '../context/ToastContext';

// UI-only emergency stop. It performs no real control action on any system:
// it opens a confirmation modal, then records a CRITICAL audit toast.
export default function EmergencyStop() {
  const [confirming, setConfirming] = useState(false);
  const [engaged, setEngaged] = useState(false);
  const { pushToast } = useToast();

  const engage = () => {
    setConfirming(false);
    setEngaged(true);
    pushToast(
      'CRITICAL',
      'EMERGENCY STOP ENGAGED (SIMULATION) — AUDIT-2026-11-02-EMSTOP-001 recorded to the fictional transcript registry. No real system was affected.'
    );
  };

  const reset = () => {
    setEngaged(false);
    pushToast('INFO', 'Emergency stop reset (simulation). Containment posture returned to ARMED.');
  };

  return (
    <>
      {engaged ? (
        <button
          type="button"
          onClick={reset}
          className="inline-flex items-center gap-1.5 rounded-md border border-red-500/60 bg-red-500/20 px-2.5 py-1 text-[11px] font-semibold text-red-300 hover:bg-red-500/30"
          aria-label="Reset simulated emergency stop"
        >
          <RotateCcw size={12} /> STOP ENGAGED — RESET
        </button>
      ) : (
        <button
          type="button"
          onClick={() => setConfirming(true)}
          className="inline-flex items-center gap-1.5 rounded-md border border-red-500/50 bg-red-500/10 px-2.5 py-1 text-[11px] font-semibold text-red-300 hover:bg-red-500/20"
          aria-label="Open simulated emergency stop confirmation"
        >
          <OctagonAlert size={12} /> EMERGENCY STOP
        </button>
      )}

      {engaged && (
        <div className="border-b border-red-500/40 bg-red-500/10 px-4 py-1 text-[11px] font-semibold tracking-wide text-red-300 md:px-6">
          SAFEGUARD MODE — simulated emergency stop engaged. All governance actions are UI-only;
          this demonstration controls no real system.
        </div>
      )}

      {confirming && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Confirm emergency stop">
          <div className="w-full max-w-md rounded-lg border border-red-500/40 bg-gray-900 p-5 shadow-2xl">
            <div className="flex items-center gap-2 text-red-300">
              <OctagonAlert size={18} />
              <h2 className="text-sm font-semibold">Confirm simulated emergency stop</h2>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-gray-300">
              This is a demonstration affordance in a fictional governance environment. Engaging it
              records a CRITICAL audit event and displays Safeguard Mode. It does not halt, isolate,
              or control any real model, service, or financial system.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirming(false)}
                className="rounded-md border border-gray-600 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={engage}
                className="rounded-md bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-500"
              >
                Engage (simulation)
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
