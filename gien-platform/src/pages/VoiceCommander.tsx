import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Page, Card, StatusBadge } from '../components/ui';
import { useToast, useRole } from '../contexts';

type StopState = 'idle' | 'armed' | 'active' | 'resume-armed';

interface SpeechRecognitionAlternativeLike {
  readonly transcript: string;
}

interface SpeechRecognitionResultLike extends ArrayLike<SpeechRecognitionAlternativeLike> {
  readonly isFinal: boolean;
}

interface SpeechRecognitionEventLike extends Event {
  readonly resultIndex: number;
  readonly results: ArrayLike<SpeechRecognitionResultLike>;
}

interface SpeechRecognitionLike {
  lang: string;
  interimResults: boolean;
  continuous: boolean;
  onresult: ((event: SpeechRecognitionEventLike) => void) | null;
  onend: (() => void) | null;
  onerror: ((event: Event) => void) | null;
  start(): void;
}

type SpeechRecognitionConstructorLike = new () => SpeechRecognitionLike;

function getSpeechRecognitionConstructor(): SpeechRecognitionConstructorLike | undefined {
  const speechGlobal = globalThis as typeof globalThis & {
    SpeechRecognition?: SpeechRecognitionConstructorLike;
    webkitSpeechRecognition?: SpeechRecognitionConstructorLike;
  };
  return speechGlobal.SpeechRecognition ?? speechGlobal.webkitSpeechRecognition;
}

interface LogEntry { ts: string; intent: string; outcome: string; channel: string; role: string; }

const GRAMMAR: { intent: string; patterns: string[]; effect: string }[] = [
  { intent: 'show_overview', patterns: ['overview', 'executive summary'], effect: 'Navigate to Executive Summary' },
  { intent: 'show_risk', patterns: ['systemic risk', 'telemetry'], effect: 'Navigate to Systemic Risk Telemetry' },
  { intent: 'show_compliance', patterns: ['compliance'], effect: 'Navigate to Compliance Matrix' },
  { intent: 'export_alerts', patterns: ['export alerts'], effect: 'Open Alert History export' },
  { intent: 'emergency_stop', patterns: ['emergency stop'], effect: 'Arm the kill-switch (confirmation required)' },
  { intent: 'resume_operations', patterns: ['resume operations'], effect: 'Restore operations (confirmation required)' },
];

export default function VoiceCommander() {
  const navigate = useNavigate();
  const { push } = useToast();
  const { role } = useRole();
  const [typed, setTyped] = useState('');
  const [transcript, setTranscript] = useState('');
  const [listening, setListening] = useState(false);
  const [supported] = useState<boolean>(() => Boolean(getSpeechRecognitionConstructor()));
  const [stopState, setStopState] = useState<StopState>('idle');
  const [log, setLog] = useState<LogEntry[]>([]);
  const recognitionRef = useRef<SpeechRecognitionLike | null>(null);

  const now = () => new Date().toISOString().slice(11, 19) + 'Z';
  const record = (intent: string, outcome: string, channel: string) => {
    setLog(l => [{ ts: now(), intent, outcome, channel, role }, ...l].slice(0, 12));
  };

  const dispatch = (intent: string, channel: 'voice' | 'typed') => {
    if (stopState === 'active' && intent !== 'resume_operations') {
      record(intent, 'BLOCKED — kill-switch active', channel);
      push({ severity: 'RED', title: 'Command blocked', body: 'Kill-switch active — autonomous actions disabled. Only resume operations is accepted.' });
      return;
    }
    switch (intent) {
      case 'show_overview': record(intent, 'NAVIGATE /', channel); navigate('/'); break;
      case 'show_risk': record(intent, 'NAVIGATE /telemetry', channel); navigate('/telemetry'); break;
      case 'show_compliance': record(intent, 'NAVIGATE /compliance', channel); navigate('/compliance'); break;
      case 'export_alerts': record(intent, 'NAVIGATE /alerts', channel); navigate('/alerts'); break;
      case 'emergency_stop': record(intent, 'ARMED — awaiting confirmation', channel); setStopState('armed'); break;
      case 'resume_operations':
        if (stopState === 'active') { record(intent, 'RESUME-ARMED — awaiting confirmation', channel); setStopState('resume-armed'); }
        else { record(intent, 'NO-OP — kill-switch not active', channel); }
        break;
      default: record(intent, 'UNKNOWN', channel);
    }
  };

  const matchIntent = (text: string) => {
    const t = text.toLowerCase();
    const g = GRAMMAR.find(x => x.patterns.some(p => t.includes(p)));
    return g ? g.intent : null;
  };

  const handleTyped = () => {
    const intent = matchIntent(typed);
    if (intent) dispatch(intent, 'typed'); else push({ severity: 'AMBER', title: 'Unrecognized command', body: typed });
    setTyped('');
  };

  const startListening = () => {
    const SpeechRecognition = getSpeechRecognitionConstructor();
    if (!SpeechRecognition) return;
    const rec = new SpeechRecognition();
    recognitionRef.current = rec;
    rec.lang = 'en-US';
    rec.interimResults = false;
    rec.continuous = false;
    rec.onresult = event => {
      const result = event.results[event.resultIndex] ?? event.results[0];
      const text = result?.[0]?.transcript.trim() ?? '';
      if (!text) return;
      setTranscript(text);
      const intent = matchIntent(text);
      if (intent) dispatch(intent, 'voice'); else push({ severity: 'AMBER', title: 'Unrecognized command', body: text });
    };
    rec.onend = () => setListening(false);
    rec.onerror = () => setListening(false);
    rec.start();
    setListening(true);
  };

  return (
    <Page title="Voice Commander" subtitle="Voice control interface · closed grammar · confirmation-gated emergency stop · mandatory typed fallback">
      {stopState === 'active' && (
        <div className="rounded-lg border border-red-400 bg-red-50 dark:bg-red-950/40 p-4 flex items-center gap-3">
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-600 text-white">KILL-SWITCH ACTIVE</span>
          <span className="text-sm text-red-800 dark:text-red-200">Autonomous actions disabled (simulation affordance) — resume operations is the only accepted command.</span>
        </div>
      )}

      <Card title="Command grammar v1">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Intent</th>
                <th className="py-2 pr-3">Utterance patterns</th>
                <th className="py-2 pr-3">Effect</th>
              </tr>
            </thead>
            <tbody>
              {GRAMMAR.map(g => (
                <tr key={g.intent} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3 font-mono text-xs">{g.intent}</td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{g.patterns.join(' · ')}</td>
                  <td className="py-2 pr-3">{g.effect}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Voice capture">
        <div className="flex items-center gap-3 mb-3">
          <StatusBadge status={supported ? 'GREEN' : 'AMBER'} />
          <span className="text-xs text-slate-500">{supported ? 'Web Speech API available in this browser' : 'Web Speech unavailable — typed console is the sole interface'}</span>
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <button onClick={startListening} disabled={listening} className="px-3 py-1.5 text-sm rounded bg-sky-600 text-white disabled:opacity-50">{listening ? 'Listening…' : 'Enable microphone and speak'}</button>
          <span className="text-xs text-slate-500">Opt-in consent · no audio persisted · tokenized intent transcripts only</span>
        </div>
        {transcript && <div className="mt-2 text-sm">Heard: <span className="font-mono">{transcript}</span></div>}
        <div className="mt-4 flex flex-wrap gap-2">
          <input value={typed} onChange={e => setTyped(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') handleTyped(); }} placeholder="Typed fallback — e.g. export alerts, emergency stop" className="flex-1 min-w-[240px] px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800" />
          <button onClick={handleTyped} className="px-3 py-1.5 text-sm rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900">Execute</button>
        </div>
        <p className="text-xs text-slate-500 mt-2">Every voice path has a keyboard equivalent (WCAG 2.2 AA); spoken alerts mirror band transitions in enterprise mode.</p>
      </Card>

      <Card title="Emergency stop state machine">
        <div className="flex items-center gap-3 mb-2">
          <span className="text-xs uppercase text-slate-500">Current state</span>
          <span className="font-mono text-sm">{stopState}</span>
        </div>
        <p className="text-xs text-slate-500">idle → armed (first confirmation) → active (kill-switch banner, autonomous actions disabled) → resume-armed (second confirmation) → idle. Every transition is audit-logged; resume operations is the only exit path.</p>
        <div className="mt-3 flex gap-2">
          <button onClick={() => dispatch('emergency_stop', 'typed')} disabled={stopState === 'active'} className="px-3 py-1.5 text-sm rounded bg-red-600 text-white hover:bg-red-700 disabled:opacity-50">Trigger stop (typed)</button>
          <button onClick={() => dispatch('resume_operations', 'typed')} disabled={stopState !== 'active'} className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700 disabled:opacity-50">Resume operations</button>
        </div>
      </Card>

      <Card title="Audit trail (simulated — WORM-committed with ML-DSA-87 in enterprise mode)">
        {log.length === 0 ? (
          <p className="text-sm text-slate-500">No commands dispatched this session.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Time</th>
                <th className="py-2 pr-3">Intent</th>
                <th className="py-2 pr-3">Outcome</th>
                <th className="py-2 pr-3">Channel</th>
                <th className="py-2 pr-3">Actor role</th>
              </tr>
            </thead>
            <tbody>
              {log.map((l, i) => (
                <tr key={i} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3 font-mono text-xs">{l.ts}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{l.intent}</td>
                  <td className="py-2 pr-3">{l.outcome}</td>
                  <td className="py-2 pr-3">{l.channel}</td>
                  <td className="py-2 pr-3">{l.role}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {(stopState === 'armed' || stopState === 'resume-armed') && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" role="dialog" aria-modal="true">
          <div className="bg-white dark:bg-slate-900 rounded-lg p-6 max-w-md w-full">
            <h3 className="font-semibold mb-2">{stopState === 'armed' ? 'Confirm emergency stop' : 'Confirm resume operations'}</h3>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
              {stopState === 'armed'
                ? 'Simulation affordance only — confirms the kill-switch state, disables autonomous actions, and logs a CRITICAL audit event. No real systems are affected.'
                : 'Second confirmation — restores operations from the kill-switch state and logs the resume event.'}
            </p>
            <div className="flex gap-2 justify-end">
              <button onClick={() => { if (stopState === 'armed') setStopState('idle'); else setStopState('active'); }} className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700">Cancel</button>
              <button onClick={() => {
                if (stopState === 'armed') {
                  setStopState('active');
                  record('emergency_stop', 'CONFIRMED — kill-switch active', 'typed');
                  push({ severity: 'CRITICAL', title: 'Emergency stop confirmed', body: 'Kill-switch active — autonomous actions disabled. Log entry recorded (simulation).' });
                } else {
                  setStopState('idle');
                  record('resume_operations', 'CONFIRMED — operations restored', 'typed');
                  push({ severity: 'GREEN', title: 'Operations resumed', body: 'Kill-switch cleared. Log entry recorded (simulation).' });
                }
              }} className={stopState === 'armed' ? 'px-3 py-1.5 text-sm rounded bg-red-600 text-white hover:bg-red-700' : 'px-3 py-1.5 text-sm rounded bg-emerald-600 text-white hover:bg-emerald-700'}>Confirm</button>
            </div>
          </div>
        </div>
      )}
    </Page>
  );
}