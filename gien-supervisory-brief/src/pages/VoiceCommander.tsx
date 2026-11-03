import { useCallback, useMemo, useRef, useState } from 'react';
import { Mic, MicOff, Radio } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import EmergencyStop from '../components/EmergencyStop';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import { FICTIONAL_NOTICE, VOICE_COMMANDS } from '../data/extendedData';
import { useToast } from '../context/ToastContext';

interface SpeechResultEventLike {
  resultIndex: number;
  results: ArrayLike<ArrayLike<{ transcript: string }>>;
}

interface RecognitionLike {
  lang: string;
  continuous: boolean;
  interimResults: boolean;
  start: () => void;
  stop: () => void;
  onresult: ((event: SpeechResultEventLike) => void) | null;
  onerror: (() => void) | null;
  onend: (() => void) | null;
}

type RecognitionCtor = new () => RecognitionLike;

function getRecognitionCtor(): RecognitionCtor | null {
  const w = window as unknown as { SpeechRecognition?: RecognitionCtor; webkitSpeechRecognition?: RecognitionCtor };
  return w.SpeechRecognition ?? w.webkitSpeechRecognition ?? null;
}

export default function VoiceCommander() {
  const navigate = useNavigate();
  const { pushToast } = useToast();
  const [listening, setListening] = useState(false);
  const [supported] = useState(() => getRecognitionCtor() !== null);
  const [transcript, setTranscript] = useState<{ id: number; text: string; matched: string | null }[]>([]);
  const recognitionRef = useRef<RecognitionLike | null>(null);
  const counter = useRef(0);

  const commands = useMemo(() => VOICE_COMMANDS, []);

  const handlePhrase = useCallback(
    (text: string) => {
      const normalized = text.toLowerCase().trim();
      const match = commands.find((c) => normalized.includes(c.phrase));
      counter.current += 1;
      setTranscript((prev) => [{ id: counter.current, text, matched: match?.route ?? null }, ...prev].slice(0, 12));
      if (match) {
        navigate(match.route);
        pushToast('INFO', `Voice command recognised: "${match.phrase}" → ${match.route}`);
      } else if (normalized.includes('emergency stop')) {
        pushToast('ELEVATED', 'Emergency stop requires the confirmation control; voice cannot engage it.');
      }
    },
    [commands, navigate, pushToast]
  );

  const toggle = () => {
    if (listening) {
      recognitionRef.current?.stop();
      setListening(false);
      return;
    }
    const Ctor = getRecognitionCtor();
    if (!Ctor) return;
    const recognition = new Ctor();
    recognition.lang = 'en-US';
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.onresult = (event) => {
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const phrase = event.results[i][0]?.transcript ?? '';
        if (phrase) handlePhrase(phrase);
      }
    };
    recognition.onerror = () => {
      setListening(false);
      pushToast('ELEVATED', 'Speech recognition error; check microphone permissions.');
    };
    recognition.onend = () => setListening(false);
    recognitionRef.current = recognition;
    try {
      recognition.start();
      setListening(true);
      pushToast('INFO', 'Listening for a navigation command.');
    } catch {
      pushToast('ELEVATED', 'Speech recognition could not start in this browser.');
    }
  };

  return (
    <div>
      <PageHeader
        title="Voice Commander"
        subtitle="Hands-free navigation and supervisory alerts with a guarded emergency stop"
        crumbs={[{ label: 'Home', to: '/dashboard' }, { label: 'Voice Commander' }]}
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="rounded-lg border border-gray-700 bg-gray-800/50 p-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400">Microphone</h2>
          <button
            type="button"
            onClick={toggle}
            disabled={!supported}
            className={`mt-3 inline-flex w-full items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-semibold transition-colors ${
              supported ? (listening ? 'bg-red-500 text-white hover:bg-red-400' : 'bg-indigo-500 text-white hover:bg-indigo-400') : 'cursor-not-allowed bg-gray-700 text-gray-500'
            }`}
          >
            {listening ? <MicOff size={15} /> : <Mic size={15} />}
            {listening ? 'Stop listening' : 'Start listening'}
          </button>
          <p className="mt-2 text-[11px] text-gray-500">
            {supported
              ? 'Speech is processed by the browser speech engine. No audio leaves this device in the simulation.'
              : 'Web Speech API is unavailable in this browser; the command list below remains usable.'}
          </p>

          <h2 className="mt-5 text-xs font-semibold uppercase tracking-wider text-gray-400">Emergency stop</h2>
          <p className="mt-1 text-[11px] text-gray-500">
            UI-only affordance. Requires explicit confirmation and writes a CRITICAL audit toast.
          </p>
          <div className="mt-2">
            <EmergencyStop />
          </div>
        </section>

        <section className="rounded-lg border border-gray-700 bg-gray-800/50 p-4">
          <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-400">
            <Radio size={13} /> Available commands
          </h2>
          <ul className="mt-2 space-y-1.5">
            {commands.map((c) => (
              <li key={c.phrase} className="rounded border border-gray-700/70 bg-gray-900/50 px-2.5 py-1.5">
                <p className="font-mono text-[11px] text-indigo-300">“{c.phrase}”</p>
                <p className="text-[11px] text-gray-500">{c.description} · {c.route}</p>
              </li>
            ))}
          </ul>
        </section>

        <section className="rounded-lg border border-gray-700 bg-gray-800/50 p-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400">Transcript log</h2>
          {transcript.length === 0 ? (
            <p className="mt-2 text-[11px] text-gray-500">No phrases captured in this session.</p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {transcript.map((t) => (
                <li key={t.id} className="rounded border border-gray-700/70 bg-gray-900/50 px-2.5 py-1.5">
                  <p className="text-[11px] text-gray-300">“{t.text}”</p>
                  <div className="mt-1">
                    <StatusBadge variant={t.matched ? 'COMPLIANT' : 'NOT_APPLICABLE'} label={t.matched ? `→ ${t.matched}` : 'NO MATCH'} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <p className="mt-4 text-[11px] text-gray-500">{FICTIONAL_NOTICE}</p>
    </div>
  );
}
