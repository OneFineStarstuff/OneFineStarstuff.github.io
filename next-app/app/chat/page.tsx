"use client";
import { useEffect, useRef, useState } from 'react';
import { ProvenanceBadge } from '@/components/ProvenanceBadge';

/**
 * Renders the chat page interface and handles message sending and streaming.
 *
 * The function manages the state for user input, messages, and streaming status. It sets up an EventSource to listen for incoming messages and updates the message list accordingly. It also handles fallback scenarios and cleans up the EventSource on component unmount.
 *
 * @returns {JSX.Element} The rendered chat page component.
 */
export default function ChatPage() {
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<{ role: 'user'|'assistant'; content: string; meta?: any }[]>([]);
  const [streaming, setStreaming] = useState(false);
  const [fallback, setFallback] = useState(false);
  const eventSrc = useRef<EventSource | null>(null);

  const send = async () => {
    if (!input.trim() || streaming) return;
    const userMsg = { role: 'user' as const, content: input };
    setMessages(m => [...m, userMsg, { role: 'assistant', content: '' }]);
    setInput("");
    setStreaming(true);
    const es = new EventSource(`/api/chat/stream?q=${encodeURIComponent(userMsg.content)}&s=${Date.now()}` , { withCredentials: false });
    eventSrc.current = es;

    es.addEventListener('token', (e: MessageEvent) => {
      const data = JSON.parse(e.data);
      setMessages(m => {
        const copy = [...m];
        const idx = copy.length - 1; // last assistant
        copy[idx] = { ...copy[idx], content: (copy[idx].content || '') + data.delta };
        return copy;
      });
    });

    es.addEventListener('meta', (e: MessageEvent) => {
      const meta = JSON.parse(e.data);
      if (meta.fallback) setFallback(true);
      setMessages(m => {
        const copy = [...m];
        const idx = copy.length - 1;
        copy[idx] = { ...copy[idx], meta };
        return copy;
      });
    });

    es.addEventListener('done', () => { setStreaming(false); es.close(); eventSrc.current = null; });
    es.addEventListener('error', () => { setStreaming(false); es.close(); eventSrc.current = null; });

    // Using GET-only SSE with query payload; no POST body needed
  };

  useEffect(() => () => { eventSrc.current?.close(); }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Chat <span className="text-xs align-middle text-slate-500">(ephemeral by default)</span></h1>
      <div className="rounded border bg-white p-3">
        <div className="space-y-3" role="log" aria-live="polite">
          {messages.map((m, i) => (
            <div key={i} className={m.role === 'user' ? 'text-right' : 'text-left'}>
              <div className={"inline-block max-w-[80%] rounded px-3 py-2 " + (m.role==='user'?'bg-amber-100':'bg-slate-100')}>
                <div className="whitespace-pre-wrap">{m.content}</div>
                {m.role==='assistant' && m.meta && (
                  <div className="mt-1"><ProvenanceBadge meta={m.meta} /></div>
                )}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <input value={input} onChange={e=>setInput(e.target.value)} className="flex-1 rounded border px-3 py-2" placeholder="Type a message..." />
          <button onClick={send} disabled={streaming} className="rounded bg-amber-600 px-4 py-2 text-white disabled:opacity-50">Send</button>
          {fallback && <span className="text-xs text-slate-500">Fallback in use</span>}
          <a href="/api/consent?userId=demo" target="_blank" className="text-xs text-amber-700 underline">Export consent ledger</a>
        </div>
      </div>
    </div>
  );
}
