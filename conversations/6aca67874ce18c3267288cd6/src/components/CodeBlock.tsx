import { Check, Copy } from 'lucide-react';
import { useState } from 'react';

export default function CodeBlock({
  code,
  language = 'text',
  maxHeight = 'max-h-80',
}: {
  code: string;
  language?: string;
  maxHeight?: string;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className={`relative overflow-hidden rounded-md border border-gray-700 bg-gray-950 ${maxHeight} overflow-y-auto`}>
      <div className="flex items-center justify-between border-b border-gray-800 bg-gray-900/80 px-3 py-1.5">
        <span className="font-mono text-[10px] uppercase tracking-wider text-gray-500">{language}</span>
        <button
          type="button"
          onClick={copy}
          aria-label="Copy code to clipboard"
          className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-gray-400 hover:bg-gray-800 hover:text-gray-200"
        >
          {copied ? <Check size={11} /> : <Copy size={11} />}
          {copied ? 'COPIED' : 'COPY'}
        </button>
      </div>
      <pre className="overflow-x-auto p-3 font-mono text-xs leading-relaxed text-gray-300">
        <code>{code}</code>
      </pre>
    </div>
  );
}
