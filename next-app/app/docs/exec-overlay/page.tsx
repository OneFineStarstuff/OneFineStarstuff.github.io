import { readFileSync } from 'fs';
import path from 'path';
export const dynamic = 'force-static';
export const metadata = { title: 'Executive Pack Overlay: Deployment Readiness Summary' } as const;
export default function Page() {
  const md = readFileSync(path.join(process.cwd(), 'next-app', 'docs', 'exec-overlay.md'), 'utf8');
  return <pre className="whitespace-pre-wrap text-sm">{md}</pre>;
}
