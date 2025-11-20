import { readFileSync } from 'fs';
import path from 'path';
export const dynamic = 'force-static';
export default function Page() {
  const md = readFileSync(path.join(process.cwd(), 'next-app', 'templates', 'kpi-alignment.md'), 'utf8');
  return <pre className="whitespace-pre-wrap text-sm">{md}</pre>;
}
