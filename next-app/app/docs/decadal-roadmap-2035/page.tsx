import process from "node:process";
import process from 'node:process';
import { readFileSync } from 'fs';
import path from 'path';

export const dynamic = 'force-static';

export default function Page() {
  const md = readFileSync(path.join(process.cwd(), 'docs', 'decadal-roadmap-2035.md'), 'utf8');
  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="prose dark:prose-invert">
        <pre className="whitespace-pre-wrap text-sm font-sans">{md}</pre>
      </div>
    </div>
  );
}
