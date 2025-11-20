import { readFileSync } from 'fs';
import path from 'path';
export const dynamic = 'force-static';
/**
 * Renders the content of a markdown file as preformatted text.
 */
export default function Page() {
  const md = readFileSync(path.join(process.cwd(), 'next-app', 'docs', 'governance-terms-mapping.md'), 'utf8');
  return <pre className="whitespace-pre-wrap text-sm">{md}</pre>;
}
