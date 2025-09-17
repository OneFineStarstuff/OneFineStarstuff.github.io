import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

export type ConsentAction = 'persist_on' | 'persist_off' | 'export';
export type ConsentEvent = { userId: string; sessionId?: string; action: ConsentAction; ts: string; prevHash?: string; hash?: string };

const DATA_DIR = path.join(process.cwd(), 'next-app', '.data', 'consent');

export async function appendConsentEvent(e: Omit<ConsentEvent, 'hash' | 'prevHash'>) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const chainFile = path.join(DATA_DIR, `${e.userId}.jsonl`);
  let prevHash: string | undefined;
  try {
    const last = await tailLastLine(chainFile);
    if (last) prevHash = JSON.parse(last).hash;
  } catch {}
  const event: ConsentEvent = { ...e, prevHash, ts: e.ts ?? new Date().toISOString() };
  event.hash = hashEvent(event);
  await fs.appendFile(chainFile, JSON.stringify(event) + '\n', 'utf8');
  return event;
}

export function hashEvent(e: ConsentEvent) {
  const s = `${e.userId}|${e.sessionId ?? ''}|${e.action}|${e.ts}|${e.prevHash ?? ''}`;
  return crypto.createHash('sha256').update(s).digest('hex');
}

export async function exportConsent(userId: string) {
  const chainFile = path.join(DATA_DIR, `${userId}.jsonl`);
  try {
    const raw = await fs.readFile(chainFile, 'utf8');
    const events = raw.trim().split('\n').map((l) => JSON.parse(l) as ConsentEvent);
    return { events, root: events.at(-1)?.hash };
  } catch (e: any) {
    if (e.code === 'ENOENT') return { events: [], root: undefined };
    throw e;
  }
}

async function tailLastLine(file: string): Promise<string | null> {
  try {
    const data = await fs.readFile(file, 'utf8');
    const lines = data.trim().split('\n');
    return lines.length ? lines[lines.length - 1] : null;
  } catch (e: any) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}
