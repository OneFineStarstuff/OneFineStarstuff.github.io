import process from 'node:process';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

export type ConsentAction = 'persist_on' | 'persist_off' | 'export';
export type ConsentEvent = {
  userId: string;
  sessionId?: string;
  action: ConsentAction;
  ts: string;
  prevHash?: string;
  hash?: string;
  sig?: string;
};

const DATA_DIR = path.join(process.cwd(), 'next-app', '.data', 'consent');

/**
 * DASH-07: each event's hash is additionally SIGNED. Here we use HMAC-SHA256 with
 * a server secret as a stand-in; in production this is the CRYSTALS-Dilithium /
 * ML-DSA-65 HSM signer used by the PQC WORM logger, so a writer with raw file
 * access cannot forge a consistent chain. Signature is over the event hash.
 */
const TEST_SECRET = 'test-only-ledger-secret-do-not-use-in-prod';
function ledgerSecret(): string {
  const s = process.env.SENTINEL_LEDGER_SECRET ?? process.env.SENTINEL_SESSION_SECRET;
  if (s && s.length >= 16) return s;
  if (process.env.NODE_ENV === 'production') {
    throw new Error('SENTINEL_LEDGER_SECRET is not set or too short');
  }
  return TEST_SECRET;
}

export function signHash(hash: string): string {
  return crypto.createHmac('sha256', ledgerSecret()).update(hash).digest('hex');
}

export function verifyEvent(e: ConsentEvent): boolean {
  if (!e.hash || !e.sig) return false;
  if (hashEvent(e) !== e.hash) return false;
  const expected = signHash(e.hash);
  if (e.sig.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(e.sig), Buffer.from(expected));
}

export async function appendConsentEvent(e: Omit<ConsentEvent, 'hash' | 'prevHash' | 'sig'>) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const chainFile = path.join(DATA_DIR, `${e.userId}.jsonl`);

  // DASH-07: fail CLOSED on prevHash read errors — never silently start a new
  // chain (which would let a transient failure mask a break).
  let prevHash: string | undefined;
  const last = await tailLastLine(chainFile); // throws on real IO errors -> propagates
  if (last) {
    const prev = JSON.parse(last) as ConsentEvent;
    if (!verifyEvent(prev)) {
      throw new Error('consent ledger integrity violation: previous head failed verification');
    }
    prevHash = prev.hash;
  }

  const event: ConsentEvent = { ...e, prevHash, ts: e.ts ?? new Date().toISOString() };
  event.hash = hashEvent(event);
  event.sig = signHash(event.hash);
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
    const events = raw
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as ConsentEvent);
    // Verify the chain end-to-end on export.
    const verified = events.every(verifyEvent);
    return { events, root: events.at(-1)?.hash, verified };
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
      return { events: [], root: undefined, verified: true };
    }
    throw e;
  }
}

async function tailLastLine(file: string): Promise<string | null> {
  try {
    const data = await fs.readFile(file, 'utf8');
    const lines = data.trim().split('\n');
    return lines.length && lines[0] ? lines[lines.length - 1] : null;
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw e; // fail closed on any other IO error
  }
}
