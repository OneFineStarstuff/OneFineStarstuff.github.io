import process from 'node:process'
import crypto from 'crypto'
import fs from 'fs/promises'
import { basename, resolve } from 'path'

export type ConsentAction = 'persist_on' | 'persist_off' | 'export'
export type ConsentEvent = {
  userId: string
  sessionId?: string
  action: ConsentAction
  ts: string
  prevHash?: string
  hash?: string
}

const DATA_DIR = resolve(process.cwd(), 'next-app', '.data', 'consent')

/**
 * Ensures the path is safe and within the designated data directory.
 */
function getSafeChainFile (userId: string): string {
  const sanitized = userId.replace(/[^a-zA-Z0-9_-]/g, '')
  const safeId = basename(sanitized)
  if (!safeId || safeId !== sanitized) {
    throw new Error('Invalid user ID format')
  }
  const filePath = resolve(DATA_DIR, `${safeId}.jsonl`)
  if (!filePath.startsWith(DATA_DIR)) {
    throw new Error('Security Error: Path traversal attempt blocked')
  }
  return filePath
}

export async function appendConsentEvent (e: Omit<ConsentEvent, 'hash' | 'prevHash'>) {
  await fs.mkdir(DATA_DIR, { recursive: true })
  const chainFile = getSafeChainFile(e.userId)
  let prevHash: string | undefined
  try {
    const last = await tailLastLine(chainFile)
    if (last) {
      prevHash = JSON.parse(last).hash
    }
  } catch (err) {
    console.error('Failed to read previous hash:', err)
  }
  const event: ConsentEvent = {
    ...e,
    prevHash,
    ts: e.ts ?? new Date().toISOString()
  }
  event.hash = hashEvent(event)
  await fs.appendFile(chainFile, JSON.stringify(event) + '\n', 'utf8')
  return event
}

export function hashEvent (e: ConsentEvent) {
  const s = `${e.userId}|${e.sessionId ?? ''}|${e.action}|${e.ts}|${e.prevHash ?? ''}`
  return crypto.createHash('sha256').update(s).digest('hex')
}

export async function exportConsent (userId: string) {
  const chainFile = getSafeChainFile(userId)
  try {
    const raw = await fs.readFile(chainFile, 'utf8')
    const events = raw
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as ConsentEvent)
    return { events, root: events.at(-1)?.hash }
  } catch (e: any) {
    if (e.code === 'ENOENT') {
      return { events: [], root: undefined }
    }
    throw e
  }
}

async function tailLastLine (file: string): Promise<string | null> {
  try {
    const data = await fs.readFile(file, 'utf8')
    const lines = data.trim().split('\n')
    return lines.length ? lines[lines.length - 1] : null
  } catch (e: any) {
    if (e.code === 'ENOENT') {
      return null
    }
    throw e
  }
}
