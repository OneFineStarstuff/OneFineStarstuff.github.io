/**
 * A1 (WP-114): cryptographically seeded randomness replacement.
 * Derived data must be either fully deterministic (replayable) or
 * crypto-seeded (unpredictable attestations); Math.random is neither.
 */
export function cryptoRandom(): number {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('Web Crypto unavailable; inject a deterministic seeded generator for tests/replay.');
  }
  const u = new Uint32Array(1);
  crypto.getRandomValues(u);
  return u[0] / 4294967296;
}

/** Random hex seed, 2*bytes chars. Add the 0x prefix at the call site if required. */
export function cryptoSeed(bytes = 32): string {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('Web Crypto unavailable.');
  }
  const raw = new Uint8Array(bytes);
  crypto.getRandomValues(raw);
  return Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join('');
}
