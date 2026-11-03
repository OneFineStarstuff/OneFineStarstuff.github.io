// Deterministic fictional-data generators.
// Every hash is a stable 0x + 64-char hex string derived from a seed.

export function fakeHash(seed: string): string {
  let h = 2166136261 >>> 0;
  let out = '';
  for (let i = 0; i < 64; i++) {
    h ^= seed.charCodeAt(i % seed.length) + i * 31;
    h = Math.imul(h, 16777619) >>> 0;
    out += ((h >>> ((i % 4) * 4)) % 16).toString(16);
  }
  return '0x' + out;
}

export function truncateHash(hash: string, lead = 10, tail = 6): string {
  if (hash.length <= lead + tail + 3) return hash;
  return `${hash.slice(0, lead)}...${hash.slice(-tail)}`;
}

// Deterministic 24-point series around a base value, amplitude in absolute units.
export function series(seed: string, base: number, amp: number, points = 24): number[] {
  let s = 0;
  for (let i = 0; i < seed.length; i++) s = (s * 31 + seed.charCodeAt(i)) >>> 0;
  const out: number[] = [];
  for (let i = 0; i < points; i++) {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    const w = (s % 1000) / 1000 - 0.5; // -0.5..0.5
    out.push(Math.max(0, +(base + w * 2 * amp).toFixed(4)));
  }
  out[points - 1] = +base.toFixed(4);
  return out;
}

// Truncated PQC signature display.
export function fakeSignature(seed: string): string {
  return truncateHash(fakeHash(seed + ':sig'), 12, 8);
}
