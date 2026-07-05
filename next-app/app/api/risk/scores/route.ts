export const runtime = 'nodejs';

/**
 * Returns a mock time-series risk per layer.
 *
 * SECURITY/COMPLIANCE (DASH-04 fixed): this is SYNTHETIC demo data, not a
 * validated model output. The payload is explicitly flagged so the UI can render
 * a "DEMO DATA" banner and no consumer mistakes it for an SR 11-7 model result.
 * When wired to the real SARA/ACR + SRC-1 proof feeds, set `synthetic: false`.
 */
export function GET() {
  const now = Date.now();
  const series = ['core', 'operational', 'context'].map((k, i) => ({
    key: k,
    points: Array.from({ length: 12 }, (_, j) => ({
      t: now - (11 - j) * 3600_000,
      v: clamp(0, 100, 30 + i * 20 + Math.sin(j / 2 + i) * 15 + Math.random() * 10),
    })),
  }));
  return Response.json({
    synthetic: true,
    disclaimer: 'DEMO DATA — synthetic risk series, not a validated model output (see DASH-04).',
    generatedAt: new Date(now).toISOString(),
    series,
  });
}

/** Clamps a value between a minimum and maximum range. */
function clamp(min: number, max: number, v: number) {
  return Math.max(min, Math.min(max, v));
}
