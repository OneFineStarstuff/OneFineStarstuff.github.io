export const runtime = 'nodejs';
/**
 * Handles the GET request and returns a mock time-series risk per layer.
 */
export async function GET() {
  // Mock time-series risk per layer: core/operational/context
  const now = Date.now();
  const series = ['core','operational','context'].map((k, i) => ({
    key: k,
    points: Array.from({ length: 12 }, (_, j) => ({ t: now - (11 - j) * 3600_000, v: clamp(0, 100, 30 + i*20 + Math.sin(j/2+i)*15 + Math.random()*10) }))
  }));
  return Response.json({ series });
}
/**
 * Clamps a value between a minimum and maximum range.
 */
function clamp(min:number,max:number,v:number){return Math.max(min,Math.min(max,v));}
