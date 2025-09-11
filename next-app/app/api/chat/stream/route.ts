import { NextRequest } from 'next/server';

export const runtime = 'nodejs';

function* fakeStream(text: string) {
  for (const ch of text) {
    yield { delta: ch };
  }
}

export async function POST(req: NextRequest) {
  const { message } = await req.json();
  const ctrl = new AbortController();
  const stream = new ReadableStream({
    async start(controller) {
      try {
        const reply = `Echo: ${message}`;
        const meta = { layer: 'surface', model: 'mock', version: '0.0.1', latencyMs: 42 };
        controller.enqueue(encode(`event: meta\ndata: ${JSON.stringify(meta)}\n\n`));
        for (const chunk of fakeStream(reply)) {
          await new Promise(r => setTimeout(r, 10));
          controller.enqueue(encode(`event: token\ndata: ${JSON.stringify(chunk)}\n\n`));
        }
        controller.enqueue(encode(`event: done\n\n`));
        controller.close();
      } catch (e) {
        controller.enqueue(encode(`event: error\ndata: {"message":"stream_failed"}\n\n`));
        controller.close();
      }
    },
    cancel() { ctrl.abort(); }
  });
  return new Response(stream, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' } });
}

export async function GET() {
  // Keep the SSE connection open; body is ignored, we stream via POST response
  const stream = new ReadableStream({ start(){} });
  return new Response(stream, { headers: { 'Content-Type': 'text/event-stream' } });
}

function encode(s: string) { return new TextEncoder().encode(s); }
