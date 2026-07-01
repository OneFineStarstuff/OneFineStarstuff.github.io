import { NextRequest } from 'next/server';
import { preFilter, steerPrompt, postModerate } from '@/lib/safety/pipeline';
import { getPrincipal, UNAUTHORIZED } from '@/lib/auth/session';
import { readJson, sanitizeForStream } from '@/lib/http/guard';

export const runtime = 'nodejs';

function* fakeStream(text: string) {
  for (const ch of text) {
    yield { delta: ch };
  }
}

function encode(s: string) {
  return new TextEncoder().encode(s);
}

/**
 * Streams a moderated reply as server-sent events.
 *
 * SECURITY (DASH-05 fixed): if post-moderation returns `block`, the reply is
 * NOT streamed — a safe refusal is emitted instead. The moderation decision is
 * now enforcing, not merely observability. All values embedded in SSE frames are
 * sanitized (DASH-03) to prevent stream/log injection via newlines.
 */
function streamForMessage(message: string) {
  const ctrl = new AbortController();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        const pre = preFilter(message);
        const safePrompt = steerPrompt(message);
        const candidate = `Echo: ${safePrompt}`;
        const post = postModerate(candidate);

        const blocked = post.action === 'block';
        const reply = blocked
          ? 'This request was blocked by the safety policy and cannot be answered.'
          : candidate;

        const meta = {
          layer: 'surface',
          model: 'mock',
          version: '0.0.1',
          latencyMs: 42,
          pre,
          post,
          blocked,
        };
        controller.enqueue(encode(`event: meta\ndata: ${JSON.stringify(meta)}\n\n`));

        for (const chunk of fakeStream(reply)) {
          await new Promise((r) => setTimeout(r, 5));
          const safeDelta = { delta: sanitizeForStream(chunk.delta, 4) };
          controller.enqueue(encode(`event: token\ndata: ${JSON.stringify(safeDelta)}\n\n`));
        }
        controller.enqueue(encode(`event: done\n\n`));
        controller.close();
      } catch {
        controller.enqueue(encode(`event: error\ndata: {"message":"stream_failed"}\n\n`));
        controller.close();
      }
    },
    cancel() {
      ctrl.abort();
    },
  });
  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    },
  });
}

/**
 * POST only (DASH-03 fixed: the unauthenticated GET text-generation path was
 * removed). Requires an authenticated principal and a size-capped JSON body.
 */
export async function POST(req: NextRequest) {
  const principal = getPrincipal(req);
  if (!principal) return UNAUTHORIZED();

  const body = await readJson<{ message?: unknown }>(req);
  if (!body.ok) return new Response(JSON.stringify({ error: body.error }), { status: body.status });

  const message = body.data.message;
  if (typeof message !== 'string' || message.length === 0) {
    return new Response(JSON.stringify({ error: 'message required' }), { status: 400 });
  }
  return streamForMessage(message);
}
