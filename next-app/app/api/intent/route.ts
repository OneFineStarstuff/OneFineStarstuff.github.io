export const runtime = 'edge';
export async function POST(req: Request) {
  const { message } = await req.json();
  const intent = /simulate|prove|optimize|model/i.test(message) ? 'analytical' : 'casual';
  return new Response(JSON.stringify({ intent }), { headers: { 'content-type': 'application/json' } });
}
