const https = require('https');
const token = process.env.GITHUB_TOKEN;
if (!token) { console.error('Missing GITHUB_TOKEN'); process.exit(1); }
const data = JSON.stringify({
  title: 'Sprint A: Governance Capability Matrix, Strategy Map, Templates',
  head: 'genspark_ai_developer',
  base: 'main',
  body: `This PR delivers Sprint A items:\n\n- Governance Capability Matrix UI reading data/maturity.json (score badges, gates, evidence/gaps, remediation, deep links)\n- Strategy Map (Mermaid) docs page\n- Templates: KPI Alignment and Pilot Charter, plus routes\n- Cockpit nav updated to link the matrix\n\nTesting:\n- Build pages under /governance/maturity, /docs/strategy-map, /templates/kpi-alignment, /templates/pilot-charter\n- All files are static/SSR-friendly (force-static used for file reads)\n\nNext:\n- /api/governance/events (hash-chained audit) + RBAC guards\n- Observability (OTel/PostHog), Auth (NextAuth), provider adapters (OpenAI/Anthropic)`,
  maintainer_can_modify: true
});
const opts = {
  hostname: 'api.github.com',
  path: '/repos/OneFineStarstuff/OneFineStarstuff.github.io/pulls',
  method: 'POST',
  headers: {
    'User-Agent': 'genspark-ai-developer-bot',
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data)
  }
};
const req = https.request(opts, res => {
  let b='';
  res.on('data', c => b+=c);
  res.on('end', () => {
    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
      const j = JSON.parse(b);
      console.log('PR_URL=' + j.html_url);
    } else {
      console.error('PR create failed', res.statusCode, b);
      process.exit(2);
    }
  });
});
req.on('error', e => { console.error(e); process.exit(3); });
req.write(data); req.end();
