const fs = require('fs');
const path = require('path');

const WORKFLOWS_DIR = '.github/workflows';
const SERVER_JS = 'rag-agentic-dashboard/server.js';
const PKG_JSON = 'rag-agentic-dashboard/package.json';

// 1. Precise Action Pinning
const ACTION_MAP = {
    'actions/checkout': '692973e3d937129bcbf40652eb9f2f61becf3332',
    'actions/setup-python': 'f677109307c7a44114705603b30e01c0ad72a39d',
    'actions/setup-node': '1a44421d2379b183610001099a6792610738d8f2',
    'actions/upload-artifact': '65462800fd760344b1a7b4382951275a0abb4808',
    'actions/download-artifact': 'fa0a91b85d4f404e444e00e005971372dec800d1',
    'actions/labeler': '8558fd74291d67161a8a78ce36a881fa63b766a9',
    'github/super-linter': '4483756a815a5f6e80b27902d3345e54d5b27163',
    'ludeeus/action-shellcheck': '94e0a5663708a74e508827f311c818816c1416e8',
    'denoland/setup-deno': '61fe2df320078202e33d7d5ad347e7dcfa0e8f31',
    'open-policy-agent/setup-opa': '790401b7a0f785501861034177727192667d4e32',
    'github/codeql-action/init': '23acc5c56da8f1d67c0558b779d201e5d797c271',
    'github/codeql-action/analyze': '23acc5c56da8f1d67c0558b779d201e5d797c271',
    'docker/setup-buildx-action': '944597f4a0709b9bc0446465693c7d9e1c15433d',
    'docker/login-action': 'dd4fa0671be5250ee6f50aedf4cb05514baad2da',
    'docker/build-push-action': 'ac9327eae2b366085ac7f6a2d02df8aa8ead720a',
    'actions/configure-pages': '1f0c5cde4bc74c01375badad0f946a4993308d16',
    'actions/cache': '0c45773b623bec8c7efd44a0f4691c13d78905c1',
    'actions/upload-pages-artifact': '56afc609e74202658d3ffba0e8f6dee46298ecc2',
    'actions/deploy-pages': 'd6db9015730510f01c9ca7c21b66236e14d1719c'
};

const workflows = fs.readdirSync(WORKFLOWS_DIR).filter(f => f.endsWith('.yml'));
workflows.forEach(file => {
    let content = fs.readFileSync(path.join(WORKFLOWS_DIR, file), 'utf8');
    for (const [action, sha] of Object.entries(ACTION_MAP)) {
        const regex = new RegExp(`uses:\\s*${action}(@[^\\s]*)?`, 'g');
        content = content.replace(regex, `uses: ${action}@${sha}`);
    }
    fs.writeFileSync(path.join(WORKFLOWS_DIR, file), content);
});

// 2. server.js Hardening
let serverContent = fs.readFileSync(SERVER_JS, 'utf8');

// A. Fix ReDoS by replacing keyword regex with safe inclusion checks
serverContent = serverContent.replace(
    /if \(\['govern', 'map', 'measure', 'manage'\]\.every\(k => new RegExp\(k, 'i'\)\.test\(text\)\)\)/g,
    "if (['govern', 'map', 'measure', 'manage'].every(k => text.toLowerCase().includes(k)))"
);
serverContent = serverContent.replace(
    /if \(\['govern', 'map', 'measure', 'manage'\]\.every\(k => text\.toLowerCase\(\)\.includes\(k\.toLowerCase\(\)\)\)\)/g,
    "if (['govern', 'map', 'measure', 'manage'].every(k => text.toLowerCase().includes(k)))"
);

// B. Global Rate Limiting and File Access Protection
// Ensure express-rate-limit is at the top and applied to all routes
serverContent = serverContent.replace(/const rateLimit = require\('express-rate-limit'\);/g, '');
serverContent = serverContent.replace(/const limiter = rateLimit\(\{[\s\S]*?\}\);/g, '');
serverContent = serverContent.replace(/app\.use\(limiter\);/g, '');

const appInitPos = serverContent.indexOf('const app = express();');
if (appInitPos !== -1) {
    const insertPos = serverContent.indexOf('\n', appInitPos) + 1;
    const rateLimitBlock = `\nconst rateLimit = require('express-rate-limit');\nconst limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });\napp.use(limiter);\n`;
    serverContent = serverContent.slice(0, insertPos) + rateLimitBlock + serverContent.slice(insertPos);
}

// C. Resolve Deno Linting (unused req)
// We prefix 'req' with '_' in route handlers where 'req' is not used in the body.
const routeRegex = /app\.(get|post|put|delete)\(['"](.*?)['"],\s*\((req),\s*(res)\)\s*=>/g;
serverContent = serverContent.replace(routeRegex, (match, method, route, req, res) => {
    // This is a simple heuristic: if the body is just res.json(...) or res.sendFile(...), req is usually unused.
    // Or we can just check if 'req.' exists in the line.
    const lineEndPos = serverContent.indexOf('\n', serverContent.indexOf(match));
    const line = serverContent.substring(serverContent.indexOf(match), lineEndPos);
    if (!line.includes('req.')) {
        return `app.${method}('${route}', (_req, res) =>`;
    }
    return match;
});

fs.writeFileSync(SERVER_JS, serverContent);

// 3. package.json Dependencies
const pkg = JSON.parse(fs.readFileSync(PKG_JSON, 'utf8'));
pkg.dependencies['express-rate-limit'] = '^7.5.0';
fs.writeFileSync(PKG_JSON, JSON.stringify(pkg, null, 2) + '\n');

// 4. Netlify Rules Formatting
const headerContent = "/*\n  Cross-Origin-Opener-Policy: same-origin\n  Cross-Origin-Embedder-Policy: require-corp\n";
const redirectContent = "/api/* /api/:splat 200\n/* /index.html 200\n";

fs.writeFileSync('_headers', headerContent);
fs.writeFileSync('_redirects', redirectContent);
fs.writeFileSync('next-app/public/_headers', headerContent);
fs.writeFileSync('next-app/public/_redirects', redirectContent);

// 5. DeepSource Config
const dsContent = `version = 1

[[analyzers]]
name = "python"
enabled = true
  [analyzers.meta]
  runtime_version = "3.x"

[[analyzers]]
name = "javascript"
enabled = true

[[analyzers]]
name = "shell"
enabled = true

[[analyzers]]
name = "docker"
enabled = true
`;
fs.writeFileSync('.deepsource.toml', dsContent);

console.log('Final fixes applied successfully.');
