const fs = require('fs');
const path = 'rag-agentic-dashboard/server.js';
let content = fs.readFileSync(path, 'utf8');

// 1. Move rate limiter to the very top (after app initialization)
// First, remove existing rate limit blocks to avoid duplicates
content = content.replace(/\/\/ -- Rate Limiting --[\s\S]*?app\.use\(limiter\);/g, '');
content = content.replace(/const rateLimit = require\('express-rate-limit'\);\nconst fs = require\('fs'\);/g, '');
content = content.replace(/const rateLimit = require\('express-rate-limit'\);/g, '');

// Now add it at the top
const appInitIdx = content.indexOf('const app = express();');
if (appInitIdx !== -1) {
  const insertPos = content.indexOf('\n', appInitIdx) + 1;
  const rateLimitCode = "\nconst rateLimit = require('express-rate-limit');\n" +
    "const limiter = rateLimit({\n" +
    "  windowMs: 15 * 60 * 1000, // 15 minutes\n" +
    "  max: 100, // Limit each IP to 100 requests per window\n" +
    "  standardHeaders: true,\n" +
    "  legacyHeaders: false,\n" +
    "});\n" +
    "app.use(limiter);\n";
  content = content.slice(0, insertPos) + rateLimitCode + content.slice(insertPos);
}

// 2. Fix ReDoS in regex
// Search for the problematic regex and replace it with a safe inclusion check
content = content.replace(
  /if \(\['govern', 'map', 'measure', 'manage'\]\.every\(k => new RegExp\(k, 'i'\)\.test\(text\)\)\)/g,
  "if (['govern', 'map', 'measure', 'manage'].every(k => text.toLowerCase().includes(k.toLowerCase())))"
);

fs.writeFileSync(path, content);
