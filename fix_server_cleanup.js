const fs = require('fs');
const path = 'rag-agentic-dashboard/server.js';
let content = fs.readFileSync(path, 'utf8');

// Remove all rate limit related lines
content = content.replace(/const rateLimit = require\('express-rate-limit'\);/g, '');
content = content.replace(/\/\/ -- Rate Limiting --[\s\S]*?app\.use\(limiter\);/g, '');
content = content.replace(/\/\/ ── Rate Limiting ──[\s\S]*?app\.use\(limiter\);/g, '');
content = content.replace(/const limiter = rateLimit\(\{[\s\S]*?\}\);/g, '');
content = content.replace(/app\.use\(limiter\);/g, '');

// Now add it once properly
const appInitIdx = content.indexOf('const app = express();');
if (appInitIdx !== -1) {
  const insertPos = content.indexOf('\n', appInitIdx) + 1;
  const rateLimitCode = "\nconst rateLimit = require('express-rate-limit');\n" +
    "const limiter = rateLimit({\n" +
    "  windowMs: 15 * 60 * 1000,\n" +
    "  max: 100,\n" +
    "  standardHeaders: true,\n" +
    "  legacyHeaders: false,\n" +
    "});\n" +
    "app.use(limiter);\n";
  content = content.slice(0, insertPos) + rateLimitCode + content.slice(insertPos);
}

// Ensure fs is only required once
content = content.replace(/const fs = require\('fs'\);/g, '');
const pathReqIdx = content.indexOf("const path = require('path');");
if (pathReqIdx !== -1) {
    const insertPos = content.indexOf('\n', pathReqIdx) + 1;
    content = content.slice(0, insertPos) + "const fs = require('fs');\n" + content.slice(insertPos);
}

fs.writeFileSync(path, content);
