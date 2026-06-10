import re

with open('rag-agentic-dashboard/server.js', 'r') as f:
    content = f.read()

# Fix broken logic
content = content.replace("if (/govern-map-measure-manage)');", "if (/govern/i.test(text)) domainEvidence.push('NIST AI RMF functions enumerated (Govern, Map, Measure, Manage)');")

# Fix slow regexes
content = content.replace("/govern(ance)?/i", "/govern/i")
content = content.replace("/govern(ance)?|compliance/i", "/govern|compliance/i")

# Rate limiting for ALL routes
if "const rateLimit = require('express-rate-limit');" not in content:
    content = "const express = require('express');\nconst rateLimit = require('express-rate-limit');\n" + content.split("const express = require('express');", 1)[1]

if "const limiter = rateLimit" not in content:
    content = content.replace("const app = express();", "const app = express();\nconst limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });\napp.use(limiter);")
else:
    # Ensure it's applied to all routes
    content = content.replace("app.use('/api/', limiter);", "app.use(limiter);")

# Rename unused req
content = re.sub(r'\(req, res\) => res\.json', r'(_req, res) => res.json', content)
content = re.sub(r'app\.get\(\'([^\']+)\', \(req, res\) => \{', r"app.get('\1', (_req, res) => {", content)

with open('rag-agentic-dashboard/server.js', 'w') as f:
    f.write(content)
