import re

with open('rag-agentic-dashboard/server.js', 'r') as f:
    content = f.read()

# Fix the broken line
content = content.replace("if (/govern-map-measure-manage)');", "if (/govern/i.test(text)) domainEvidence.push('NIST AI RMF functions enumerated (Govern, Map, Measure, Manage)');")

# Fix slow regexes
content = content.replace("/govern(ance)?/i", "/govern/i")
content = content.replace("/govern(ance)?|compliance/i", "/govern|compliance/i")

# Ensure rate limit is active
if "const rateLimit = require('express-rate-limit');" not in content:
    content = content.replace("const express = require('express');", "const express = require('express');\nconst rateLimit = require('express-rate-limit');")
    content = content.replace("const app = express();", "const app = express();\nconst limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });\napp.use('/api/', limiter);")

with open('rag-agentic-dashboard/server.js', 'w') as f:
    f.write(content)
