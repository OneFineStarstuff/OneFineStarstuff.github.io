import re

with open('rag-agentic-dashboard/server.js', 'r') as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    # Fix the broken evaluation logic line
    if "if (/govern-map-measure-manage)');" in line:
        line = "    if (/govern|map|measure|manage/i.test(text)) domainEvidence.push('NIST AI RMF functions enumerated (Govern, Map, Measure, Manage)');\n"

    # Fix slow regex in line 540 and 550
    line = line.replace("/govern(ance)?/i", "/govern/i")
    line = line.replace("/govern(ance)?|compliance/i", "/govern|compliance/i")

    new_lines.append(line)

content = "".join(new_lines)

# Ensure rate limiting is present and correct
if "const rateLimit = require('express-rate-limit');" not in content:
    content = content.replace("const express = require('express');", "const express = require('express');\nconst rateLimit = require('express-rate-limit');")

if "const limiter = rateLimit" not in content:
    # Insert after app initialization
    content = re.sub(r"(const app = express\(\);)", r"\1\nconst limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });\napp.use('/api/', limiter);", content)

with open('rag-agentic-dashboard/server.js', 'w') as f:
    f.write(content)
