import re

with open('rag-agentic-dashboard/server.js', 'r') as f:
    content = f.read()

# Pattern to find (_req, res) => { ... req.params ... } or (_req, res) => { ... req.body ... }
# We want to change _req back to req if req is used inside the block.

def replacer(match):
    params = match.group(1)
    body = match.group(2)
    if '_req' in params and ('req.' in body or 'req[' in body):
        return match.group(0).replace('_req', 'req')
    return match.group(0)

# This is a bit complex for a single regex due to nested braces.
# I'll use a simpler approach: check every line where _req is defined and req is used.

lines = content.split('\n')
for i in range(len(lines)):
    line = lines[i]
    if '(_req, res) => {' in line:
        # Check subsequent lines until the next route or end of block
        j = i + 1
        found_req = False
        while j < len(lines) and 'app.' not in lines[j] and '});' not in lines[j]:
            if 'req.' in lines[j] or 'req[' in lines[j]:
                found_req = True
                break
            j += 1
        if found_req:
            lines[i] = lines[i].replace('_req', 'req')

with open('rag-agentic-dashboard/server.js', 'w') as f:
    f.write('\n'.join(lines))
