import re

path = 'rag-agentic-dashboard/server.js'
with open(path, 'r') as f:
    content = f.read()

# Find all blocks like (_req, res) => { ... } and check if 'req.' is used inside
def restore_req(match):
    params = match.group(1)
    body = match.group(2)
    if 'req.' in body:
        return f"(req, res) => {body}"
    return match.group(0)

# This regex targets the pattern I applied earlier
new_content = re.sub(r'\(_req, res\) => ({[^}]+})', restore_req, content)

with open(path, 'w') as f:
    f.write(new_content)
