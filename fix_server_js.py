import re

path = 'rag-agentic-dashboard/server.js'
with open(path, 'r') as f:
    content = f.read()

# Pattern: (req, res) => ...
# We want to replace it with (_req, res) => ... IF 'req' is not used in the body.
# For simplicity in this large file, many routes are one-liners: (req, res) => res.json(...)
# I'll target those first.

new_content = re.sub(r'\(req, res\) => res\.', '(_req, res) => res.', content)
new_content = re.sub(r'\(req, res\) => {', '(_req, res) => {', new_content)

# Note: This might over-replace if req IS used in a block.
# But the linter specifically complained about those that ARE NOT used.
# Let's refine: Only replace if "req" does not appear in the next 50 chars?
# Actually, the routes that USE req usually use req.params or req.body.

# Let's try to be a bit smarter.
def replacer(match):
    full = match.group(0)
    # Check if 'req' (not followed by anything) is used in the following characters?
    # This is getting complex. Let's just fix the ones that specifically failed or are obvious.
    return full.replace('(req, res)', '(_req, res)')

# Re-run the sed but more carefully for common patterns
