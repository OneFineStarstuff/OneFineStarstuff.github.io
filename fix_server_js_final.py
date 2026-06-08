import re

path = 'rag-agentic-dashboard/server.js'
with open(path, 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    # If line has (_req, res) but also uses 'req.' later in the same line
    if '(_req, res)' in line and 'req.' in line:
        line = line.replace('(_req, res)', '(req, res)')
    # If it's a multi-line block, this is harder.
    # But many are single lines or the req use is on the same line.
    new_lines.append(line)

with open(path, 'w') as f:
    f.writelines(new_lines)
