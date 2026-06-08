import re
import os

path = 'rag-agentic-dashboard/server.js'
with open(path, 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if '(req, res)' in line:
        # Check if req is used in the rest of the line
        # This is a heuristic for one-liners
        parts = line.split('=>', 1)
        if len(parts) > 1:
            body = parts[1]
            if 'req.' not in body and ' req ' not in body and ' req,' not in body and ' req)' not in body:
                print(f"{i+1}: {line.strip()}")
