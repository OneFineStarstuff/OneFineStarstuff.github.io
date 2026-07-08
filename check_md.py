import re

with open('docs/reports/DAILY_GIEN_DEVSECOPS_DOSSIER_V2.4.md', 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    # MD013: 120 char limit
    if len(line.rstrip()) > 120:
        print(f"Line {i+1} too long: {len(line.rstrip())} chars")

    # MD030: One space after list marker
    match = re.match(r'^(\s*[-*+]|\s*\d+\.)(\s+)', line)
    if match:
        if len(match.group(2)) != 1:
            print(f"Line {i+1} MD030 violation: '{match.group(2)}' spaces after marker")
