import sys
from pathlib import Path

path = Path("rag-agentic-dashboard/gen-sentinel-ai-v24.py")
lines = path.read_text().splitlines()
new_lines = []
for line in lines:
    if len(line) > 120 and '"' in line:
        # Simple heuristic to split long strings
        # Find the first quote and if there is a space around 100 chars, split it
        start_quote = line.find('"')
        end_quote = line.rfind('"')
        if start_quote != -1 and end_quote > start_quote:
            content = line[start_quote+1:end_quote]
            if len(content) > 100:
                # Split content
                split_point = content.rfind(' ', 0, 100)
                if split_point == -1: split_point = 100
                head = content[:split_point]
                tail = content[split_point:]
                indent = line[:start_quote]
                new_line = f'{indent}"{head}"\n{indent}"{tail.strip()}"'
                # This only works for certain structures. Let's be safer.
                # Just keep it as is for now or try to wrap it manually for key ones.
                new_lines.append(line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    else:
        new_lines.append(line)

# path.write_text("\n".join(new_lines))
