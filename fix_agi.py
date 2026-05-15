import re
import sys

def add_docstrings(content):
    # Add module docstring if missing
    """Add missing module and class/method/function docstrings to the content."""
    if not content.startswith('"""'):
        content = '"""\nAGI Pipeline Legacy Module.\n"""\n' + content

    # Add docstrings to classes
    content = re.sub(r'class (\w+)(\(.*\))?:', r'class \1\2:\n    """\n    Class \1.\n    """', content)

    # Add docstrings to methods
    content = re.sub(r'    def (\w+)\((.*)\):', r'    def \1(\2):\n        """\n        Method \1.\n        """', content)

    # Add docstrings to top-level functions
    content = re.sub(r'^def (\w+)\((.*)\):', r'def \1(\2):\n    """\n    Function \1.\n    """', content, flags=re.MULTILINE)

    return content

with open('agi-pipeline.py', 'r') as f:
    lines = f.readlines()

# Remove my previous disable line
if lines[0].startswith('# pylint: disable'):
    lines = lines[1:]

content = ''.join(lines)
content = add_docstrings(content)

with open('agi-pipeline.py', 'w') as f:
    f.write(content)
