import os
import re

pins = {
    "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/setup-python": "0b93645e9fea7318ecaed2b359559ac225c90a2b",
    "actions/setup-node": "1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a",
    "actions/upload-artifact": "65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08",
    "actions/labeler": "8558fd74291d67161a8a78ce36a881fa63b766a9",
    "github/codeql-action/init": "a65a038433a26f4363cf9f029e3b9ceac831ad5d",
    "github/codeql-action/analyze": "a65a038433a26f4363cf9f029e3b9ceac831ad5d",
    "github/super-linter": "454ba4482ce2cd0c505bc592e83c06e1e37ade61",
    "open-policy-agent/setup-opa": "3d1284a7e8027725914bca15554477dd762a938",
    "ludeeus/action-shellcheck": "94e4a7d7ca9a4589251034c201409d80d200e007",
    "actions/configure-pages": "983d7736d9b0ae728b81ab479565c72886d7745b",
    "actions/upload-pages-artifact": "56afc609e74202658d3ffba0e8f6dda462b719fa",
    "actions/deploy-pages": "d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
    "actions/cache": "1bd1e32a3bdc45362d1e726936510720a7c30a57",
}

def fix_workflow(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            new_lines.append("\n")
            continue

        # Fix indentation for keys under steps
        # If it starts with - uses: or - name: at 6 spaces (index 6)
        # Then following keys (with:, run:, uses:) should be at 8 spaces.
        if line.startswith("      uses:") or line.startswith("      with:") or line.startswith("      run:") or line.startswith("      name:"):
            # This is likely a step child but at wrong indentation
            line = "        " + line.strip() + "\n"

        # Pinning SHAs
        for action, sha in pins.items():
            if f"uses: {action}@" in line:
                indent = line[:line.find("uses:")]
                line = f"{indent}uses: {action}@{sha}\n"
                break

        # Ensure 2 spaces before comments
        if " #" in line:
            line = re.sub(r"([^ ]) #", r"\1  #", line)

        new_lines.append(line)

    with open(filepath, 'w') as f:
        f.writelines(new_lines)

for root, _, files in os.walk('.github/workflows'):
    for file in files:
        if file.endswith('.yml'):
            fix_workflow(os.path.join(root, file))
