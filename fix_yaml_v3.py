import os
import re

pins = {
    "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/setup-python": "0b93645e9fea7318ecaed2b359559ac225c90a2b",
    "actions/setup-node": "1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a",
    "actions/upload-artifact": "65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08",
    "actions/labeler": "8558fd74291d67161a8a78ce36a881fa63b766a9",
    "open-policy-agent/setup-opa": "34a30e8a924d1b03ce2cf7abe97250bbb1f332b5",
    "ludeeus/action-shellcheck": "94e4a7d7ca9a4589251034c201409d80d200e007",
    "github/codeql-action/init": "a65a038433a26f4363cf9f029e3b9ceac831ad5d",
    "github/codeql-action/analyze": "a65a038433a26f4363cf9f029e3b9ceac831ad5d",
    "github/super-linter": "454ba4482ce2cd0c505bc592e83c06e1e37ade61",
    "actions/configure-pages": "983d7736d9b0ae728b81ab479565c72886d7745b",
    "actions/upload-pages-artifact": "56afc609e74202658d3ffba0e8f6dda462b719fa",
    "actions/deploy-pages": "d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
    "actions/cache": "1bd1e32a3bdc45362d1e726936510720a7c30a57"
}

def fix_workflow(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        raw = line.rstrip()
        if not raw:
            new_lines.append("\n")
            continue

        # Pinning SHAs first
        for action, sha in pins.items():
            if f"uses: {action}@" in raw:
                indent = raw[:raw.find("uses:")]
                raw = f"{indent}uses: {action}@{sha}"
                break

        # Fixing Indentation
        # steps: (4 spaces)
        #   - name: (6 spaces)
        #     uses: (8 spaces)
        #     with: (8 spaces)
        #       key: (10 spaces)

        # If it starts with "- " at 4 spaces, CodeFactor wants it at 6?
        # "Wrong indentation: expected 10 but found 8" usually means child of 8 is at 8.

        # Simple rule: if line starts with 4 spaces and a dash, it's a step.
        if raw.startswith("    - "):
            raw = "      " + raw[4:]
        elif raw.startswith("      ") and not raw.startswith("        "):
            # This is 6 spaces. If it's a name/uses/run/with under a step, it should be 8.
            # But wait, if step starts at 6, its children should be at 8.
            # My previous replacement moved "- uses" to 6.
            if any(raw.strip().startswith(k) for k in ["name:", "uses:", "run:", "with:", "env:", "if:"]):
                raw = "        " + raw.strip()
        elif raw.startswith("        ") and not raw.startswith("          "):
            # This is 8 spaces. If it's under with: or env:, it should be 10.
            # This is hard to do without state.
            pass

        # Ensuring 2 spaces before comments
        if " #" in raw:
            raw = re.sub(r"([^ ]) #", r"\1  #", raw)

        new_lines.append(raw + "\n")

    with open(filepath, 'w') as f:
        f.writelines(new_lines)

for root, _, files in os.walk('.github/workflows'):
    for file in files:
        if file.endswith('.yml'):
            fix_workflow(os.path.join(root, file))
