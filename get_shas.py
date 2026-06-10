import subprocess
import re

def get_sha(repo, tag):
    try:
        url = f"https://github.com/{repo}"
        # Try dereferenced tag first (for annotated tags)
        cmd = ["git", "ls-remote", "--tags", url, f"refs/tags/{tag}^{{}}"]
        output = subprocess.check_output(cmd, text=True).strip()
        if output:
            return output.split()[0]
        # Fallback to direct tag
        cmd = ["git", "ls-remote", "--tags", url, f"refs/tags/{tag}"]
        output = subprocess.check_output(cmd, text=True).strip()
        if output:
            return output.split()[0]
        # Fallback to searching all tags
        cmd = ["git", "ls-remote", "--tags", url]
        output = subprocess.check_output(cmd, text=True).strip()
        for line in output.split('\n'):
            if f"refs/tags/{tag}" in line:
                return line.split()[0]
    except:
        pass
    return None

actions = {
    "actions/checkout": "v4.2.2",
    "actions/setup-python": "v5.3.0",
    "actions/setup-node": "v4.2.0",
    "actions/upload-artifact": "v4.6.0",
    "actions/labeler": "v5.0.0",
    "actions/cache": "v4.2.0",
    "actions/configure-pages": "v5.0.0",
    "actions/upload-pages-artifact": "v3.0.1",
    "actions/deploy-pages": "v4.0.5",
    "github/codeql-action": "v3.28.10",
    "github/super-linter": "v4.10.1",
    "open-policy-agent/setup-opa": "v2.2.0",
    "ludeeus/action-shellcheck": "2.0.0",
    "denoland/setup-deno": "v1.1.4",
    "docker/setup-buildx-action": "v1.6.0",
    "docker/login-action": "v1.14.1",
    "docker/build-push-action": "v2.10.0",
}

for repo, tag in actions.items():
    sha = get_sha(repo, tag)
    print(f"{repo}: {sha}")
