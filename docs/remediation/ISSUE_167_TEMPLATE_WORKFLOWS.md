# Issue #167 — CI startup failures from unused starter workflows

## Finding

Failing runs on main traced to workflows shipped by GitHub repository templates, none of which describe the current project's build:

- .github/workflows/webpack.yml
- .github/workflows/jekyll-docker.yml
- .github/workflows/nextjs.yml
- .github/workflows/deno.yml
- .github/workflows/manual.yml

These files are generic starter pipelines. They assume root-level webpack/Next.js/Jekyll/Deno applications or generic manual inputs that are not the repository's canonical build targets. Their failures add noise to the Actions view and can make required-check selection ambiguous.

## Change

Removed the five unused starter workflows listed above. No application build, governance validator, or deployment workflow is replaced by this change.

## Verification requirements

- Confirm the remaining repository-specific workflows still cover the intended targets, including Sentinel Governance Gates and the path-scoped GIEN platform/API workflows.
- Confirm GitHub Pages behavior through the repository's actual Pages configuration rather than inferring it from a deleted template.
- Check that no ruleset or branch protection still requires the deleted starter workflow names as status checks.
- Inspect the first post-merge push and pull-request runs before marking the cleanup complete.

## Limitations

This change removes five known template workflows only. It does not claim that all workflow noise has been eliminated, nor that all remaining CI failures are resolved. External checks such as Vercel, pre-commit.ci, DeepSource and Codeac require separate inspection and acceptance.
