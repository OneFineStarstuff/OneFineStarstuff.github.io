# Issue #167 — CI startup failures from unused starter workflows

## Finding

Failing runs on `main` traced to workflows shipped by GitHub's repository templates,
none of which describe this project's build:

- `.github/workflows/webpack.yml`
- `.github/workflows/jekyll-docker.yml`
- `.github/workflows/nextjs.yml`
- `.github/workflows/deno.yml`
- `.github/workflows/manual.yml`

`nextjs.yml` and `webpack.yml` assume an application at the repository root and a
particular package manager; `jekyll-docker.yml` assumes a Jekyll source; `deno.yml`
and `manual.yml` are generic starters. Each fails on every push, which is why the
Actions tab reads as permanently red and why `startup_failure` appears alongside
genuine step failures.

## Change

Removed: `webpack.yml`, `jekyll-docker.yml`, `nextjs.yml`, `deno.yml`, `manual.yml`.

## Verification

- The remaining repo-specific workflows are untouched: `sentinel-governance-gates.yml`,
  `super-linter.yml`, and the GIEN governance validators.
- This change deletes no build logic that was passing. Every removed workflow was
  already failing on `main`.
- GitHub Pages deployment is unaffected: it is served by the Pages build pipeline,
  not by `jekyll-docker.yml`.

## Follow-up

`super-linter.yml` and `sentinel-governance-gates.yml` still fail on content, not on
configuration, and are tracked under #170.
