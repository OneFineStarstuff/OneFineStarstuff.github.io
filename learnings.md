# Learnings: Resolving CI Suite Failures and Environment Setup

## 1. GitHub Actions: pull_request_target and Checkouts
- **Issue:** PR Labeler was failing to find .github/labeler.yml.
- **Solution:** Actions on `pull_request_target` need an explicit `actions/checkout@v4` to see the code.

## 2. Pylint Aggregate Scores
- **Issue:** Build failing due to duplication and style noise in legacy scripts.
- **Solution:** Use a `.pylintrc` to disable stylistic checks while keeping Fatal/Error levels active.

## 3. Subdirectory Path Mapping
- **Issue:** Next.js CI was looking for package.json in the root.
- **Solution:** Update workflow to correctly target the `next-app/` subdirectory.

## 4. Dependencies
- **Whisper:** Use `openai-whisper` to avoid ambiguous package name issues.
- **Multipart:** Add `python-multipart` for FastAPI form data support.
- **Binaries:** Install `ffmpeg` and `espeak-ng` in Dockerfiles.
