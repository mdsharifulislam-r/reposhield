# GitHub Actions and branch protection

Use [examples/github-actions-reposhield.yml](../examples/github-actions-reposhield.yml) as a starting point.

## Principles

1. **Scan before you install or build.** `npm install` scripts and build tools execute repository code.
2. Use `actions/checkout` with `fetch-depth: 0` so RepoShield can compare against the base branch.
3. Pin the RepoShield version you have reviewed.
4. Install your own dependencies with `npm ci --ignore-scripts` after the scan passes.
5. Keep `permissions` minimal: `contents: read`, plus `security-events: write` only for SARIF upload.

## SARIF upload

`github/codeql-action/upload-sarif` requires `security-events: write`. Code scanning is available for public repositories and for private repositories with GitHub Code Security enabled. Pull requests from forks receive a read-only token, so the upload step cannot write there; the scan step still fails the job on its own.

## Branch protection (required, or the workflow protects nothing)

A workflow does not block merges by itself. Configure this in the repository settings (admin rights needed; RepoShield never changes repository settings):

1. **Settings → Branches → Add branch protection rule** (or a **ruleset**) for `main` and any release branches.
2. Enable **Require status checks to pass before merging**, then search for and select the **`reposhield`** job (the job name in the workflow). The check appears in the list only after it has run at least once.
3. Enable **Require branches to be up to date before merging**.
4. Enable **Require a pull request before merging** with at least one approval, and **Require review from Code Owners** for `.github/workflows/`, `package.json`, lockfiles, and `.reposhield*` files.
5. Enable **Do not allow bypassing the above settings** so administrators are covered too.

Also remember: a pull request can modify the workflow itself. For `pull_request` events GitHub runs the workflow from the PR branch, so a malicious PR could weaken it. Code owners on `.github/workflows/` and, where available, **required workflows** in an organization ruleset reduce that risk. Do not use `pull_request_target` with a checkout of untrusted code.
