# Remediation guide

RepoShield only reports and plans. It never changes your repository. If a finding looks real, treat the repository and every machine that ran it as potentially compromised until proven otherwise.

## 1. Contain

- Do **not** run `npm install`, build, test, or start commands in the affected checkout.
- Work on a copy or fresh clone; keep the original for evidence.
- Run `reposhield-scan recovery inspect` to list affected files, the suspect commit, and diff context.

## 2. Review (do not execute)

- Read the flagged code as text. Decode encoded strings as text only.
- `git log -p -- <file>` and `git blame <file>` to find who introduced it and when. Check whether the author or commit looks genuine (author, signature, unusual timing).
- Compare with the last trusted commit (`reposhield-scan baseline` records one).

## 3. Revert, carefully

Suggested plans from RepoShield (run them yourself, after reviewing):

- `git revert <commit>`: preserves history and is reversible.
- Or restore specific files from a trusted commit: `git restore --source <trusted> -- <file>`.
- Avoid `git reset --hard` and force-pushes unless you fully understand the consequences and have a backup branch.

**Reverting does not undo what already happened.** It does not remove malicious dependencies already installed, malicious GitHub Actions or workflow changes, tokens already stolen, or anything the code did on machines that ran it. Also check other branches, tags, open PRs, and forks for the same payload.

## 4. Rotate credentials

Assume anything the process could read was exposed: environment variables, `.env` files, `~/.npmrc`, `~/.aws`, `~/.ssh`, cloud and CI secrets, browser sessions, cookies.

1. Revoke and reissue npm tokens, GitHub PATs and deploy keys, cloud keys (AWS/GCP/Azure), database and API credentials, signing keys.
2. Rotate **from a clean machine**, not the affected one.
3. Review audit logs (GitHub, npm, cloud) for unauthorized use since the first suspect commit.
4. Invalidate sessions and review SSH authorized keys and CI runners.

## 5. Review dependencies

- Diff `package.json` and lockfiles against the trusted commit; look for new Git/URL dependencies, changed `resolved` hosts, look-alike names, and new lifecycle scripts.
- Reinstall from a clean lockfile in a clean environment with `npm ci --ignore-scripts`; delete `node_modules` first.
- Check `npm ls` and the `resolved`/integrity fields for unexpected entries.
- Review GitHub Actions workflows, third-party action versions (pin to commit SHAs), and repository secrets and settings.

## 6. Follow up

- Add RepoShield to CI and make it a required check ([github-actions.md](github-actions.md)).
- Enable 2FA, require signed commits where practical, and restrict who can push and publish.
- If you published packages from the affected environment, consider them compromised and follow npm's incident process.
