# Branching and PR Policy (Speckit Workflow)

## Purpose
This policy keeps `main` stable while allowing iterative feature delivery through Spec Kit.

## Branch Model

### Long-lived branches
- `main`: Production and tagged releases only.
- `develop/v1`: Integration branch for Release 1 development.

### Short-lived branches
- `feat/<id>-<short-name>`: Feature implementation branch created from `develop/v1`.
- `fix/<id>-<short-name>`: Non-release bug fix branch created from `develop/v1`.
- `hotfix/<id>-<short-name>`: Emergency production fix created from `main`.

## Merge Flow
1. Create feature branch from `develop/v1`.
2. Run Speckit flow on the feature branch: `specify -> plan -> tasks -> implement`.
3. Open PR into `develop/v1`.
4. After all planned features are merged and validated, open one release PR: `develop/v1 -> main`.
5. Tag release on `main` (example: `v1.0.0`).

## Pull Request Rules

### For PRs into `develop/v1`
- Require at least 1 approval.
- Require passing status checks:
  - Lint/format/static analysis
  - Automated tests
- Require PR template completion.
- Prefer squash merge for clean history.

### For PRs into `main`
- Require at least 2 approvals.
- Require all `develop/v1` checks to pass.
- Require release notes section completed.
- Restrict direct pushes.

## Required Checks by Constitution
- Code quality gates must pass.
- Test standards must be met and evidence attached.
- UX consistency changes must be reviewed and documented.
- Performance budgets and regression evidence must be provided where relevant.

## Suggested Naming Conventions
- Features: `feat/001-auth-login`
- Fixes: `fix/017-token-refresh-bug`
- Hotfixes: `hotfix/critical-login-outage`

## Release Procedure (R1)
1. Freeze `develop/v1` for feature merges.
2. Run full regression and performance checks.
3. Open PR `develop/v1 -> main`.
4. Merge after approvals and checks.
5. Tag `v1.0.0` on `main`.
6. Optionally branch `develop/v2` from `main` for next release train.

## GitHub Settings Checklist
- Protect `main`.
- Protect `develop/v1`.
- Enforce pull requests before merge.
- Enforce required status checks.
- Enforce linear history or squash merge.
- Restrict force pushes and deletions.
