# Decision Records

This directory stores decision records for API research outcomes, implementation
trade-offs, and stack recommendations.

## Naming Convention

Use one file per decision:

- `YYYY-MM-DD-short-title.md`
- Example: `2026-07-24-go-vs-node-for-feature-001.md`

## When to Create a Decision Record

Create a record when you:

- Choose one language/framework over alternatives for a feature
- Change a contract, benchmark method, or quality gate with broad impact
- Accept a trade-off that affects performance, maintainability, or operations

## Required Template

Copy this template into a new file for each decision.

```md
# Decision: <Title>

## Status
- Proposed | Accepted | Superseded

## Date
- YYYY-MM-DD

## Context
- Problem statement
- Scope (feature IDs, services, or components)
- Constraints (time, team, infra, compliance)

## Options Considered
1. Option A
2. Option B
3. Option C

## Comparison Summary
| Dimension | Option A | Option B | Option C |
|-----------|----------|----------|----------|
| Correctness | | | |
| Performance | | | |
| Maintainability | | | |
| Developer Experience | | | |
| Operability | | | |

## Decision
- Selected option:
- Why:

## Consequences
- Benefits:
- Risks:
- Mitigations:

## Evidence
- Spec:
- Plan:
- Tasks:
- Test results:
- Benchmark results:

## Follow-up Actions
- [ ] Action 1
- [ ] Action 2

## Supersedes / Superseded By
- (Optional links)
```

## Review Expectations

- Link the decision record in the related PR.
- Keep rationale evidence-based using shared tests and benchmark results.
- Update status to `Superseded` when replaced by a newer decision.
