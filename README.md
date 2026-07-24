# Simple API Exploration

## Overview

This repository is a research workspace for API design and implementation across
multiple programming languages. The goal is to compare approaches, validate design
trade-offs, and capture implementation patterns that are portable between stacks.

## Scope

- Explore REST and event-driven API patterns
- Prototype implementations in any language/framework
- Define and test API contracts
- Measure quality, consistency, and performance characteristics

## Working Model

- `main` remains stable and release-oriented
- `develop/v1` is the integration branch for active research and feature work
- Feature branches are created from `develop/v1`
- Spec Kit drives delivery flow: `specify -> plan -> tasks -> implement`

## Repository Guidance

- Constitution: `.specify/memory/constitution.md`
- Branch and PR rules: `docs/branching-and-pr-policy.md`
- PR checklist template: `.github/pull_request_template.md`
- Research method and evaluation rules: `docs/research-method.md`

## Repository Structure

```text
repo/
├─ README.md
├─ docs/
│  ├─ branching-and-pr-policy.md
│  ├─ research-method.md
│  └─ decisions/
├─ specs/
│  ├─ 001-feature-a/
│  │  ├─ spec.md
│  │  ├─ plan.md
│  │  ├─ tasks.md
│  │  ├─ contract/
│  │  │  └─ openapi.yaml
│  │  ├─ test-vectors/
│  │  └─ benchmark-scenarios/
│  └─ 002-feature-b/
├─ implementations/
│  ├─ 001-feature-a/
│  │  ├─ python-fastapi/
│  │  ├─ node-express/
│  │  └─ go-fiber/
│  └─ 002-feature-b/
├─ tests/
│  ├─ contract/
│  ├─ integration/
│  └─ conformance/
├─ benchmarks/
│  ├─ harness/
│  └─ reports/
└─ tooling/
	├─ run-tests/
	├─ run-benchmarks/
	└─ compare-results/
```

Directory intent:

- `specs/`: feature-scoped requirements, plans, tasks, contracts, and test vectors
- `implementations/`: language-specific implementations grouped by feature
- `tests/`: shared validation suites for cross-language conformance
- `benchmarks/`: benchmark harnesses and generated performance reports
- `tooling/`: scripts and utilities for repeatable test/benchmark execution
- `docs/decisions/`: architecture and research decision records

## Research Expectations

- Keep proposals language-agnostic unless a feature explicitly targets one stack
- Include test evidence for each experiment
- Keep UX and error contracts consistent for comparable implementations
- Define performance budgets and report observed results

## Typical Workflow

1. Create a feature branch from `develop/v1`
2. Generate feature artifacts with Spec Kit commands
3. Implement and validate with tests and measurements
4. Open PR into `develop/v1`
5. Merge `develop/v1` into `main` for release

## Notes

This repo intentionally supports mixed-language experiments. Add stack-specific
setup docs in feature folders when needed.