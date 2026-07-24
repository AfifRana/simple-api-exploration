# Research Method for Multi-Language API Implementations

## Purpose

This guide defines how to run fair, repeatable API implementation research across
multiple programming languages and frameworks.

## Core Principle

Compare implementations of the same feature against the same contract, tests, and
workload profiles. Avoid changing multiple variables at once.

## Feature-Level Research Workflow

1. Define feature scope in `specs/<feature-id>/spec.md`.
2. Define implementation plan in `specs/<feature-id>/plan.md`.
3. Define executable tasks in `specs/<feature-id>/tasks.md`.
4. Publish API contract in `specs/<feature-id>/contract/openapi.yaml`.
5. Create shared test vectors in `specs/<feature-id>/test-vectors/`.
6. Create benchmark scenarios in `specs/<feature-id>/benchmark-scenarios/`.
7. Implement each language variant in `implementations/<feature-id>/<language-stack>/`.
8. Run shared conformance and benchmark workflows.
9. Record outcomes and decision notes in `docs/decisions/`.

## Mandatory Comparison Controls

- Contract parity: all implementations must conform to the same API contract.
- Functional parity: all implementations must pass the same contract and
  conformance tests.
- Environment parity: run tests and benchmarks with equivalent runtime resources.
- Data parity: use identical fixture sets and input distributions.
- Scenario parity: benchmark workload mix and durations must be identical.

## Evaluation Dimensions

## Correctness

- Contract test pass rate
- Integration test pass rate
- Edge-case behavior consistency

## Performance

- p50 and p95 latency
- Throughput (requests/second)
- Error rate under load
- Memory and CPU profile under steady state

## Developer Experience and Maintainability

- Time to first working implementation
- Complexity hotspots and readability notes
- Testability and debugging ergonomics
- Dependency and upgrade risk

## Operability

- Logging quality and structured diagnostics
- Monitoring/metrics coverage
- Startup behavior and health checks
- Deployment complexity

## Evidence Requirements for PRs

Every feature implementation PR must include:

- Language and stack name
- Link to feature spec, plan, and tasks
- Contract and conformance test results
- Benchmark run summary and environment details
- Known trade-offs and unresolved issues

## Decision Record Format

When selecting or recommending a stack, add a file in `docs/decisions/`:

- Decision title
- Context and constraints
- Options considered
- Comparison summary table
- Final recommendation
- Follow-up actions

## Versioning of Research Inputs

- Changes to contract or benchmark scenarios must be tracked in the same feature
  branch and explicitly called out in PR notes.
- If comparability is affected by a late change, rerun impacted implementations.

## Anti-Patterns to Avoid

- Comparing different API contracts between languages
- Benchmarking with mismatched hardware limits
- Making framework-specific optimizations in only one implementation before
  baseline comparison
- Drawing conclusions without test and benchmark evidence
