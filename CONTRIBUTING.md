# Contributing to Gödel Tally

Thank you for helping improve Tally. Bug fixes, connector improvements, registry evidence,
documentation, tests, accessibility work, and carefully scoped features are welcome.

## Before you start

- Search existing issues and pull requests to avoid duplicate work.
- Open an issue before a large behavior, schema, dependency, or architecture change.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
- Only contribute code, data, images, and documentation that you have the right to license.

By submitting a contribution, you agree that it is licensed under the repository's Apache-2.0
license.

## Set up the repository

Required tool versions and local commands are documented in
[Development guide](https://godel-labs.ai/docs/tally/development). The short path is:

```bash
npm --prefix apps/web ci
make check
```

Use a topic branch and keep a pull request focused on one coherent change. Do not commit `.env`,
credentials, source exports, customer data, build output, or editor state.

## Engineering contracts

Contributions must preserve these boundaries:

- Raw connector payloads and raw observations are not durable product data.
- Prompt text, response text, documents, arbitrary request bodies, headers, cookies, and tokens do
  not belong in findings or logs.
- Attribution is explicit and source-derived. Do not infer a user from an IP address or a destination
  from a provider name.
- Findings are evidence. Governance state does not imply a universal enforcement action.
- Unknown providers and models remain in Authorization Queue until reviewed.
- Scanner traffic must remain bounded, previewable, and restricted to explicitly authorized scopes.
- Connector retries and backfills must remain idempotent.
- Credentials must use the existing sealed-storage path and must redact themselves from diagnostics.

## Tests and fixtures

Add the narrowest test that proves the behavior and its failure mode. Connector changes should
normally include:

- a sanitized positive fixture;
- a negative or ambiguous fixture;
- assertions for fields that must be retained; and
- redaction assertions for fields that must not survive normalization.

Use reserved domains, documentation IP ranges, synthetic identifiers, and obvious non-secret test
values. Never copy production telemetry into the repository.

Registry changes require sourced facts, deterministic output, matcher coverage, and an updated
generated artifact when the registry version changes:

```bash
make registry-lint
make registry-build
make schema-check
```

## Pull requests

A pull request should explain:

- the problem and intended behavior;
- security, privacy, compatibility, and migration impact;
- tests and manual checks actually run;
- generated files or documentation changed; and
- follow-up work that is intentionally out of scope.

Run `make check` before requesting review. Run `make audit`, `make secret-scan`, and
`make compose-check` for dependency, release, deployment, or security-sensitive changes.

Reviewers may request smaller commits, additional fixtures, or explicit evidence for registry facts.
Maintainers merge changes after required checks and review pass.
