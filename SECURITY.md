# Security policy

Gödel Tally handles security telemetry and connector credentials. Please do not open a public issue,
discussion, or pull request for a suspected vulnerability.

## Reporting a vulnerability

Email **security@godel-labs.ai** with the subject `Tally security report`. Include, when available:

- the affected commit, tag, endpoint, or component;
- impact and required access;
- a minimal sanitized reproduction;
- suggested mitigation;
- whether the issue is already public; and
- a safe way to contact you.

Do not send customer data, source logs, credentials, prompts, responses, documents, private keys, or
live exploit traffic. Use synthetic fixtures and redacted diagnostics. If a file is essential,
describe it first and wait for a secure transfer method.

Maintainers will coordinate validation, remediation, release timing, and disclosure with the
reporter. Please allow a reasonable remediation window before public disclosure.

## Supported versions

Tally is pre-1.0 and has no tagged releases yet. Security fixes are made on `main`. A supported
version policy will be published with the first tagged release.

## Deployment boundary

Standalone Tally requires user authentication and serves TLS directly in `tallyd`. The native
installer and optional Compose deployment publish `127.0.0.1:2357` by default. A shared or remote deployment should use a trusted certificate,
network access controls, production PostgreSQL credentials, managed secret storage, backups,
and monitoring.

Keep `TALLY_SECRET_KEY` stable and private. Rotating it makes existing connector credentials
undecryptable until they are entered again.
