# Security Policy

Invart is pre-1.0 software. Please treat it as a local-first control-plane toolkit, not a complete sandbox.

## Supported Version

The current supported line is `0.9.x`.

## Reporting Issues

Please do not open a public issue for a vulnerability that includes exploitable details, secrets, or private logs. Use a private security advisory or contact the maintainers directly when the project is published.

## Security Boundaries

Invart currently focuses on:

- pre-runtime inventory;
- runtime event mediation;
- policy decisions and approvals;
- append-only ledger facts;
- proof, replay, audit, coverage, and evidence artifacts;
- wrapper, launcher, hook/plugin, MCP, and source-level shim integration.

Invart does not yet claim:

- kernel-level sandboxing;
- hosted enterprise administration;
- IdP/SCIM/SAML integration;
- guaranteed coverage for agents launched entirely outside managed launchers, wrappers, and observable surfaces.

Deterministic critical rules must not be downgraded by LLM reviewers.
