# Small examples before full demos.

[HTML version](html/examples.html)


The examples/ directory contains short runnable or copyable examples for local evaluation.

### Basic managed session

examples/basic-managed-session.sh creates a ledger and proof for one low-risk command.

### Policy profile

examples/policy-profile.toml shows a small TOML profile with path-aware risk rules.

### Unsafe event

examples/unsafe-action-event.json is a shell event you can analyze without executing it.

## Analyze The Unsafe Event

```bash
invart runtime analyze-event --event "$(cat examples/unsafe-action-event.json)"
```
