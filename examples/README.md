# Invart Examples

These examples are intentionally small. They are meant to help new users feel the control loop before running larger demos.

## Basic Managed Session

```bash
bash examples/basic-managed-session.sh
```

## Analyze A Risky Event Without Executing It

```bash
invart runtime analyze-event --event "$(cat examples/unsafe-action-event.json)"
```

## Policy Profile

Use `examples/policy-profile.toml` as a starting point for policy-as-code experiments.
