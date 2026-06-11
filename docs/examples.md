# Examples and safe fixtures

[HTML version](html/examples.html)

This page is a compatibility index for small examples. For a guided first run, use [Quickstart](quickstart.md). For layer-by-layer operation, use the [five-layer operator guide](five-layer-operator-guide.md).

## Runnable examples

| Example | Use it for |
| --- | --- |
| [`../examples/basic-managed-session.sh`](../examples/basic-managed-session.sh) | Create one managed session, ledger, and proof for a low-risk command. |
| [`../examples/policy-profile.toml`](../examples/policy-profile.toml) | Inspect a compact policy-as-code profile with path-aware rules. |
| [`../examples/unsafe-action-event.json`](../examples/unsafe-action-event.json) | Analyze an unsafe shell event without executing it. |

## Analyze the unsafe event

```bash
invart runtime analyze-event --event "$(cat examples/unsafe-action-event.json)"
```

This command analyzes a JSON event payload. It does not execute the unsafe command inside the fixture.

## Next steps

- Use [Quickstart](quickstart.md) to create a real local ledger.
- Use [Five-layer Operator Guide](five-layer-operator-guide.md) to inspect L1-L5 on that ledger.
- Use [Runtime Effect Demo](runtime-effect-demo.md) for generated demo artifacts and action timelines.
