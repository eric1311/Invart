# Kappaski Project Instructions

## Product Boundary

Kappaski is an agent runtime control plane for safety, observability, policy, proof, and audit across coding agents and related tool ecosystems. It is not a plugin-only wrapper and should not rely on extension hooks as the sole safety boundary.

The control-plane loop is:

- Before run: inventory environment, tools, skills, MCP, supply chain, policy profile, and risk posture.
- During run: observe commands, files, network, process tree, tool calls, policy decisions, approval state, and potential target deviation.
- After run: produce proof, replay, audit summary, and actionable risk findings.

## Architecture Boundary

- Ledger is the fact source; proof is the portable summary.
- Deterministic critical rules cannot be downgraded by LLM judgment.
- LLM reviewers may classify, explain, or upgrade risk, but policy enforcement and hard safety boundaries remain rule-governed.
- Profiles may bind to session, repo, and team, with priority `session > repo > team`.
- Enterprise mode should prefer explicit policy and auditable override paths over local silent override.

## Validation Boundary

Use real harnesses and data whenever feasible. For coding-agent compatibility, prefer SWE-Bench Lite, ClawBench-like cases, or real plugin/skill/tool corpora over mock-only tests.

Compatibility claims should state evidence: same exit code, same artifact, same grading result, or documented acceptable metadata differences. Do not claim security coverage from plugin/extension integration alone when lower-level runtime behavior remains unobserved.

## Implementation Defaults

Before editing roadmap, policy, replay, native integration, or benchmark code, check the current docs and tests for the target version. Keep version docs, README, and tests synchronized with implemented behavior.

## Skill routing

When the user's request matches an available skill, ALWAYS invoke it using the Skill
tool as your FIRST action. Do NOT answer directly, do NOT use other tools first.
The skill has specialized workflows that produce better results than ad-hoc answers.

Key routing rules:
- Product ideas, "is this worth building", brainstorming -> invoke office-hours
- Bugs, errors, "why is this broken", 500 errors -> invoke investigate
- Ship, deploy, push, create PR -> invoke ship
- QA, test the site, find bugs -> invoke qa
- Code review, check my diff -> invoke review
- Update docs after shipping -> invoke document-release
- Weekly retro -> invoke retro
- Design system, brand -> invoke design-consultation
- Visual audit, design polish -> invoke design-review
- Architecture review -> invoke plan-eng-review
- Save progress, checkpoint, resume -> invoke checkpoint
- Code quality, health check -> invoke health
