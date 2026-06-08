# What belongs in the public repository.

[HTML version](html/open-source-boundary.html)


The root of this repository is now organized as the open-source Invart project. Internal planning material lives outside the public docs tree.

### Public

Source code, tests, pinned safe fixtures, examples, public docs, brand assets, license, contribution guide, security policy, and changelog.

### Local/internal

Historical roadmap drafts, long design discussions, brand exploration, generated release artifacts, local ledgers, and private notes.

## Local-only directories

```bash
internal/
.invart/
.kappaski/
.venv/
build/
dist/
logs/
rust/**/target/
```

These paths are ignored by git so the GitHub repository can stay focused and understandable.
