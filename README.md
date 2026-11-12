# autosearch

**An LLM-driven pipeline for static memory-safety audits.**

autosearch coordinates specialized agents to examine source code, challenge
potential findings, and record results in a queryable SQLite database. A
Python orchestrator manages each audit; a separate workspace keeps its
targets, findings, configuration, and logs together.

## Security research credits

[CVE-2026-43726](https://support.apple.com/en-us/148287) and
[CVE-2026-39872](https://support.apple.com/en-us/127685) were found by
Utkarsh Pal using autosearch. Apple also acknowledged Utkarsh for WebKit
Canvas research in its [Safari 27 advisory](https://support.apple.com/en-us/149039).

## How it works

1. **Define scope:** create a workspace and add or generate target methods.
2. **Audit and challenge:** run model cohorts and review their conclusions with
   validator, challenger, and clean-check agents.
3. **Track and refine:** store findings and agent runs in SQLite, and update
   rules and mitigations as the campaign progresses.
4. **Review and repeat:** inspect findings in the CLI, monitor cycles in the
   terminal UI, and revisit targets when the rules change.

This is static analysis: autosearch does not execute the target program, fuzz
it, or verify findings with ASan. LLM conclusions can be wrong; independently
review and validate findings before acting on them.

> **Privacy and cost:** prompts can contain target source code and are sent to
> the configured model provider. Workspaces retain findings and agent logs.
> Audit only code you are authorized to share, protect workspace data, and
> check model usage before a large run.

## Install

Requires Python 3.9 or later and authenticated GitHub Copilot access.

```bash
git clone https://github.com/ut-god/autosearch-public.git
cd autosearch-public
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
autosearch --version
```

The `github-copilot-sdk` dependency manages the Copilot CLI process. For
development and tests, install the extras with `pip install -e '.[dev]'`.

## Quick start

Create a workspace for a local WebKit checkout:

```bash
autosearch init webkit-image-decoders \
    --target ~/code/WebKit \
    --template webkit-image-decoders
cd ~/autosearch-workspaces/webkit-image-decoders
```

Templates provide configuration, but start with **empty targets and rules**.
Add methods to `targets.md`, using an actual method from your target checkout:

```text
Namespace::Class::method  # UAF — reason this method is in scope
```

Run a cycle and inspect its output:

```bash
autosearch run --once
autosearch findings list --limit 20
autosearch findings show 1  # replace 1 with an ID from the list
```

Use `autosearch tui` to monitor a running audit, or `autosearch run --forever`
for continuous cycles. The [runbook](docs/runbook-new-audit.md) covers target
generation, prompt overlays, and bootstrapping a new audit.

## Oracles and skills

The optional MethodFacts oracle supplies agents with source-derived facts.
Phase 1 indexes IDL exposure; Phase 2 adds information such as callers and
mutable globals using libclang and a compilation database. From a workspace:

```bash
autosearch build-oracle --phase=1
autosearch build-oracle --phase=all  # requires libclang and compile_commands.json
```

### Optional: libclang for Phase 2 oracles

Install the Python bindings with `pip install libclang` and ensure a compatible
libclang shared library is available. Use `--libclang /path/to/libclang.so`
to select it explicitly. See the [oracle reference](docs/reference.md#build)
for build setup and platform-specific guidance.

WebKit audit playbooks for memory-safety bug classes live in `.github/skills/`.
The [technical reference](docs/reference.md) covers the agents, oracle,
configuration, commands, and workspace data in more detail.

## Repository layout

| Path | Purpose |
|---|---|
| `src/autosearch/` | CLI, orchestrator, agents, storage, and terminal UI |
| `.github/skills/` | WebKit memory-safety audit playbooks |
| `templates/` | Starter workspace configurations |
| `scripts/` | Workspace bootstrap tools |
| `docs/` | Runbook and technical reference |
| `tests/` | Automated tests |

Campaign workspaces default to `~/autosearch-workspaces/` and are separate
from the target source repository, which is treated as read-only.

## License

Released under the [MIT License](LICENSE).
