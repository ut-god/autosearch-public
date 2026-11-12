# autosearch

**A static memory-safety audit pipeline powered by LLM agents.**

autosearch coordinates specialized agents to examine source code, challenge
potential findings, and track results in a queryable SQLite database. A Python
orchestrator manages the workflow; a separate workspace holds each campaign's
configuration, targets, findings, and logs.

It is designed for static analysis: it does not execute the target program,
run a fuzzer, or verify findings with ASan. **LLM output can be wrong**—review
and independently validate findings before acting on them.

[Install](#install) · [Quick start](#quick-start) ·
[How it works](#how-it-works) · [Runbook](docs/runbook-new-audit.md) ·
[License](#license)

## How it works

1. **Scope an audit.** Create a workspace for a target repository and add or
   generate a list of methods to inspect.
2. **Audit and challenge.** The orchestrator dispatches auditors and runs
   validation, challenge, or clean-check steps as appropriate. Multiple models
   can audit a method in parallel.
3. **Record and refine.** Results, agent runs, and campaign state are stored
   in SQLite. Rules and mitigations can evolve as the audit progresses.
4. **Inspect and repeat.** Browse findings from the CLI, monitor cycles in the
   terminal UI, and expand or review scope as needed.

### Highlights

- **Structured workflow:** specialized agents with machine-readable output
  coordinated by a deterministic scheduler.
- **Parallel, configurable cohorts:** use multiple models and optional
  cross-vendor agreement to reduce redundant verification steps.
- **Persistent workspaces:** keep findings, configuration, prompts, and logs
  separate from the target source tree.
- **Re-auditing when rules change:** targets can become eligible again when
  the catalog or mitigation epoch changes.
- **Optional source oracles:** provide agents with mechanically extracted
  facts such as IDL exposure and, with libclang, caller and global information.

> **Privacy and cost:** audit prompts can contain target source code and are
> sent to the configured model provider. Workspaces also retain findings and
> agent logs. Audit only code you are authorized to share, protect workspace
> data, and check model usage and costs before a large run.

## Security research credits

[CVE-2026-43726](https://support.apple.com/en-us/148287) and
[CVE-2026-39872](https://support.apple.com/en-us/127685) were found by
Utkarsh Pal using autosearch. Apple also acknowledged Utkarsh for WebKit
Canvas research in its [Safari 27 advisory](https://support.apple.com/en-us/149039).

## Repository layout

```
autosearch/                          this repo (the tool)
├── pyproject.toml
├── README.md                        this file
├── src/autosearch/
│   ├── cli.py                       click-based `autosearch` command
│   ├── orchestrator.py              cycle scheduler
│   ├── agent_invoke.py              shared render → dispatch → parse → repair → record
│   ├── dispatch.py                  github-copilot-sdk adapter (long-lived client + per-call session)
│   ├── parse.py                     strict JSON extractor + one-shot repair
│   ├── render.py                    {{TOKEN}} placeholder substitution
│   ├── score.py                     per-cycle scoring
│   ├── status.py                    heartbeat for TUI
│   ├── import_git.py                legacy `[autosearch]` commit importer
│   ├── agents/                      LLM agent prompts (markdown, strict-JSON output)
│   │   ├── auditor.md               6 per cycle (3 Anthropic + 3 OpenAI)
│   │   ├── validator.md             1 per CLAIM, opposite vendor
│   │   ├── challenger.md            1 round per CLAIM (2 vendors, parallel) — was pre+post commit, merged
│   │   ├── clean-check.md           1 per CLEAN (skipped on cross-vendor agreement)
│   │   ├── refinement.md            1 per cycle (skipped on no-new-signal cycles:
│   │   │                              no claim past auditor + no verified-clean guards)
│   │   ├── threat-modeler.md        out-of-band: code → structured threat model
│   │   ├── target-generator.md      out-of-band: threat model → targets.md entries
│   │   ├── scope-reviewer.md        out-of-band: gate / retirement engine
│   │   └── analyst.md               out-of-band: rejection-code mining
│   ├── store/
│   │   ├── schema.sql               13-table SQLite schema
│   │   ├── db.py                    Store class (per-thread connections)
│   │   └── workspace.py             config.toml loader + targets.md parser
│   └── tui/
│       └── app.py                   Textual live monitor
└── templates/
    └── webkit-image-decoders/       starter campaign configuration
```

External, per campaign:

```
~/autosearch-workspaces/             one dir per campaign
└── webkit-image-decoders/
    ├── config.toml                  cohort, model mix, timeouts
    ├── targets.md                   in-scope <Class::Method> entries
    ├── rules/{catalog,mitigations}.md
    ├── findings.db                  SQLite corpus, WAL mode
    ├── threat-models/               saved threat-modeler outputs
    ├── reports/                     analyst + scope-reviewer outputs
    └── logs/
        ├── autosearch.log           run log
        ├── status.json              TUI heartbeat (atomic writes)
        ├── cycles/<n>/              per-cycle prompt+response capture
        │   ├── manifest.json
        │   ├── 00001_auditor_auditor_m1na.json
        │   └── ...
        └── out-of-band/<cmd>-<ts>/  threat-model / analyze / etc. captures
```

The target repo (e.g. `~/code/WebKit`) is **read-only** to autosearch.

## Install

```bash
git clone https://github.com/ut-god/autoseach-public.git
cd autoseach-public
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
autosearch --version
```

Requirements: Python ≥3.9, an active GitHub Copilot subscription.
Dispatch goes through the [`github-copilot-sdk`](https://pypi.org/project/github-copilot-sdk/)
Python package (installed automatically as a dependency) which bundles
the Copilot CLI binary — you do **not** need to install or authenticate
the `copilot` CLI separately, the SDK handles startup and login.

The dispatcher (`src/autosearch/dispatch.py`) keeps a single
`CopilotClient` warm per orchestrator process and opens a short-lived
session per LLM call. The `model` argument is honored per session
(unlike the legacy `copilot --yolo -p` invocation, where the CLI's
user-config model selection won regardless). To wire in an alternate
backend (direct vendor SDK, local Ollama, etc.), implement the
`Dispatcher` Protocol in `dispatch.py` and substitute it where
`default_dispatcher()` is called in `cli.py`.

### Optional: libclang for Phase 2 oracles

The MethodFacts oracle (see "Oracles" section below) has two phases.
Phase 1 (IDL exposure) is text-only and ships with no extra deps.
Phase 2 (mutable_globals + callers + thread_protections) needs
**libclang**:

```bash
# Python bindings
pip install libclang

# System libclang (Debian/Ubuntu)
apt install libclang-18-dev  # or libclang-15-dev, must match installed clang version

# macOS
brew install llvm  # provides libclang.dylib
```

The Phase 2 builder auto-detects the libclang shared library at
`/usr/lib/x86_64-linux-gnu/libclang-18.so.18`; override with
`--libclang /path/to/libclang.so` if your install differs.

### Skills

autosearch ships a set of WebKit memory-corruption audit playbooks in
`.github/skills/` (the open [agent-skills standard](https://agentskills.io)
project location):

- `webkit-uaf-audit/` — UAF, RACE_TO_UAF, DOUBLE_FREE
- `webkit-bounds-audit/` — HEAP_OVERFLOW, STACK_OVERFLOW, OOB_*, RACE_TO_OOB
- `webkit-int-overflow-audit/` — INT_OVERFLOW_TO_OOB
- `webkit-type-confusion-audit/` — TYPE_CONFUSION, RACE_TO_TYPE_CONFUSION
- `webkit-uninit-read-audit/` — UNINIT_READ
- `webkit-arbitrary-rw-audit/` — ARBITRARY_RW

Each skill ends with an "Oracle citations (mandatory for high-risk bug
classes)" section that documents the required `factsheet_citations` for
that bug class. When the auditor concludes CLEAN on a target with a
`bug_class_hint` of `RACE_TO_*` or `UAF`, missing citations cause the
orchestrator to force a cross-vendor clean-check even when both vendors
agreed CLEAN. See "Oracles" section below for the full FactSheet schema.

The dispatcher passes `.github/skills/` directly into
`CopilotClient.create_session(skill_directories=[...])`, so skills
auto-load **per-session** without any global install. This keeps
autosearch hermetic — no other Copilot session running on the same
machine sees these skills, so unrelated work in other repos is
completely unaffected.

To add a new skill: `mkdir .github/skills/my-new-skill && create SKILL.md`
(with `name:` and `description:` YAML frontmatter). The next auditor
session will auto-discover it.

### Per-role custom agents

Each autosearch role (auditor, validator, challenger, clean-check,
refinement, threat-modeler, target-generator, scope-reviewer,
analyst, overlay-suggester) is registered with the SDK as a native
**custom agent** (`infer: false`, identity-line `prompt`,
per-role `description`). The dispatcher pre-selects the matching
agent on every call via `create_session(custom_agents=[...],
agent=<role>)`. Benefits:

1. **Per-role identity in SDK telemetry** — `events.jsonl` shows the
   active role for every assistant turn, so SDK session-state dirs
   are trivially correlatable with the `agent_runs.agent_name` column
   in `findings.db`.
2. **Per-agent skill scoping** — only C++-memory-safety reasoners
   eagerly preload the 6 webkit-* skills; synthesizers don't carry
   ~30KB of irrelevant context per call.

| Role group | Roles | Skills eagerly preloaded |
|---|---|---|
| C++ memory-safety reasoners | `auditor`, `validator`, `challenger`, `clean-check`, `threat-modeler` | all 6 webkit-* |
| Synthesizers | `refinement`, `target-generator`, `scope-reviewer`, `analyst`, `overlay-suggester` | none |

The orchestrator's deterministic state machine stays in Python —
`infer: false` on every agent ensures the runtime never auto-routes;
we always pre-select via `agent=<role>`. This is opposite of the
SDK's default "delegate based on intent" pattern: autosearch needs
guaranteed cycle-by-cycle determinism, so we hold the wheel.

Adding a new role: drop a new `agents/<role>.md` and append the role
name to `_KNOWN_AGENT_NAMES` / `_DISPLAY_NAMES` / `_DESCRIPTIONS` in
`dispatch.py`. The drift-guard test
(`test_agent_configs_match_packaged_md_templates`) ensures these stay
in sync.

## Quick start

This example uses a local WebKit checkout. The bundled templates provide
configuration, but start with **empty targets and rules**; add or generate
targets before starting an audit.

```bash
# Create a workspace from the bundled image-decoders template
autosearch init webkit-image-decoders \
    --target ~/code/WebKit \
    --template webkit-image-decoders

cd ~/autosearch-workspaces/webkit-image-decoders
```

Edit `targets.md` to add methods from your target checkout. Each target has
the following format; replace the example with an actual method and a reason:

```text
Namespace::Class::method  # UAF — reason this method is in scope
```

Then start a cycle and inspect its results:

```bash
autosearch run --once
autosearch findings list --limit 20
autosearch findings show 1     # replace 1 with an ID from the list

# Live monitor (separate terminal)
autosearch tui
```

See the [runbook](docs/runbook-new-audit.md) for generating targets, writing a
prompt overlay, and building the optional oracle. To preview the automated
bootstrap for an IDL-rich area before spending model calls, run this from
the autosearch repository checkout:

```bash
scripts/first_run.sh \
    --name webaudio-test \
    --target ~/code/WebKit \
    --area Source/WebCore/Modules/webaudio \
    --recursive --dry-run
```

Additional commands:

```bash
autosearch run --forever       # continuous audit
autosearch build-oracle --phase=1
autosearch analyze --since-cycles 50
autosearch review-scope --retire
```

## Oracles (mechanical ground truth via SDK tools)

The audit pipeline ships an optional **MethodFacts oracle** that gives
auditors and clean-checkers structured ground-truth about every
`Class::method` in the target codebase, callable mid-reasoning as the
`oracle_method_facts(method)` SDK tool. These facts help agents check
assumptions about reachability, threading, and shared state.

Built per-workspace into `oracles/method_facts.json`:

| Field | Source | Catches |
|---|---|---|
| `idl_exposure` (`exposed_to_window`, `exposed_to_worker`, `via_idls`) | text parse of `*.idl` + Web IDL `includes` mixins + partial interfaces | "the threat-modeler said RACE; auditor assumed Window-only" |
| `mutable_globals_touched` | libclang AST walk (NeverDestroyed, LazyNeverDestroyed, file-scope statics, namespace globals) | "did the auditor notice the singleton?" |
| `callers_1hop` | libclang reverse call graph (capped at 50 per method) | UAF capture analysis, async dispatch tracing |
| `thread_protections` (`self_asserts_main_thread`, `self_holds_lock`, callers asserting / not asserting) | libclang scan for `assertIsMainThread`, `Locker`, `std::lock_guard`, etc., bubbled over callers | "is the main-thread invariant actually enforced?" |

### Build

```bash
# Phase 1 only: text IDL parse, ~5 sec, no clang dependency
autosearch build-oracle --phase=1

# Phase 1 + Phase 2: full libclang AST pass over compile_commands.json
# Cold ~10-15 min on 16 cores; cached per target_sha
autosearch build-oracle --phase=all --workers=16

# Scope to a subdirectory (much faster for iterative work)
autosearch build-oracle --phase=all --scope=platform/graphics/cg/

# Path remap for sandbox-built CDBs
autosearch build-oracle --phase=all --remap=/sdk/webkit=$HOME/WebKit
```

`compile_commands.json` discovery:

| Build setup | What you need |
|---|---|
| WebKit GTK / WPE / PlayStation | Nothing — `DEVELOPER_MODE=ON` (default for `build-webkit`) auto-emits `compile_commands.json` |
| Generic CMake | `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` at configure, or `export CMAKE_EXPORT_COMPILE_COMMANDS=1` |
| WebKit Cocoa (Xcode generator) | `bear -- build-webkit --release` (`brew install bear`) |
| Other / arbitrary build | `bear -- <your-build-command>` |

### Schema enforcement

When a target has a `bug_class_hint` of `RACE_TO_*` or `UAF`, cleans
MUST include a `factsheet_citations` field naming the oracle subfields
they consulted. Missing citations cause the orchestrator to (a) log a
`phase3 citation gap` warning and (b) **force a cross-vendor
clean-check to run even when both vendors agreed CLEAN**. This reduces
the risk that both vendors share the same unsupported assumption.

Skill files (`.github/skills/webkit-*-audit/SKILL.md`) document the
required-citation set per bug class.

## Pipeline

```
                      Phase 1 — SCOPE  (on-demand, manual)
                      ─────────────────────────────────────
   {CODE_PATHS} ──► threat-modeler ──► target-generator ──► (scope-reviewer)
                                                                    │
                                                                    ▼
                                                  append section to targets.md
                                                                    │
                      Phase 2 — AUDIT  (per cycle, parallel)        │
                      ─────────────────────────────────────         │
                                                                    ▼
                       orchestrator.run_cycle() reads
                       targets / catalog / mitigations / target_sha
                                       │
                       ┌───────────────┴────────────────┐
                       ▼                                ▼
       12 auditors (6 methods × 2 vendors)     2 post-commit challengers
       (parallel cohort, ThreadPoolExecutor)   (parallel, on oldest re-challengeable
                       │                        confirmed/settled finding)
                       ▼
       quorum detection (claims AND cleans)
                       │
                       ▼
       parallel per-result processing
       ──────────────────────────────
       per CLAIM:                           per CLEAN:
         validator (opposite vendor)          if cross-vendor CLEAN agreement:
            ↓                                   skip clean-check (agreement IS it)
         IF accept AND NOT quorum:            else:
           pre-commit challenger × 2            clean-check (opposite vendor)
            ↓                                     ↓
           IF either reverts → contested         confirm  OR  found_claim → recurse
           ELSE → confirmed
         IF accept AND quorum:
           skip pre-commit (agreement IS it)
            ↓
           confirmed
                                       │
                                       ▼
                       Phase 3 — LEARN
                       ─────────────────
                  refinement.md  (per cycle, when claims present)
                  analyst.md     (manual / cron, every ~10 cycles)
                  scope-reviewer.md  (manual / cron, every ~25 cycles)
```

## Hybrid 6×2 cohort with cross-vendor quorum

Each cycle picks **6 methods** from `targets.md` (least-recently-audited
first, round-robined across sub-areas). Each method is audited by
**2 vendors** (1 Anthropic + 1 OpenAI) drawn from `cohort_models`. Total:
**12 auditor invocations per cycle**, all dispatched in parallel.

| Cohort outcome on a method | Action |
|---|---|
| 2 CLAIMs at the **same canonical_key** (`class+method+bug_class+file+line-bucket`) | quorum: skip pre-commit challenger; record both claims (one `confirmed`, one `superseded`) |
| 2 CLAIMs at **different canonical_keys** | both go through validator + pre-commit challenger independently |
| 2 CLEANs (parseable) | quorum: skip clean-check for both; both rows marked `spot_check_verdict='quorum_skip'` |
| 1 CLAIM + 1 CLEAN | claim → validator + challenger as normal; clean → clean-check as normal |
| 1 parseable + 1 parse_failed | no quorum (only 1 signal) — process the one that parsed |

The mental model: **cross-vendor agreement substitutes for the next
verification step.** Same logic for both kinds.

`canonical_key` = sha256 of `(target_class | target_method | bug_class |
file | line_bucket_5)` — adjacent lines collapse to one key so claims
about the same op at slightly different lines deduplicate.

## Output contract — strict JSON

Every agent emits exactly one fenced JSON block. The parser:

1. Locates the **last** ```` ```json ```` block in the response (LLMs
   often emit thinking text or tool calls first).
2. JSON-decodes; validates required fields per `kind`.
3. On failure: ONE repair re-prompt that quotes the bad response and
   asks for re-emission. A second failure marks the run `parse_failed`
   and the cycle proceeds without that result.

No permissive regex fallback. The full prompt + raw response + parse
status is recorded in `agent_runs` for every invocation. The repair
path has been observed firing successfully on real LLM responses
(`parse_status='repaired'`).

## Schema highlights

`findings.db` — single file, WAL mode, **per-thread connections** (each
worker thread gets its own `sqlite3.Connection` via `threading.local`;
SQLite WAL handles concurrency natively).

13 tables; the important ones:

- `agent_runs` — one row per LLM invocation, immutable, captures
  prompt + response + model + CLI version + parse_status for full
  reproducibility.
- `claims` — structured; `state ∈ {proposed, validated, contested,
  confirmed, settled, reverted, rejected, superseded}`. `superseded`
  is reserved for quorum duplicates. `state_reason` carries the
  adjudication note (e.g. `validator + challenger survived`,
  `validator:NOT_REACHABLE`, `challenger gpt-5.4 reverted`, or
  `validator + challenger survived (class label disputed by validator)`
  when the validator returned `WRONG_BUG_CLASS` — see
  "State machine adjudication" below).
- `validations`, `challenges (phase=pre|post)`, `cleans` — append-only.
  `cleans.spot_check_verdict ∈ {confirm, found_claim, quorum_skip, NULL}`.
- `catalog_versions`, `mitigations_versions`, `prompt_versions` —
  content-addressed by sha256; bind every claim/clean to its epoch.
- `cycles` — idempotent: `status='running'` at start; on next start
  any leftover `running` rows are auto-marked `aborted`.
- `raw_commits` — staging table for `import-git`; preserves every
  legacy `[autosearch] ...` commit body verbatim. Idempotent by SHA.

### State machine adjudication

The orchestrator's claim state machine has one non-obvious rule worth
calling out:

**`WRONG_BUG_CLASS` is not a rejection.** When the validator returns
`verdict=reject + code=WRONG_BUG_CLASS`, it has explicitly admitted the
underlying unchecked op IS real — only the bug-class label the auditor
chose is disputed (e.g. auditor said `RACE_TO_UAF` but the singleton is
process-lifetime so it's really `RACE_TO_OOB` or
`RACE_TO_TYPE_CONFUSION`). The orchestrator treats this as
**`validated`** (not rejected) and proceeds to the challenger gate;
if the challenger doesn't disprove the underlying op, the claim lands as
`confirmed` with `state_reason` containing
`(class label disputed by validator)` so manual triage knows to
re-classify rather than re-investigate existence.

All other reject codes (`NOT_REACHABLE`, `DUPLICATE`,
`INSUFFICIENT_IMPACT`, `OFF_TARGET`, `CRASH_ONLY_DOS`, etc.) terminate
the claim as `rejected` as expected.

Find class-disputed confirmed bugs:
```sql
SELECT id, target_class, target_method, bug_class, state_reason
FROM claims
WHERE state = 'confirmed' AND state_reason LIKE '%disputed%';
```

## CLI surface

```
autosearch init <name>                    Create a workspace from a template
autosearch run --once|--cycles N|--forever  Audit cycle (Phase 2)
autosearch run --target-method Class::Method  Debug: 1 auditor on 1 method
autosearch findings list [--state]        Browse the corpus
autosearch findings show <id>             Full claim + validations + challenges
autosearch findings export [--format]     Stdout export (json|markdown)
autosearch findings cost [--since-cycles N] [--by agent|model|agent_model]
                                          Cost / token / duration roll-up
                                          (token estimates from char counts;
                                          pricing in src/autosearch/pricing.py)
autosearch agent list [filters...]        Browse individual LLM agent runs
autosearch agent show <id> [--format]     Full prompt + response + parsed JSON
autosearch agent path <id>                Path to per-cycle log file
autosearch import-git --from PATH         Backfill legacy git-commit history
autosearch catalog-diff [--since-cycles]  Show catalog evolution
autosearch tui                            Live monitor (Textual)
autosearch threat-model PATHS... [--per-file] [--include cpp,h] [--recursive]   Phase 1 step 1
autosearch generate-targets --from-threat-model FILE | --aggregate <glob> [--apply]   Phase 1 step 2
autosearch review-scope --gate FILE | --retire                   Phase 1 gate / Phase 3 retirement
autosearch analyze [--since-cycles]       Phase 3 rejection-code mining
autosearch suggest-overlay --area PATH [--apply] [--batch-size N] [--pool N]
                                          Propose a [prompt_overlay] block
                                          from IDL + headers (Phase 1 helper)
autosearch suggest-overlay --apply-from FILE   Apply a saved proposal (no LLM)
autosearch build-oracle --phase=1|all [--scope SUBSTR] [--remap OLD=NEW] [--workers N] [--port PORT]
                                          Build MethodFacts oracle for the workspace.
                                          --phase=1: IDL exposure only (~5 sec, no clang).
                                          --phase=all: also runs libclang AST pass over
                                          compile_commands.json (10-15 min cold on 16 cores).
                                          See "Oracles" section below.
```

## Debugging — inspect what an agent thought / did

Every LLM invocation is fully captured: rendered prompt, raw response (including
tool-call traces), parsed JSON, model, CLI version, duration, parse status. Stored
in two places, mirrored:

- `agent_runs` table in `findings.db` — queryable via SQL or `autosearch agent`
- `<workspace>/logs/cycles/<n>/<id>_<agent>_<slot>.json` — browsable with `less`/`jq`/grep

### `autosearch agent list` — find the run you want

```bash
autosearch agent list --limit 20                           # 20 most recent runs
autosearch agent list --latest                             # only the latest cycle
autosearch agent list --cycle 8                            # specific cycle
autosearch agent list --name auditor --state parse_failed  # all hallucinations
autosearch agent list --state repaired                     # one-shot repair retries that succeeded
autosearch agent list --slot auditor/m1#a                  # specific cohort slot across cycles
autosearch agent list --model gpt-5.4 --name auditor       # one vendor's auditor work
```

Output is a table with `id, cycle, agent, slot, model, parse_status, duration, target`.
The `target` column is parsed from the agent's own JSON output (works for auditor
+ clean-check; shows `(verdict)` or `(kind)` for validators / challengers / refinement).

### `autosearch agent show <id>` — read the full run

```bash
autosearch agent show 142                  # default: header + prompt + response + parsed JSON
autosearch agent show 142 --format header  # metadata only (id, cycle, slot, model, dur, parse)
autosearch agent show 142 --format prompt  # just the rendered prompt (for piping)
autosearch agent show 142 --format response  # just the raw LLM response (incl. tool calls)
autosearch agent show 142 --format parsed  # just the parsed JSON (suitable for jq)
autosearch agent show 142 --format json    # whole row as one JSON object
autosearch agent show 142 --no-pager       # don't elide long prompts/responses
```

The `prompt` and `response` formats emit plain text to stdout, so you can pipe:

```bash
autosearch agent show 142 --format prompt   | less
autosearch agent show 142 --format response | grep -A5 "json"
autosearch agent show 142 --format parsed   | jq '.checks_verified[] | .file'
```

### `autosearch agent path <id>` — locate the log file

```bash
autosearch agent path 142
# → /Users/you/autosearch-workspaces/<ws>/logs/cycles/000008/00142_auditor_auditor_m1na.json

less $(autosearch agent path 142)
jq .parsed_json $(autosearch agent path 142)
```

### Common debug questions

| Question | Command |
|---|---|
| What did opus think about copyTo? | `autosearch agent list --slot auditor/m1#a` then `agent show <id>` |
| Why did this run return CLEAN? | `agent show <id> --format parsed` shows the body + checks_verified citations |
| Did the auditor actually read source? | `agent show <id> --format response` shows tool-call traces (`Search (glob)`, `Read FILE`) before the JSON |
| Was overlay substituted correctly? | `agent show <id> --format prompt \| grep "ATTACKER_SURFACE\|<your-overlay-keyword>"` |
| Which run was the longest? | `agent list --limit 5` (durations shown), then `show <id>` |
| Did any agents need the repair retry? | `agent list --state repaired` |
| Compare opus vs gpt on the same target | `agent list --slot auditor/m3#a` and `--slot auditor/m3#o` |
| Find all parse failures | `agent list --state parse_failed --limit 50` |

### Mid-flight limitation

`agent_runs` rows are written **after** the LLM call returns, not before. So:

- ✅ Completed agents → fully inspectable via `agent show <id>`
- ❌ Currently running agents → no DB row yet; `agent list --latest` may show 0 rows during a cohort dispatch

If you need to peek at what a *currently-running* agent is doing, your options today are:
1. Wait for it to finish (the TUI's `dur` column shows live elapsed per slot).
2. Read the rendered prompt template directly: `cat ~/autosearch/src/autosearch/agents/<agent_name>.md` plus `cat <workspace>/logs/status.json` for the `target` substitution.

Future work: split `agent_invoke.invoke()` so the prompt is recorded at dispatch
start (parse_status=`running`) and updated on completion. Then `agent show <id>`
would work for in-flight runs too.

## Scope expansion (Phase 1)

`targets.md` is the cohort's input. When you spin up a new campaign or
add a new code area to an existing one, you need to populate `targets.md`
with `<Class::Method>` entries the auditor cohort will work through.

Three approaches, in increasing automation:

### 1. Hand-curate (smallest scope)

Edit `<workspace>/targets.md` directly. Format:

```
<Namespace>::<Class>::<Method>   # <BUG_CLASS> — <reason>
```

Bug classes (canonical taxonomy in
[`src/autosearch/agents/_taxonomy.md`](src/autosearch/agents/_taxonomy.md),
auto-injected into every agent prompt as `{{TAXONOMY}}`):
`HEAP_OVERFLOW`, `STACK_OVERFLOW`, `OOB_READ`, `OOB_WRITE`, `UAF`,
`DOUBLE_FREE`, `TYPE_CONFUSION`, `RACE_TO_TYPE_CONFUSION`,
`INT_OVERFLOW_TO_OOB`, `UNINIT_READ`, `RACE_TO_OOB`, `RACE_TO_UAF`,
`ARBITRARY_RW`, `n/a`. Group methods under
`### <SubArea> (<source path>)` headings inside `## Campaign N` headings.

To add or rename a class: edit `_taxonomy.md` only. All agent prompts
read it via `{{TAXONOMY}}` — no need to touch each prompt.

The targets table refreshes from `targets.md` on every cycle start.

### 2. Single-shot threat-model (small areas, ≤~5KLOC)

```bash
autosearch threat-model Source/WebCore/Modules/webcodecs/
# → 1 LLM call. One model sees all paths at once.
# → output: <workspace>/threat-models/<name>-<timestamp>.json

autosearch generate-targets \
    --from-threat-model threat-models/webcodecs-*.json --apply
# → 1 LLM call. Converts threat model → targets.md section, appends.
```

Caveat: a single LLM holding many files in context picks ~25 candidate
methods total (capped in the prompt). Misses methods in larger areas.

### 3. Per-file threat-model (any size — recommended)

```bash
autosearch threat-model --per-file Source/WebCore/Modules/webcodecs/
# → N parallel LLM calls (one per .cpp file in the directory).
# → Each call sees its single file deeply.
# → output: <workspace>/threat-models/<name>-<timestamp>/<file>.json (one per file)

autosearch generate-targets \
    --aggregate 'threat-models/webcodecs-*/*.json' --apply
# → 1 LLM call. Reads all per-file outputs, dedupes by (method, bug_class),
#   merges into a single targets.md section, appends.
```

`--per-file` mode flags:

| Flag | Default | Purpose |
|---|---|---|
| `--per-file` | off | Switch from single-shot to per-file mode |
| `--include cpp` | `cpp` | Comma-list of extensions to walk (`cpp,h,mm,cc`) |
| `--recursive` | off | Walk subdirectories (e.g. `wasm/` has `js/`, `b3/`, etc.) |
| `--max-files 200` | 200 | Hard cap on dispatch count. Errors with file list as preview |
| `--pool 6` | 6 | Max parallel workers. Bump to 12 if no `run --forever` competing |

Inputs `PATHS...` may be:
- explicit files (`foo.cpp bar.cpp`)
- shell globs (`*.cpp` — your shell expands)
- quoted globs (`"Source/X/*.cpp"` — autosearch expands)
- DIRECTORIES (`Source/X/Y/`) → walked for `--include` extensions
- relative or absolute paths

Dry-run preview (don't dispatch, just list matched files):

```bash
autosearch threat-model --per-file --max-files 0 \
    Source/JavaScriptCore/wasm/ --recursive
# → Errors out: "matched 132 files, exceeds --max-files=0. First 5: ..."
```

### Empirical comparison (WebCodecs run)

| Approach | Wall | LLM calls | Methods discovered | Novel vs hand-curated |
|---|---|---|---|---|
| Hand-curated (initial) | 0 | 0 | 61 | — (baseline) |
| Per-file (12 files) + aggregate | 19m | 12 + 1 | 46 unique candidates | **4 new** (`resetDecoder`, `resetEncoder`, `allocationSize`, `audioElementSpan`) |

Per-file caught: internal helpers (vs public API), unchecked-multiply
allocations, free-function span casts. Hand-curation caught the obvious
public surface but missed these patterns.

### When to use which

| Situation | Approach |
|---|---|
| You know the codebase inside-out | Hand-curate |
| Adding a small known-shape area (1-3 files) | Single-shot threat-model |
| Cold-starting a campaign (any size) | Per-file + aggregate |
| Periodic re-audit after major refactor | Per-file with `--recursive` over the changed directory |

### 4. Auto-suggested overlay (recommended for new campaigns)

When bootstrapping a new campaign, instead of writing the `[prompt_overlay]`
block by hand (5–15 min), let the LLM propose it from the area's IDL files
and public headers:

```bash
# Generate a proposal — review it in the saved JSON / TOML
autosearch suggest-overlay --area Source/WebCore/Modules/webcodecs/
# → saves to <workspace>/threat-models/overlay-proposal-<timestamp>.{json,toml}

# Apply a reviewed proposal without another LLM call
autosearch suggest-overlay --apply-from threat-models/overlay-proposal-*.json

# One-shot: generate + apply (skip manual review)
autosearch suggest-overlay --area Source/WebCore/Modules/webcodecs/ --apply
```

For large areas with many IDL/header files, the command automatically
batches them into parallel LLM calls and merges the results:

```bash
# WebGPU has ~145 IDL files; batch into groups of 30, 8 workers
autosearch suggest-overlay --area Source/WebCore/Modules/WebGPU/ \
    --batch-size 30 --pool 8
```

| Flag | Default | Purpose |
|---|---|---|
| `--area PATH` | (required unless `--apply-from`) | Code area to survey |
| `--include` | `idl,h` | Extensions to walk for context |
| `--max-context-files` | 80 | Soft cap on files surveyed |
| `--batch-size` | 30 | Max files per LLM call (auto-batches when exceeded) |
| `--pool` | 6 | Max parallel batch workers |
| `--apply` | off | Also write the proposal to `config.toml` |
| `--apply-from FILE` | — | Apply a saved proposal (no LLM call) |
| `--model` | `refinement_model` | Override the model |

The `first_run.sh` bootstrap script includes `suggest-overlay --apply`
as its final step (Phase 5/5), so `scripts/first_run.sh` handles this
automatically for new campaigns.

## Performance

Measured on a 12-auditor (6×2) all-CLEAN cycle against the WebKit
image-decoder template + imported corpus:

| Configuration | Wall | LLM calls |
|---|---|---|
| Sequential post-process (initial) | 20m22s | 26 |
| Parallel per-result via ThreadPoolExecutor | 7m25s | 26 |
| **+ Skip clean-check on cross-vendor CLEAN agreement** | **3m38s** | **14** |

5.6× speedup vs. the initial sequential design. Auditor cohort is
now ~73% of the wall (slowest of 12 parallel auditors). Further wall
reductions would have to attack the auditor cohort itself (fewer
methods, faster models, or sub-method pipelining — but pipelining
would break quorum, so it's not pursued).

## Configuration

A typical `<workspace>/config.toml`:

```toml
target_repo = "/Users/you/code/WebKit"
target_branch = "main"

# Hybrid cohort: cohort_methods × cohort_models_per_method = total auditors per cycle.
# Each method is audited by `cohort_models_per_method` distinct models from
# `cohort_models`, preferring different vendors for cross-vendor quorum.
cohort_methods           = 6
cohort_models_per_method = 2

cohort_models     = ["claude-opus-4.7", "gpt-5.4"]
challenger_models = ["claude-opus-4.7", "gpt-5.4"]
refinement_model  = "claude-opus-4.7"

cycle_timeout_seconds        = 4500
agent_timeout_seconds        = 1500
pre_commit_challenge_enabled = true

# (deprecated) These two fields configured the legacy subprocess
# dispatcher. They are accepted for backward compatibility but ignored
# by the SDK-based dispatcher and safe to delete.
# dispatch_command = "copilot"
# dispatch_args    = ["--yolo", "-p"]

# Workspace-specific framing of the trust boundary (see "Prompt overlay" below).
[prompt_overlay]
attacker_surface = """renderer-reachable JS / HTML / IDL entry points
(<img src=>, CSS background-image, fetch(), createImageBitmap(), …)"""
scope_includes   = """Includes C library callbacks from libpng/libjpeg/libwebp/libavif/libjxl,
ICC/LCMS color transforms, SharedBuffer segment arithmetic, and ImageBackingStore pixel writes."""
extra_out_of_scope = """  - Pure origin / CSP / cookie / web-platform issues"""
```

Knobs:
- `cohort_methods=3, cohort_models_per_method=2` → 6 runs, lighter cycles
- `cohort_methods=12, cohort_models_per_method=2` → 24 runs, more coverage
- `cohort_models_per_method=1` → reverts to pure-coverage mode (no quorum)
- Add a third vendor to `cohort_models` and bump `cohort_models_per_method=3`
  → 3-vendor quorum (rarer agreement → stronger when it fires)

## Prompt overlay (workspace-specific framing)

The bundled agent prompts (`auditor.md`, `validator.md`, `challenger.md`,
`threat-modeler.md`, …) are **target-agnostic**. They contain
no WebKit / browser / image-decoder hardcoding. The trust boundary —
"what counts as attacker-controllable input?" — is supplied per
workspace via three placeholder strings substituted into every prompt
at render time:

| Placeholder | What it replaces | Defaults to |
|---|---|---|
| `{{ATTACKER_SURFACE}}` | The reachability framing in GOAL, OUT OF SCOPE, REQUIRED EVIDENCE, and the `reachability` JSON field | `"external attacker-controlled input"` |
| `{{SCOPE_INCLUDES}}` | A workspace-specific "includes" addendum to the SCOPE section | `""` (empty) |
| `{{EXTRA_OUT_OF_SCOPE}}` | Workspace-specific extra OUT-OF-SCOPE bullets (e.g. web-platform issues) | `""` (empty) |

### Who populates these

| Scenario | Who | Effort | When you'd edit |
|---|---|---|---|
| Use existing template (`autosearch init … --template webkit-image-decoders`) | template author (already done) | zero | rarely |
| New campaign with no template (generic defaults kick in) | workspace operator (you, post-init) | 5–15 min | once, when starting the campaign |
| Building a new shareable template | template author (you, once) | 5–15 min | when adding a new attack surface |

The values are **stable per workspace** — they don't change between
cycles or even between major refactors. Wrong values fail loudly:
too narrow → auditors return CLEAN for everything ("not reachable");
too broad → validators reject claims with `NOT_REACHABLE`. Either way
you'll see the signal in the cycle output.

### Concrete examples

WebKit image-decoders (the bundled template):

```toml
[prompt_overlay]
attacker_surface   = "renderer-reachable JS / HTML / IDL entry points (<img src=>, fetch(), <canvas>.drawImage(), …)"
scope_includes     = "Includes C library callbacks from libpng/libjpeg/libwebp/libavif/libjxl, ICC/LCMS color transforms, SharedBuffer segment arithmetic, and ImageBackingStore pixel writes."
extra_out_of_scope = "  - Pure origin / CSP / cookie / web-platform issues"
```

Hypothetical `libwebp-standalone`:

```toml
[prompt_overlay]
attacker_surface = "WebPDecode*() / WebPDemuxer*() public API calls with attacker-supplied bytes"
scope_includes   = "Includes libwebp internal helpers and dsp/sse/neon backends."
extra_out_of_scope = ""
```

Hypothetical `linux-kernel-driver`:

```toml
[prompt_overlay]
attacker_surface = "syscall / ioctl / file_operations entry points reachable by an unprivileged user"
scope_includes   = "Includes copy_from_user, get_user, container_of casts, RCU read-side critical sections."
extra_out_of_scope = """  - Pure capability / DAC / MAC permission issues
  - Information leaks already covered by KASLR"""
```

Hypothetical generic network server:

```toml
[prompt_overlay]
attacker_surface   = "parsed HTTP request bytes from an unauthenticated client"
scope_includes     = "Includes connection state, header parser, and body decompression paths."
extra_out_of_scope = "  - Logic bugs in authentication / authorization beyond memory corruption"
```

If you skip the `[prompt_overlay]` block entirely, the generic
defaults render to coherent (if vague) prompts — the audit cycle
still works, just with weaker reachability framing.

## Templates

A template is a pre-packaged starter campaign (config + targets +
seed catalog + seed mitigations + prompt overlay) that `autosearch
init … --template <name>` copies into a new workspace.

```
templates/webkit-image-decoders/
├── config.toml          ← cohort + models + [prompt_overlay] block
├── targets.md           ← add or generate in-scope methods
├── rules/
│   ├── catalog.md       ← initially empty pattern catalog
│   └── mitigations.md   ← initially empty mitigation catalog
└── README.md
```

Adding a template = `mkdir templates/<name> && cp <files>`. No Jinja,
no variable expansion — plain copy + `target_repo` rewrite. The
`[prompt_overlay]` block is the only thing that needs to be tailored
per attack surface; everything else is operator-tunable knobs.

## Importing an existing corpus

If you have a compatible legacy audit branch, import it into a workspace
with `autosearch import-git --from <target-repo> --branch <branch>`.
Review imported findings before sharing the workspace.

## License

Released under the [MIT License](LICENSE).
