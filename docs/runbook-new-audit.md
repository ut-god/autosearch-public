# Runbook: bootstrapping a new audit from scratch

This is the step-by-step process for taking a fresh code area (a directory
in a target repo) and turning it into a running autosearch campaign.

Worked example throughout: the **CoreGraphics** campaign that ran in this
session. Treat the example commands as templates — replace the names and
paths to match your own area.

## Prerequisites

1. **autosearch installed**: `pip install -e ~/autosearch` (see [Install](../README.md#install))
2. **Target repo cloned read-only**: e.g. `~/WebKit`
3. **GitHub Copilot subscription active** (the SDK handles auth)
4. **(Optional) For full Phase-2 oracles**: libclang installed (see [README Install](../README.md#optional-libclang-for-phase-2-oracles))
5. **(Optional) For full Phase-2 oracles**: a build of the target with
   `compile_commands.json` available (WebKit GTK auto-emits it via
   `DEVELOPER_MODE=ON`; for other build systems see the [Oracles bootstrap matrix](../README.md#build))

## Decision: scripted bootstrap vs manual?

| Path | Use when |
|---|---|
| `scripts/first_run.sh` | The area has IDLs and you trust the auto-generated `[prompt_overlay]` block (e.g. WebCodecs, WebGPU, MSE). Now also runs `build-oracle --phase=1` automatically; pass `--build-oracle all` for the full libclang pass, or `--build-oracle none` to skip. |
| **Manual** (this runbook) | The area has no IDLs (CG, IPC handlers), or you want to write a custom attacker-surface description |

If you go with `first_run.sh`, run `scripts/first_run.sh --help` and skip
to step 5 below.

---

## Step 1: Create the workspace

```bash
autosearch init <name> --target ~/WebKit
```

Worked example:
```bash
autosearch init core-graphics --target ~/WebKit
# Output: workspace created: /home/user/autosearch-workspaces/core-graphics
#         target_repo: /home/user/WebKit
```

What this gives you:
```
~/autosearch-workspaces/core-graphics/
├── config.toml      # ← workspace config; you'll edit this in Step 2
├── findings.db      # ← empty SQLite corpus (created on first run)
├── targets.md       # ← empty target list (filled in Step 4)
├── rules/           # ← catalog.md and mitigations.md (auto-managed)
├── reports/         # ← markdown reports (auto-generated)
└── logs/            # ← per-cycle agent logs (auto-managed)
```

The `<name>` is the workspace identifier. Workspaces live under
`~/autosearch-workspaces/<name>/` by default; override with
`autosearch init <name> --target ~/WebKit --root /path/to/workspaces`.

---

## Step 2: Write a `[prompt_overlay]` block

The overlay is the single most impactful artifact. It describes the
attacker surface, trust boundaries, and what's in/out of scope for *this*
area. The default workspace ships with an empty `[prompt_overlay]`; you
must populate it.

Two ways:

### 2a. Auto-generate from IDL + headers (areas with IDLs)

```bash
cd ~/autosearch-workspaces/core-graphics
autosearch suggest-overlay --area Source/WebCore/Modules/webcodecs/ --apply
```

This walks `*.idl` + `*.h` under the area, dispatches the
`overlay-suggester` LLM, saves the proposal to
`threat-models/overlay-proposal-<timestamp>.{json,toml}`, and replaces
the `[prompt_overlay]` block in `config.toml`. **Review the diff
afterward** — `git diff config.toml` is your friend.

For large areas (>30 IDL files), use batching:
```bash
autosearch suggest-overlay --area Source/WebCore/Modules/WebGPU/ \
    --batch-size 30 --pool 8 --apply
```

### 2b. Write it by hand (areas without IDLs, or for tight control)

CoreGraphics has no IDLs (it's platform code below the IDL layer). The CG
overlay was written by hand. Edit `config.toml` to add:

```toml
[prompt_overlay]

attacker_surface = """
<2-3 paragraphs describing how attacker bytes / numerics / enums reach
this code area. Name the trust classes (trust_a = raw bytes, trust_b =
attacker numerics, trust_c = enum strings, not_attacker = callback
identities). Enumerate the JS/IPC/IDL entry points that ultimately call
into this code. Examples of primitive bug patterns the auditor should
hunt: int-overflow before allocation, OOB on tile drawing, UAF on async
callbacks, race-to-OOB on shared singletons, etc.
"""

scope_includes = """
Primary in-scope (audit fully):
  - Source/WebCore/platform/graphics/cg/*.cpp, *.mm, *.h
  - Source/WebCore/platform/graphics/cocoa/*.cpp, *.mm, *.h
  - Source/WebCore/platform/graphics/cv/*.cpp, *.mm, *.h
Cross-reference into <other relevant dirs>...
"""

extra_out_of_scope = """
  - Apple's framework code itself (CoreGraphics.framework, ImageIO.framework)
  - GPU-process IPC encoders/decoders (different trust boundary)
  - Skia / WebRender backends (different platform)
"""
```

The fuller CG example is in
`~/autosearch-workspaces/core-graphics/config.toml` lines 16-101 — a good
template for any platform-code audit.

**Pro tip**: name the closed-source-adjacent boundary explicitly
(`Apple framework code itself` is OUT, `the WebKit↔Apple-API glue is`
IN). The auditor reads this verbatim and uses it to decide which file
boundaries to honor.

---

## Step 3: Threat-model the area, per-file

```bash
cd ~/autosearch-workspaces/<name>
autosearch threat-model --per-file <path-or-paths>... \
    --include cpp,mm \
    --name <campaign-name>
```

Worked example:
```bash
cd ~/autosearch-workspaces/core-graphics
autosearch threat-model --per-file ~/WebKit/Source/WebCore/platform/graphics/cg/ \
    --include cpp,mm
```

What happens:
- Walks the directory for `*.cpp` and `*.mm` files
- Dispatches **one threat-modeler per file in parallel** (default 20 workers)
- Each call sees its single file deeply (much higher signal than one
  big context with all files)
- Skips utility files that don't have a real attacker surface ("no_threat_model")
- Saves output to
  `threat-models/<name>-<timestamp>/<file>.json` (one per file)

Expected output:
```
dispatching 31 threat-modelers (pool=20, model=claude-opus-4.7)...
per-file threat-modeling complete: 16 threat models, 15 no_threat_model,
0 parse_failed → 67 total candidate methods
  saved to: /path/to/workspace/threat-models/cg-20260510T174029Z/
  next: autosearch generate-targets --aggregate '...'
```

**Cost**: ~$0.20-0.50 per file with claude-opus-4.7. CG was 50 files
→ ~$6 setup. Budget accordingly.

For multiple directories (scope expansion later), pass them all in one
call so they share a single timestamp directory:
```bash
autosearch threat-model --per-file \
    ~/WebKit/Source/WebCore/platform/graphics/cocoa/ \
    ~/WebKit/Source/WebCore/platform/graphics/cv/ \
    --include cpp,mm \
    --name cocoa-cv
```

---

## Step 4: Aggregate threat models → targets

```bash
autosearch generate-targets \
    --aggregate 'threat-models/<campaign>-<timestamp>/*.json' \
    --apply
```

Worked example:
```bash
autosearch generate-targets \
    --aggregate 'threat-models/cg-20260510T174029Z/*.json' \
    --apply
```

What happens:
- Reads all per-file threat-model JSONs
- Dedupes candidate methods by `(target_class, target_method)`
- For >30 candidates, splits into batches and dispatches in parallel
- Writes the merged section to `targets.md` under
  `## Campaign N — aggregated from M per-file threat models`

Expected output:
```
aggregated 16 per-file threat models (15 skipped) → 67 unique candidate
methods, 70 sinks
candidate count (67) exceeds threshold (30); using batched generation
split into 3 batches (sizes: 30, 30, 7)
  batch 1/3: 30 candidates... emit=25 drop=0
  ...
batched generation complete:
  total emit: 65   total drop: 0   batches: 3 (0 failed)
appended to targets.md under 'Campaign N — ...'
```

`--apply` writes to `targets.md`. Without it, the proposed section is
just printed to stdout for review.

---

## Step 5: Build the MethodFacts oracle (optional but recommended)

The oracle gives auditors structured ground-truth about IDL exposure,
singletons, callers, and thread protections — see [README Oracles section](../README.md#oracles-mechanical-ground-truth-via-sdk-tools).

### 5a. Phase 1 only — fast (5 sec, no clang dep)

```bash
autosearch build-oracle --phase=1
```

Walks every `*.idl` under `Source/WebCore/`. Indexes ~1851 methods on
WebKit. Populates only `idl_exposure` (the cheapest fact family).

Use when:
- You don't have libclang installed
- You don't have `compile_commands.json` for the target
- You want to start auditing immediately and add Phase 2 later

### 5b. Phase 1 + Phase 2 — full (~10-15 min on 16 cores)

```bash
autosearch build-oracle --phase=all --workers=16
```

Adds the libclang AST pass: `mutable_globals_touched`, `callers_1hop`,
`thread_protections`. Indexes ~47K methods on WebKit GTK.

Auto-detects `compile_commands.json` and rewrites sandbox path prefixes
(e.g. `/sdk/webkit` → `~/WebKit`). Override remap with
`--remap OLD=NEW` (multi-pass for multiple rewrites).

For iterative work, scope to a subdirectory:
```bash
autosearch build-oracle --phase=all --scope=platform/graphics/cg/
```

The oracle is cached at `<workspace>/oracles/method_facts.json` keyed
on `target_sha`. Rebuild when the target changes.

---

## Step 6: Smoke-test with a single cycle

```bash
autosearch -w . run --once
```

This runs ONE full cycle and exits. Checks:
- Did the auditor cohort fire on every target?
- Did claims/cleans land in `findings.db`?
- Did the oracle load? (look for `dispatch oracle: loaded N methods`)
- Did the cost match expectation? (`autosearch findings cost`)

Inspect what happened:
```bash
autosearch findings list --limit 20
autosearch agent list --latest
autosearch agent show <id>           # full prompt+response of one run
```

Common issues at this stage:
- **All claims rejected as OFF_TARGET**: your overlay's `scope_includes`
  doesn't match the target paths
- **Auditor parse failures**: usually a model going off-prompt; one-shot
  repair retry handles most cases (look for `parse_status='repaired'`)
- **No oracle calls in events.jsonl**: oracle JSON not loaded; check
  `<workspace>/oracles/method_facts.json` exists and `AUTOSEARCH_WORKSPACE`
  env var is set (orchestrator sets it automatically each cycle)

---

## Step 7: Run the production loop

```bash
nohup autosearch -w . run --forever >> forever-launch.log 2>&1 &
echo "PID: $!"
```

Or with monitoring in another terminal:
```bash
autosearch -w . tui          # live dashboard
tail -f forever-launch.log   # raw log
```

Cycle wall is typically **3-15 min** depending on cohort size and
new-target density. Cost is **$1-2 per cycle** for a 6-target cohort
with 2 models. Budget $20-30/h for sustained operation.

---

## Step 8: Monitor + scope-expand as needed

### Periodic checks
```bash
autosearch -w . findings list --state confirmed
autosearch -w . findings cost
autosearch -w . findings show <id>          # full claim trace
```

### Scope expansion mid-campaign
When a campaign saturates its initial scope (~50+ cycles, no new
findings), expand it:
1. Run `threat-model --per-file <new-dir>` (Step 3)
2. Run `generate-targets --aggregate ... --apply` (Step 4) — appends a
   "Campaign N+1" section to `targets.md`
3. The orchestrator re-parses `targets.md` every cycle and picks up
   new targets automatically. Restart the loop only if you want them
   in immediate rotation rather than waiting for the current cycle's
   epoch-stale boost.
4. (optional) Update `[prompt_overlay].scope_includes` to declare the
   new dirs in scope (avoids `OFF_TARGET` rejections)

CG campaign added cocoa+cv mid-flight this way:
```bash
autosearch threat-model --per-file \
    ~/WebKit/Source/WebCore/platform/graphics/cocoa/ \
    ~/WebKit/Source/WebCore/platform/graphics/cv/ \
    --include cpp,mm --name cocoa-cv
autosearch generate-targets --aggregate 'threat-models/cocoa-cv-*/*.json' --apply
# (manual edit of config.toml's scope_includes)
kill <PID>; nohup autosearch -w . run --forever >> forever-launch.log 2>&1 &
```

### Stopping the loop
```bash
kill $PID                      # graceful shutdown (waits for current cycle)
kill -9 $PID                   # if it doesn't respond in 30s
```
The orchestrator marks any in-progress cycle as `aborted` on next start;
nothing is lost.

---

## Reference: the full CG bootstrap, end-to-end

For copy-paste convenience, here's exactly what was done for the
CoreGraphics campaign in this session:

```bash
# 1. workspace
autosearch init core-graphics --target ~/WebKit
cd ~/autosearch-workspaces/core-graphics

# 2. overlay (manual edit of config.toml — see Step 2b above)
$EDITOR config.toml

# 3. threat-model the cg/ directory per-file
autosearch -w . threat-model --per-file \
    ~/WebKit/Source/WebCore/platform/graphics/cg/ --include cpp,mm
# → 16 substantive threat models, 67 candidate methods

# 4. aggregate → 65 targets in targets.md
autosearch -w . generate-targets \
    --aggregate 'threat-models/cg-*/*.json' --apply

# 5. build the oracle (Phase 1 first to start fast; Phase 2 later)
autosearch -w . build-oracle --phase=1
# Later, ~108 min on 16 cores:
autosearch -w . build-oracle --phase=all --workers=16

# 6. smoke test
autosearch -w . run --once

# 7. production loop
nohup autosearch -w . run --forever >> forever-launch.log 2>&1 &
echo "PID: $!"

# 8. monitor
autosearch -w . tui
autosearch -w . findings list --state confirmed
```

Total wall time to first running cycle: ~15-30 minutes (mostly
threat-model + generate-targets dispatched LLM calls). Total cost to
first running cycle: ~$5-10.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `OraclesNotBootstrapped: No compile_commands.json` | Phase 2 build needs CDB | Use `--phase=1` only, or build target with `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` (or `bear --` for Xcode) |
| All claims `OFF_TARGET` | Overlay's `scope_includes` doesn't match | Add the actual file paths under audit to `scope_includes` |
| Many claims `DUPLICATE` | Auditor not seeing prior rejected-claim history | Pre-existing limitation; enriching `{{CONFIRMED}}` digest is on the roadmap |
| `parse_failed` rate > 10% | Model drift / prompt issue | Check `autosearch agent list --state parse_failed` then `agent show <id>` to see what the LLM emitted |
| Oracle queried but no `factsheet_citations` in cleans | Agents reading oracle but not citing in JSON | Phase 4 prompts updated; ensure oracle is loaded (look for log line); ensure auditor.md template has the citation schema |

For more, see [Known limitations](../README.md#known-limitations).
