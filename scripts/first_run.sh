#!/usr/bin/env bash
# first_run.sh — bootstrap a fresh autosearch workspace on a new codebase.
#
# Chains the Phase-1 commands you'd otherwise run by hand:
#   init  →  threat-model --per-file  →  generate-targets --apply
#         →  review-scope --gate     →  suggest-overlay --apply
#         →  build-oracle --phase=1
#
# After this completes you should be able to:
#   autosearch -w <workspace> run --forever
#
# IMPORTANT: this script is for IDL-rich code areas (e.g. WebCodecs,
# WebGPU, MSE) where suggest-overlay can auto-generate the
# [prompt_overlay] block from IDL files. For platform code WITHOUT IDLs
# (e.g. Source/WebCore/platform/graphics/cg/, IPC handlers), you must
# write the overlay by hand — see docs/runbook-new-audit.md for a
# step-by-step manual walkthrough.
#
# Run this from inside the autosearch repo (or anywhere — it just needs
# the `autosearch` CLI on PATH).

set -euo pipefail

# ---- defaults ----------------------------------------------------------------
NAME=""
TARGET=""
AREA=""
TEMPLATE=""
INCLUDE="cpp,mm,cc"   # .mm covers Apple-platform code; .cc covers a few WTF/Skia files
RECURSIVE=0
MAX_FILES=80
POOL=20
ROOT="${HOME}/autosearch-workspaces"
SKIP_THREAT_MODEL=0
SKIP_OVERLAY=0
SKIP_SCOPE_REVIEW=0
BUILD_ORACLE="1"          # 1 (text-only IDL parse, ~5s) | all (libclang, 10-15min) | none
FORCE=0
ASSUME_YES=0
DRY_RUN=0

# ---- pretty printing ---------------------------------------------------------
if [[ -t 1 ]]; then
  C_BOLD="\033[1m"; C_DIM="\033[2m"; C_GREEN="\033[32m"
  C_YELLOW="\033[33m"; C_RED="\033[31m"; C_BLUE="\033[34m"; C_OFF="\033[0m"
else
  C_BOLD=""; C_DIM=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_BLUE=""; C_OFF=""
fi

step()  { echo -e "\n${C_BOLD}${C_BLUE}▶ $*${C_OFF}"; }
ok()    { echo -e "${C_GREEN}✓${C_OFF} $*"; }
warn()  { echo -e "${C_YELLOW}⚠${C_OFF} $*"; }
err()   { echo -e "${C_RED}✗${C_OFF} $*" >&2; }
note()  { echo -e "${C_DIM}  $*${C_OFF}"; }

usage() {
  cat <<'EOF'
first_run.sh — bootstrap a new autosearch workspace end-to-end.

Required:
  --name NAME              Workspace name (e.g. webaudio-test)
  --target PATH            Path to target source repo (read-only)
  --area PATH              Code area inside target (relative to repo root,
                           e.g. Source/WebCore/Modules/webaudio)

Optional:
  --template NAME          Starter template (webcodecs | webkit-image-decoders)
                           Default: none — workspace is built from scratch.
  --include EXTS           Extensions for per-file walk      (default: cpp,mm,cc)
  --recursive              Walk --area subdirectories        (default: off)
  --max-files N            Cap on per-file dispatch          (default: 80)
  --pool N                 Parallel threat-modeler workers   (default: 20)
  --root PATH              Workspaces root                   (default: ~/autosearch-workspaces)
  --skip-threat-model      Don't run per-file threat-modeling
  --skip-overlay           Don't auto-generate [prompt_overlay]
  --skip-scope-review      Don't gate generated targets through scope-reviewer
  --build-oracle PHASE     Build the MethodFacts oracle. PHASE = 1 (text-only IDL
                           parse, ~5s, no clang dep), all (Phase 1 + libclang AST
                           pass, 10-15 min on 16 cores), or none. Default: 1.
  --force                  Overwrite existing workspace
  --yes                    Skip the confirmation prompt
  --dry-run                Print what would happen, don't execute
  -h | --help              Show this help

Phases (each can be skipped individually):
  1. autosearch init           — create workspace skeleton
  2. threat-model --per-file   — one LLM call per file under --area
  3. generate-targets --apply  — merge per-file outputs into targets.md
  4. review-scope --gate       — sanity-check the generated target list
  5. suggest-overlay --apply   — auto-generate the [prompt_overlay] block
  6. build-oracle              — index methods for oracle_method_facts SDK tool
  7. summary + next-step hint

For platform code WITHOUT IDLs (e.g. Source/WebCore/platform/graphics/cg/),
suggest-overlay can't help — write the [prompt_overlay] block by hand
and use --skip-overlay. See docs/runbook-new-audit.md for the manual path.

Examples:
  # Fully auto bootstrap on an IDL-rich code area:
  scripts/first_run.sh \
    --name webaudio-test \
    --target ~/code/WebKit \
    --area Source/WebCore/Modules/webaudio \
    --recursive --yes

  # Use a curated template, just expand its targets and keep its overlay:
  scripts/first_run.sh \
    --name webcodecs2 \
    --target ~/code/WebKit \
    --template webcodecs \
    --area Source/WebCore/Modules/webcodecs \
    --skip-overlay --yes

  # Full oracle (libclang AST pass) for higher-quality cleans:
  scripts/first_run.sh \
    --name mse \
    --target ~/code/WebKit \
    --area Source/WebCore/Modules/mediasource \
    --build-oracle all --yes
EOF
}

# ---- arg parsing -------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)              NAME="$2"; shift 2 ;;
    --target)            TARGET="$2"; shift 2 ;;
    --area)              AREA="$2"; shift 2 ;;
    --template)          TEMPLATE="$2"; shift 2 ;;
    --include)           INCLUDE="$2"; shift 2 ;;
    --recursive)         RECURSIVE=1; shift ;;
    --max-files)         MAX_FILES="$2"; shift 2 ;;
    --pool)              POOL="$2"; shift 2 ;;
    --root)              ROOT="$2"; shift 2 ;;
    --skip-threat-model) SKIP_THREAT_MODEL=1; shift ;;
    --skip-overlay)      SKIP_OVERLAY=1; shift ;;
    --skip-scope-review) SKIP_SCOPE_REVIEW=1; shift ;;
    --build-oracle)      BUILD_ORACLE="$2"; shift 2 ;;
    --force)             FORCE=1; shift ;;
    --yes|-y)            ASSUME_YES=1; shift ;;
    --dry-run)           DRY_RUN=1; shift ;;
    -h|--help)           usage; exit 0 ;;
    *)                   err "unknown arg: $1"; usage; exit 2 ;;
  esac
done

# ---- preflight ---------------------------------------------------------------
[[ -z "$NAME"   ]] && { err "--name is required";   usage; exit 2; }
[[ -z "$TARGET" ]] && { err "--target is required"; usage; exit 2; }
[[ -z "$AREA"   ]] && { err "--area is required";   usage; exit 2; }

case "$BUILD_ORACLE" in
  1|all|none) ;;
  *) err "--build-oracle must be one of: 1, all, none (got: $BUILD_ORACLE)"; exit 2 ;;
esac

if ! command -v autosearch >/dev/null 2>&1; then
  err "autosearch CLI not on PATH. Activate the venv:  source ~/autosearch/.venv/bin/activate"
  exit 2
fi
if ! command -v copilot >/dev/null 2>&1; then
  warn "copilot CLI not on PATH — agent dispatch will fail. Continuing anyway."
fi

TARGET="$(cd "$TARGET" 2>/dev/null && pwd)" || { err "--target not a real dir: $TARGET"; exit 2; }
AREA_FULL="$TARGET/$AREA"
if [[ ! -d "$AREA_FULL" && ! -f "$AREA_FULL" ]]; then
  err "--area not found inside target: $AREA_FULL"
  exit 2
fi

WORKSPACE="$ROOT/$NAME"

if [[ -d "$WORKSPACE" && $FORCE -eq 0 ]]; then
  err "workspace already exists: $WORKSPACE  (use --force to overwrite)"
  exit 2
fi

# ---- show plan ---------------------------------------------------------------
echo
echo -e "${C_BOLD}autosearch first_run plan${C_OFF}"
echo "  workspace:        $WORKSPACE"
echo "  target repo:      $TARGET"
echo "  area:             $AREA  (= $AREA_FULL)"
echo "  template:         ${TEMPLATE:-<none, build from scratch>}"
echo "  include exts:     $INCLUDE"
echo "  recursive:        $([[ $RECURSIVE -eq 1 ]] && echo yes || echo no)"
echo "  max files:        $MAX_FILES"
echo "  parallel pool:    $POOL"
echo
echo "  phases:"
echo "    1. init                                $([[ $FORCE -eq 1 ]] && echo '(force)' || echo '')"
echo "    2. threat-model --per-file             $([[ $SKIP_THREAT_MODEL -eq 1 ]] && echo '(skip)' || echo '')"
echo "    3. generate-targets --aggregate        $([[ $SKIP_THREAT_MODEL -eq 1 ]] && echo '(skip)' || echo '')"
echo "    4. review-scope --gate                 $([[ $SKIP_SCOPE_REVIEW -eq 1 ]] && echo '(skip)' || echo '')"
echo "    5. suggest-overlay --apply             $([[ $SKIP_OVERLAY -eq 1 ]] && echo '(skip)' || echo '')"
echo
warn "Phases 2-5 spend LLM calls. Rough budget: 1 call/file (Phase 2) + 1 (Phase 3) + 1 (Phase 4) + 1 (Phase 5)."
warn "  → up to ~$(( MAX_FILES + 3 )) total LLM calls if --area saturates --max-files."
echo

if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 ]]; then
  read -r -p "Proceed? [y/N] " resp
  [[ "$resp" =~ ^[Yy]$ ]] || { echo "aborted."; exit 0; }
fi

# ---- helper: run-or-print ----------------------------------------------------
run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "${C_DIM}+ $*${C_OFF}"
  else
    echo -e "${C_DIM}+ $*${C_OFF}"
    "$@"
  fi
}

# ---- phase 1: init -----------------------------------------------------------
step "Phase 1/6  —  autosearch init"
INIT_ARGS=( "$NAME" --target "$TARGET" --root "$ROOT" )
[[ -n "$TEMPLATE" ]] && INIT_ARGS+=( --template "$TEMPLATE" )
[[ $FORCE -eq 1   ]] && INIT_ARGS+=( --force )
run autosearch init "${INIT_ARGS[@]}"
ok "workspace initialized at $WORKSPACE"

# Use -w going forward so we never depend on cwd.
AS=( autosearch -w "$WORKSPACE" )

# ---- phase 2: threat-model ---------------------------------------------------
TM_DIR=""
if [[ $SKIP_THREAT_MODEL -eq 1 ]]; then
  warn "Phase 2 skipped (--skip-threat-model)"
else
  step "Phase 2/6  —  threat-model --per-file  (pool=$POOL, max=$MAX_FILES)"
  TM_NAME="bootstrap"
  TM_ARGS=( threat-model "$AREA_FULL" --per-file
            --include "$INCLUDE"
            --pool "$POOL"
            --max-files "$MAX_FILES"
            --name "$TM_NAME" )
  [[ $RECURSIVE -eq 1 ]] && TM_ARGS+=( --recursive )

  run "${AS[@]}" "${TM_ARGS[@]}"

  # Locate the per-file output directory (most recent under threat-models/).
  if [[ $DRY_RUN -eq 0 ]]; then
    TM_DIR="$(ls -dt "$WORKSPACE"/threat-models/${TM_NAME}-* 2>/dev/null | head -1 || true)"
    if [[ -z "$TM_DIR" ]]; then
      err "no threat-model output dir found under $WORKSPACE/threat-models/"
      exit 1
    fi
    n_files="$(ls "$TM_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ')"
    ok "per-file threat models written: $TM_DIR  ($n_files files)"
  fi
fi

# ---- phase 3: generate-targets -----------------------------------------------
GENERATED_JSON=""
if [[ $SKIP_THREAT_MODEL -eq 1 ]]; then
  warn "Phase 3 skipped (no per-file threat models to aggregate)"
else
  step "Phase 3/6  —  generate-targets --aggregate --apply"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "${C_DIM}+ ${AS[*]} generate-targets --aggregate '<TM_DIR>/*.json' --apply${C_OFF}"
  else
    run "${AS[@]}" generate-targets --aggregate "$TM_DIR/*.json" --apply
    GENERATED_JSON="$(ls -t "$WORKSPACE"/threat-models/generated-*.json 2>/dev/null | head -1 || true)"
    if [[ -n "$GENERATED_JSON" ]]; then
      ok "generated targets JSON: $GENERATED_JSON"
    fi
    n_targets="$(grep -cE '^[A-Za-z_][A-Za-z0-9_:]*\s*#' "$WORKSPACE/targets.md" 2>/dev/null || echo 0)"
    ok "targets.md now has $n_targets methods"
  fi
fi

# ---- phase 4: review-scope ---------------------------------------------------
if [[ $SKIP_SCOPE_REVIEW -eq 1 || -z "$GENERATED_JSON" ]]; then
  if [[ $SKIP_SCOPE_REVIEW -eq 1 ]]; then
    warn "Phase 4 skipped (--skip-scope-review)"
  else
    note "Phase 4 skipped (no generated-targets JSON to gate)"
  fi
else
  step "Phase 4/6  —  review-scope --gate  (advisory)"
  # advisory only — failures here don't abort the bootstrap
  if ! run "${AS[@]}" review-scope --gate "$GENERATED_JSON"; then
    warn "review-scope returned non-zero; review the output above"
  fi
fi

# ---- phase 5: suggest-overlay ------------------------------------------------
if [[ $SKIP_OVERLAY -eq 1 ]]; then
  warn "Phase 5 skipped (--skip-overlay)"
else
  step "Phase 5/6  —  suggest-overlay --apply"
  run "${AS[@]}" suggest-overlay --area "$AREA_FULL" --apply
  ok "[prompt_overlay] block written to $WORKSPACE/config.toml"
fi

# ---- phase 6: build-oracle ---------------------------------------------------
if [[ "$BUILD_ORACLE" == "none" ]]; then
  warn "Phase 6 skipped (--build-oracle none)"
else
  step "Phase 6/6  —  build-oracle --phase=$BUILD_ORACLE"
  if [[ "$BUILD_ORACLE" == "all" ]]; then
    note "  (libclang AST pass — cold ~10-15 min on 16 cores)"
  fi
  if ! run "${AS[@]}" build-oracle --phase="$BUILD_ORACLE"; then
    warn "build-oracle failed; the audit can still run without it (oracle"
    warn "tools just won't be available to agents). For Phase 2 you may need"
    warn "libclang installed (apt install libclang-18-dev / brew install llvm)"
    warn "and a compile_commands.json in the target repo. See"
    warn "docs/runbook-new-audit.md and README's 'Oracles' section."
  else
    ok "MethodFacts oracle written to $WORKSPACE/oracles/method_facts.json"
  fi
fi

# ---- summary -----------------------------------------------------------------
echo
echo -e "${C_BOLD}${C_GREEN}━━━ bootstrap complete ━━━${C_OFF}"
echo
echo -e "  workspace:    ${C_BOLD}$WORKSPACE${C_OFF}"
if [[ $DRY_RUN -eq 0 ]]; then
  echo "  targets:      $(grep -cE '^[A-Za-z_][A-Za-z0-9_:]*\s*#' "$WORKSPACE/targets.md" 2>/dev/null || echo '?') methods in targets.md"
  echo "  config.toml:  $(wc -l < "$WORKSPACE/config.toml" | tr -d ' ') lines"
fi
echo
echo "Next steps:"
echo "  ${C_DIM}# review what was generated:${C_OFF}"
echo "  less $WORKSPACE/targets.md"
echo "  less $WORKSPACE/config.toml"
echo
echo "  ${C_DIM}# start the audit loop:${C_OFF}"
echo "  autosearch -w $WORKSPACE run --forever"
echo
echo "  ${C_DIM}# in a second terminal, watch progress:${C_OFF}"
echo "  autosearch -w $WORKSPACE tui"
echo
