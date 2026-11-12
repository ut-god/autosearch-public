# webcodecs template

WebCodecs JS API audit — `Source/WebCore/Modules/webcodecs/`.

## What this template covers

The WebKit WebCodecs implementation: ~62 files, ~6KLOC of C++ exposed
to attacker-controlled JS via `VideoFrame`, `AudioData`, `VideoDecoder`,
`VideoEncoder`, `AudioDecoder`, `AudioEncoder`, `EncodedVideoChunk`,
`EncodedAudioChunk`. Two main risk shapes:

1. **Pixel/sample buffer arithmetic** — `copyTo`, `create`,
   `computeLayoutAndAllocationSize`, `parseVideoFrameCopyToOptions`.
   Attacker controls buffer dimensions / layout / target size.
2. **Async lifetime** — decoder/encoder state machines (`configure`,
   `decode`/`encode`, `flush`, `reset`, `close`) plus the
   `WebCodecsBase` control-message queue. Output callbacks fire across
   close / GC boundaries.

## Files

| File | Role |
|---|---|
| `config.toml` | Workspace config + `[prompt_overlay]` (WebCodecs JS attacker surface) |
| `targets.md` | Empty — add or generate in-scope methods before running |
| `rules/catalog.md` | Empty — populated by refinement |
| `rules/mitigations.md` | Empty — populated by refinement |

## Usage

```
autosearch init webcodecs-test --target ~/code/WebKit --template webcodecs
cd ~/autosearch-workspaces/webcodecs-test

# Populate targets.md before starting a cycle. See the runbook for target generation.
# Smoke test on one method first
autosearch run --target-method WebCore::WebCodecsVideoFrame::copyTo

# If healthy, full hybrid 6×2 cycle
autosearch run --once

# Live monitor in another terminal
autosearch tui
```

## What this campaign tests for the autosearch system

- Does the hybrid 6×2 cohort + cross-vendor quorum work on a non-image-decoder surface?
- Does the prompt overlay correctly substitute the WebCodecs attacker surface (vs the WebKit image-decoders default)?
- Does the auditor's catalog discovery start from zero and grow useful R-NN entries via refinement?
- Does the imported WebKit-image-decoder catalog (in a sibling workspace) over-influence WebCodecs audits, or do agents stay grounded in source evidence?

See [the runbook](../../docs/runbook-new-audit.md) for target generation.
