# WebKit image-decoders template

This template provides a starter configuration for auditing WebKit image
decoders. Targets and rule files are empty: populate them for your own
campaign before running an audit.

## Files

- `config.toml`: model, cohort, timeout, and prompt-overlay configuration.
- `targets.md`: add one `<Class::Method>` per line or generate targets.
- `rules/catalog.md`: seed patterns for the refinement agent.
- `rules/mitigations.md`: seed known mitigations for the refinement agent.

## Usage

```bash
autosearch init webkit-image-decoders \
    --target ~/code/WebKit \
    --template webkit-image-decoders
cd ~/autosearch-workspaces/webkit-image-decoders
# Populate targets.md and review your rules before starting a cycle.
autosearch run --once
```

See [the runbook](../../docs/runbook-new-audit.md) for target generation.
