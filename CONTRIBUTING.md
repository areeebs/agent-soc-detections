# Contributing

Contributions should improve detection quality, event interoperability, or analyst triage. Please include synthetic, privacy-safe examples and document assumptions, false-positive conditions, and evidence fields for every new rule.

Do not submit production prompts, tool arguments, results, credentials, or customer traces. Prefer minimal metadata-only events. Changes that make decisions from missing telemetry should explain the resulting blind spots and alert behavior.

Before proposing an upstream event mapping, cite its source schema and identify which fields are standardized versus deployment-specific. The tool is a local analysis aid and must not execute, block, or authorize agent actions.
