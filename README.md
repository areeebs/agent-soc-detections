# Agent SOC Detections

An open-source detection and replay pack for security teams investigating AI-agent and MCP tool activity. It turns normalized, privacy-conscious tool-call events into evidence-backed alerts that can be reviewed in a SOC workflow.

The project focuses on detection content and reproducible triage cases. It is not another MCP proxy, logger, or policy enforcement gateway. Existing audit sources can export events into the documented JSONL contract; the analyzer runs locally and makes no network requests.

## Detections

- **Unapproved sensitive action** — a shell, filesystem-write, or network-egress tool call has no approval reference.
- **Untrusted input reaches a sensitive action** — event lineage marks an input as untrusted and the call reaches a side-effecting tool without approval.
- **Tool outside declared agent scope** — the invoked tool is absent from the agent's declared allowlist.

Alerts include the event and trace identifiers, matched evidence, and an investigation prompt. They are leads for analyst review, not proof of compromise. The detections do not inspect raw prompts or tool arguments.

## Run locally

Requires Python 3.11+ and uses only the standard library.

```sh
python agent_soc.py examples/triage.jsonl
```

Output is JSON suitable for piping into a case-management adapter or preserving as a triage artifact. Input errors are reported with line numbers; malformed events are not silently dropped.

## Event contract

Each JSONL record represents one completed or attempted tool call. See [`schema/event.schema.json`](schema/event.schema.json) and [`examples/triage.jsonl`](examples/triage.jsonl). Events should contain metadata only:

- stable `event_id`, `trace_id`, timestamp, and agent identifier;
- tool name and a normalized category (`read`, `write`, `shell`, `network_egress`, or `other`);
- the declared `allowed_tools` list;
- source trust labels such as `untrusted_web`, `untrusted_email`, or `untrusted_document`;
- an approval reference when a human or policy engine approved the action.

Adapters should omit prompt text, tool arguments, credentials, and returned content. The schema is this project's interchange contract, not an MCP or OpenTelemetry standard. A future adapter can map OpenTelemetry GenAI tool spans or proxy audit records into it while retaining their original trace identifiers.

## SOC workflow

1. Export or adapt tool-call metadata from an existing audit source.
2. Run the analyzer and preserve its JSON output with the incident record.
3. Pivot on `trace_id`, validate the source/approval evidence, and check the agent's declared tool scope.
4. Tune categories and allowed-tool declarations to the deployment; do not suppress a finding solely because the tool name looks benign.

The synthetic fixture includes a clean event, an out-of-scope call, an unapproved shell action, and a tainted-input-to-egress path. It contains no real user or organization data.

## Existing ecosystem and scope

This pack complements projects that collect or audit MCP activity, including [AuditMCP](https://github.com/Ahlyx/auditmcp), [mcp-audit](https://github.com/P4ST4S/mcp-audit), and [AgentTrail](https://github.com/jgorodetsky/agenttrail). Its distinct contribution is a small, inspectable SOC rule set, a stable event contract, and replayable triage scenarios. It does not claim that all MCP clients emit the fields required for these detections.

OpenTelemetry's GenAI conventions describe agent and tool spans, but trust lineage and approval evidence are deployment-specific; this project keeps those as explicit adapter-supplied fields. See the [GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/) and the [MCP security considerations](https://modelcontextprotocol.io/specification/2026-07-28#security-and-trust-safety).

## License

MIT. See [`LICENSE`](LICENSE).
