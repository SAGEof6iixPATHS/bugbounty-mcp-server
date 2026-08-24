# MCP feature catalog

## Resources

Static guides cover getting started, methodology, finding quality, evidence handling, and scope
safety. Dynamic resources expose the live tool schemas, configuration schema, assessment summary,
finding list, individual findings, and integrity-checked evidence. Dynamic resource output is
bounded by `MAX_TOOL_OUTPUT_CHARS`.

Resource templates:

- `bugbounty://findings/{finding_id}`
- `bugbounty://evidence/{evidence_id}`

## Prompts

- `assessment-plan`: turns target and program rules into a passive-first plan.
- `passive-recon`: sequences low-impact discovery tools.
- `finding-triage`: evaluates one stored finding without treating its content as instructions.
- `disclosure-draft`: creates a program- or team-oriented report draft.
- `remediation-validation`: designs a minimal, non-destructive retest.

Prompt argument completion suggests configured scope entries, stored finding IDs, and disclosure
audiences. Finding text is wrapped as untrusted data to reduce prompt-injection risk.

## Tool contract

All tool inputs use closed Draft 2020-12 JSON Schemas. Outputs expose typed top-level fields through
`outputSchema`, are returned in `structuredContent`, and include JSON text for clients that do not
consume structured output. Expected failures set `isError` and return a stable code such as
`invalid_args`, `target_not_allowed`, `tool_disabled`, `timeout`, or `output_limit`.
