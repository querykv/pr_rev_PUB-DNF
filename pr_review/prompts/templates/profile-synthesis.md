# Report template: profile synthesis

Assemble the step outputs into one profile object. Carry the per-step
`structured` keys through unchanged — `description`, `tech_stack`,
`cloud_services`, `components`, `architecture`, `io_channels`, `code_flows`,
`roles`, `permission_checks`, `authentication`, `authorization`,
`sensitive_fields` — and add:

```json
{
  "notes": [
    "no ownership checks anywhere; every authenticated route is caller-trusting",
    "COVERAGE GAP: Django urls.py routes were not resolved to view classes",
    "CONFLICT: overview reports flask; io-channels found fastapi routers in app/v2/"
  ],
  "confidence": {
    "access_control_matrix": "high",
    "io_channels": "medium"
  }
}
```

Three kinds of entry belong in `notes`, and all three are load-bearing:

- **Findings** that span steps and no single worker could see.
- **`COVERAGE GAP:`** — anything nobody examined. An acknowledged blank is
  usable; a silent one is read as evidence of safety.
- **`CONFLICT:`** — where two steps disagree. Record both, do not pick a winner.
  Disagreement usually means the codebase does the thing two ways, which is
  often where the vulnerability is.

`confidence` is `high`, `medium`, or `low` per profile section, and should
reflect the *weakest* evidence the section rests on, not the average.
