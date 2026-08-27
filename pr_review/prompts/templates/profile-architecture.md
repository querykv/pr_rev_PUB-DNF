# Report template: architecture and components

```json
{
  "components": [
    {"name": "api", "role": "public HTTP surface", "location": ["app/api/"],
     "access_control": "session cookie via middleware",
     "data_sensitivity": "confidential"}
  ],
  "architecture": {
    "patterns": ["layered", "repository"],
    "data_flow": ["http -> service -> repository -> postgres"],
    "integrations": ["stripe", "sendgrid"]
  },
  "trust_boundaries": [
    {"name": "internet -> api", "crossing": "unauthenticated HTTP request",
     "enforced_by": "AuthenticationMiddleware", "file": "app/middleware.py"}
  ]
}
```

`data_sensitivity` is one of: `none`, `internal`, `confidential`, `regulated`.
For a boundary with no enforcement, set `enforced_by` to `"none"` — that is a
finding, not a blank.
