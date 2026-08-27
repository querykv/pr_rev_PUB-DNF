# Report template: I/O channels and code flow

```json
{
  "io_channels": [
    {"name": "order-events", "kind": "queue", "direction": "inbound",
     "authenticated": false,
     "description": "consumes order events; payload trusted without validation"}
  ],
  "code_flows": [
    {"channel": "order-events", "files": ["app/workers/orders.py"],
     "entry_symbols": ["orders.handle_event"]}
  ]
}
```

`kind` is one of: `http_api`, `ui`, `queue`, `cron`, `cli`, `export`,
`notification`, `log`, `file`, `webhook`. `direction` is `inbound`, `outbound`,
or `bidirectional`. Use `null` for `authenticated` when you could not determine
it — do not default it to `false`, which reads as a confirmed finding.
