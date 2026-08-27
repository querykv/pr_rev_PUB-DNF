# Report template: data sensitivity

```json
{
  "sensitive_fields": [
    {"name": "password_hash", "classification": "credential",
     "locations": ["app/models.py:User.password_hash"],
     "exposed_by": []},
    {"name": "notes", "classification": "pii",
     "locations": ["app/models.py:Ticket.notes"],
     "exposed_by": ["GET /tickets", "log:app/views.py:88"],
     "why": "free-text support bodies; name gives no indication"}
  ]
}
```

`classification` is one of: `pii`, `credential`, `financial`, `health`,
`secret`, `other`.

Include `why` for any field whose sensitivity is not evident from its name —
those are the ones this step exists to find, and the reason is what makes the
row reviewable.

`exposed_by` names the channel: an endpoint, a `log:<file>:<line>`, an export
job, or a third-party call. An empty list means you looked and found no
exposure — not that you did not look.
