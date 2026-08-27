# Report template: overview

Return a `structured` object with exactly these keys. They are parsed
mechanically into `ProjectProfile`; a renamed key is dropped without error.

```json
{
  "description": "2-3 sentences: what the system does and who it serves",
  "tech_stack": ["python3.11", "fastapi", "sqlalchemy", "postgres"],
  "cloud_services": ["aws-s3", "auth0"],
  "uncertain": ["dependency present but no usage found: celery"]
}
```

`tech_stack` and `cloud_services` are flat lists of lowercase identifiers.
Anything you could not confirm goes in `uncertain` rather than into the lists.
