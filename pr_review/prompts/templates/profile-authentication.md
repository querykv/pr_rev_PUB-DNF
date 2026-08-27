# Report template: authentication

```json
{
  "authentication": {
    "methods": ["session_cookie", "api_key"],
    "session_management": "server-side sessions, 14d expiry, no rotation on privilege change",
    "mfa": false,
    "password_policy": "8 char minimum, no complexity rule",
    "notes": ["API keys never expire"]
  },
  "failure_paths": [
    {"location": "app/auth.py:57", "behaviour": "fail_open",
     "evidence": "except JWTError: return AnonymousUser()  # request continues"}
  ]
}
```

`mfa` may be `true`, `false`, or `null` when undetermined.

`behaviour` is `fail_closed`, `fail_open`, or `unknown`. Every `fail_open` entry
needs the line of code that shows it — this is the highest-value output of the
step and must not rest on inference.
