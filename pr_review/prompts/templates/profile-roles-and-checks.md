# Report template: roles and permission checks

```json
{
  "roles": [
    {"name": "admin", "description": "full access",
     "source": "app/constants.py:Role", "inherits": ["staff"]}
  ],
  "permission_checks": [
    {"name": "IsAdminUser", "kind": "policy_class",
     "file": "app/permissions.py", "line": 12, "grants": ["admin"]}
  ],
  "unenforced_roles": ["auditor"],
  "authn_used_as_authz": [
    {"check": "login_required", "file": "app/views.py", "line": 44,
     "note": "confirms a session only; the handler is admin-scoped"}
  ]
}
```

`kind` is one of: `decorator`, `middleware`, `dependency`, `mixin`,
`inline_conditional`, `policy_class`, `other`.

`unenforced_roles` lists roles defined in the vocabulary that no check
references. `authn_used_as_authz` lists places where an authentication check
stands in for a role check.
