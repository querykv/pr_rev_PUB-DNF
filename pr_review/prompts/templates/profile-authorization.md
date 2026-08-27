# Report template: authorization and access-control matrix

Two outputs. Both are required.

## 1. The model

```json
{
  "authorization": {
    "model": "rbac",
    "resource_level_controls": false,
    "default_posture": "allow",
    "enforcement_points": ["AuthenticationMiddleware", "IsAdminUser"],
    "notes": ["route-level only; no ownership checks found"]
  }
}
```

`model` is one of: `rbac`, `abac`, `acl`, `ownership`, `mixed`, `none`,
`unknown`. `default_posture` is `deny`, `allow`, or `unknown`.

## 2. The matrix — `endpoint_csv_rows`

A list of CSV strings. **The first element must be the header, exactly:**

```
endpoint,http_method,controller,required_roles,auth_pattern,enforcement,file,line
```

Then one row per endpoint:

```
/admin/export,POST,admin_export,admin,none,declared_not_enforced,app.py,33
/items/{iid},GET,get_item,,none,none,api.py,27
/profile/{uid},GET,get_profile,user,decorator:login_required,enforced,app.py,28
```

Column rules:

- `required_roles` — `;`-separated, empty when none apply.
- `auth_pattern` — `<kind>:<name>` (`decorator:login_required`,
  `dependency:get_current_user`, `permission_classes:IsAuthenticated`,
  `mixin:LoginRequiredMixin`) or `none`.
- `enforcement` — `enforced`, `declared_not_enforced`, or `none`. Use
  `declared_not_enforced` when a requirement is stated but no runtime check
  backs it, **and when a login check exists but the handler acts on a
  caller-supplied identifier without an ownership check** — an authenticated
  IDOR is not enforced authorization.
- Quote any field containing a comma.

These rows are merged across workers with no further model involvement. A row
with the wrong column count is dropped silently, so count your commas.
