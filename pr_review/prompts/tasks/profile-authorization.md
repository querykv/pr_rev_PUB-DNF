# Task: authorization and the access-control matrix

Determine, for every endpoint, which roles may reach it and whether that is
actually enforced. This is the highest-value output of the entire profile.

**First describe the model:** RBAC, ABAC, ACL, ownership-based, mixed, or none.
Are controls resource-level (can this user act on *this* record) or only
route-level (can this user reach this route at all)? Is the default posture deny
or allow?

**Then produce one matrix row per endpoint.** Every endpoint is supplied to you
with its route, methods, and detected guards — you are not discovering them, you
are judging them. For each, decide the `enforcement` value:

- `enforced` — a check runs before handler logic and admits only the intended
  roles. You traced it.
- `declared_not_enforced` — a role requirement is documented, annotated, or
  implied by naming, but no runtime check backs it. **This is the highest-signal
  row in the matrix**: the intent is on record and the implementation is absent,
  which is exactly what a reviewer needs to see.
- `none` — no check, and none was implied.

Resolve resource-level authorization explicitly. An endpoint that requires login
and then acts on an object identifier taken from the request, without checking
that the caller owns that object, is **not** enforced — it is an IDOR. This
distinction is invisible to the deterministic extraction, which can only see
that *some* guard is present, and it is the single most valuable judgement you
make here.

Where an explicit opt-out is present (`AllowAny`, an exemption decorator),
record it as a deliberate decision rather than as a missing check, and note
whether the endpoint's sensitivity justifies it.

Emit one CSV row per endpoint into `endpoint_csv_rows`. These rows are merged
across all workers mechanically, with no further model involvement — so a
malformed row is dropped silently rather than corrected. Follow the column order
in your report template exactly.
