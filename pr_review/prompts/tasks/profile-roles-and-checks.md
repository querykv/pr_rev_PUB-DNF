# Task: roles and permission checks

Establish the vocabulary of authorization: who the system thinks its callers
are, and the mechanisms that enforce it.

**Roles.** Find where roles or permissions are *defined* — enum classes, string
constants, database tables, identity-provider claims, group names. For each,
record its name, what it is meant to permit, where it is defined, and whether it
inherits from another.

**Permission checks.** Find the mechanisms that enforce those roles: decorators,
middleware, framework dependencies, mixins, policy classes, and inline
conditionals. For each record what it is called, what kind of mechanism it is,
where it lives, and which roles it admits.

Two things are easy to miss and worth looking for specifically:

- **Checks that authenticate but do not authorize.** A decorator that only
  confirms a caller is logged in, applied where a role check was intended, is
  one of the most common real access-control failures.
- **Roles that exist in the vocabulary but are never enforced anywhere.** A role
  constant no check references usually means enforcement was intended and never
  written.

The guards attached to each endpoint are supplied to you. Your job is what those
guards actually *mean* — not where they are.
