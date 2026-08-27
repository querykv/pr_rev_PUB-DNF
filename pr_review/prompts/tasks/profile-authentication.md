# Task: authentication

Describe how the system establishes who a caller is.

Record: the authentication methods in use (session cookie, JWT, OAuth2, API key,
mTLS, basic), how sessions are created, stored, expired and invalidated, whether
multi-factor authentication exists and where it is enforced, and the password or
credential policy if one exists.

Then answer the questions that decide whether it holds:

- Where does the system decide a request is authenticated, and can any route
  reach handler code without passing that point?
- How are tokens or session identifiers generated, and are they signed and
  verified with a key the code actually validates?
- What happens on the failure path — does an expired, malformed, or absent
  credential deny the request, or fall through to an unauthenticated default?

The last one matters most: **fail-open authentication looks identical to working
authentication in every normal test**, which is why it survives to production.
Read the error and exception paths, not just the success path.

The role vocabulary from the previous step is available to you.
