# Task: I/O channels and code flow

Inventory every way data enters or leaves this system, and map each to the code
that implements it.

Channels include: HTTP APIs and UIs, message queues and event consumers,
scheduled jobs, CLI entry points, file imports and exports, outbound
notifications (email, webhooks, push), and log or telemetry sinks.

For each channel record: what it is, direction (inbound, outbound, or both),
whether it is authenticated, and the files and entry symbols that implement it.

The endpoint list is supplied to you deterministically — every route, its
methods, and the guards found on it. **Do not re-enumerate endpoints.** Your
work is the channels that are *not* HTTP routes, and which are routinely missed:
a queue consumer that trusts its payload, a cron job running with elevated
rights, a webhook receiver with no signature check, a debug export.

Outbound channels matter as much as inbound. A log line, an error report to a
third party, and an export job are all ways data leaves the system, and are
where sensitive-data exposure usually happens.
