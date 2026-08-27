# Task: architecture and components

Map the system into components and describe how they relate.

For each component, record: its name, what it is responsible for, where it lives
(paths), how access to it is controlled if at all, and the sensitivity of the
data it handles.

Then describe the architecture: the patterns in use (layered, event-driven,
MVC, microservice), how data moves between components, and where the system
integrates with anything external.

Pay particular attention to **trust boundaries** — the points where data or
control crosses from less-trusted to more-trusted. A request entering from the
internet, a message consumed from a queue, a file read from shared storage, a
call into an admin-only module. These boundaries are where later steps will look
for missing enforcement, so name them precisely rather than describing the
system as one undifferentiated whole.

The class and call-graph inventory is supplied to you. Use it to place
components; do not spend tokens re-listing symbols.
