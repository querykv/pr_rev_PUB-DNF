# Task: overview

Establish what this project *is*, so later steps can judge whether its security
posture fits its purpose.

Answer three things:

1. **What the system does**, in two or three sentences. Who uses it, and what
   would it mean for them if it were compromised.
2. **Tech stack** — language versions, web framework, ORM/database, task queue,
   template engine, auth libraries. Read dependency manifests and settings
   files; do not infer a stack from directory names.
3. **Cloud and external services** — anything the code talks to that it does not
   control: managed databases, object storage, queues, identity providers,
   payment processors, third-party APIs.

Read dependency manifests, settings/config modules, the README, and container
or IaC definitions. This step should be cheap: it is orientation, not analysis.

Where a dependency is present but you cannot tell whether it is actually used,
say so rather than listing it as part of the stack — a phantom framework in the
profile sends every later step looking for patterns that are not there.
