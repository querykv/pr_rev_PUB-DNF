A security-focused pull-request reviewer. It builds a cached model of the
repository once, works out what a PR actually changed, runs deterministic detectors over the
changed surface, and gates the PR on findings it can attribute to the diff rather than to the code
that was already there.

DNF
