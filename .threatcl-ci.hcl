# Drift review config — https://github.com/threatcl/drift-action
#
# ENISA Playbook 01's release gate ends with refresh triggers: a new API, an
# auth change, new sensitive data, a dependency change, an OTA change, a major
# architecture change. policy/enisa-release-gate.hcl cannot check any of them,
# because none is a property of the model — they are properties of a diff.
#
# threat-model.yml covers the easy direction: the model changed, so re-run the
# gate. This covers the direction that actually decays. The code changed, and
# nobody opened the .tm.hcl.

# Required, not optional. Discovery looks for *.tm.hcl at the repo root and
# under threatmodels/; this repo keeps its single model in threatmodel/,
# singular, so without this line there is nothing for the action to assess.
model_paths = ["threatmodel/sensorhub.tm.hcl"]

# `categories` is deliberately unset, so all six run. Every one of them has
# something to bite on in this tree: the services carry controls the model
# claims are implemented, go.mod is empty so any dependency is conspicuous,
# and the DFD names every process and flow that exists.

# Paths that survive when a large diff is narrowed to security-relevant files.
#
# The built-in heuristic already catches most of this tree by name — anything
# with auth, store, tenant, rbac or server in the path — but it would drop
# cmd/*/main.go and internal/mqtt/, which is exactly where the listener's TLS
# policy is wired up and where device input is parsed. In a product whose whole
# job is enforcing the boundaries on the diagram, the whole product is
# security-relevant.
trigger_paths = ["cmd/", "internal/", "tests/"]

# never: a drift finding comments, it does not block the merge.
#
# This repository is emphatic elsewhere that a gate should fail the build. The
# eleven invariants in policy/ exit non-zero and turn the pull request red, and
# the README makes a point of it. The difference is what is being checked. An
# invariant is a deterministic property of the model — "this control names an
# owner" is true or it is not. A drift review is a judgement about whether a
# diff outgrew its model, and this repo already treats judgement as a warning
# rather than an error: see `threat_count_in_enisa_range`.
#
# So deterministic checks block, and judgement advises — in a comment, with
# file:line evidence, for a human to weigh. Set "on-action-required" if you
# would rather it blocked.
fail_mode = "never"

# The `llm` and `limits` blocks are left at their defaults on purpose. Those
# defaults are compiled into the action, and the workflow pins the action by
# commit, so pinning them again here would mean a future release could not
# improve them without someone remembering to edit this file.
