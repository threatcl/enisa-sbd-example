# ENISA Secure by Design and Default Playbook 01 — release gate, as policy.
#
# Playbook 01 ends with a six-item release gate written as a markdown
# checklist. A checklist is only as good as the person remembering to read it.
# Each invariant below encodes one of those checkboxes so that CI ticks it,
# on every pull request, against the actual threat model.
#
# Run it with:
#   threatcl validate -invariants=policy/enisa-release-gate.hcl threatmodel/*.hcl
#
# Severity "error" fails validation and so fails the build. Severity "warning"
# reports without blocking — used where the playbook asks for judgement rather
# than a hard rule.
#
# Source: https://github.com/enisaeu/enisa-sbd-playbook
#         playbooks/01-trust-boundaries-and-threat-modelling.md

# ── Gate item 1 ────────────────────────────────────────────────────────────
# "Diagram updated for this release (components, flows, dependencies reflect
# reality)"
#
# The diagram cannot go stale independently, because it is generated from this
# model in CI. What policy can check is that a diagram exists at all.

invariant "diagram_exists" {
  description   = "ENISA gate 1: the model must carry a data flow diagram, which CI renders on every change"
  target        = "threatmodel"
  condition     = length(item.data_flow_diagrams) > 0
  error_message = "threat model '${item.name}' has no data_flow_diagram_v2 block, so no diagram can be generated for the release gate"
}

# ── Gate item 2 ────────────────────────────────────────────────────────────
# "Trust boundaries and privileged paths clearly marked"
#
# ENISA names the boundaries it expects to see reasoned about: internet-back
# end, tenant-tenant, device-cloud, user-admin. Every element must sit in a
# declared trust zone, otherwise the boundary it crosses is unstated.

invariant "processes_declare_trust_zone" {
  description   = "ENISA gate 2: every process sits inside a declared trust zone"
  target        = "process"
  condition     = item.trust_zone != ""
  error_message = "process '${item.name}' is not in a trust zone, so the boundaries it sits behind are unstated"
}

invariant "data_stores_declare_trust_zone" {
  description   = "ENISA gate 2: every data store sits inside a declared trust zone"
  target        = "data_store"
  condition     = item.trust_zone != ""
  error_message = "data store '${item.name}' is not in a trust zone, so the boundaries it sits behind are unstated"
}

invariant "external_elements_declare_trust_zone" {
  description   = "ENISA gate 2: every external element sits inside a declared trust zone"
  target        = "external_element"
  condition     = item.trust_zone != ""
  error_message = "external element '${item.name}' is not in a trust zone, so the boundaries it sits behind are unstated"
}

# A flow whose protocol is unstated cannot be reviewed for transport security,
# and it renders as an unlabelled arrow on the diagram ENISA asks you to draw.

invariant "flows_declare_protocol" {
  description   = "ENISA gate 2: every data flow states its protocol so transport security is reviewable"
  target        = "flow"
  condition     = item.protocol != ""
  error_message = "flow '${item.name}' does not declare a protocol, so its transport security cannot be reviewed"
}

# ── Gate item 3 ────────────────────────────────────────────────────────────
# "Top threat scenarios reviewed; high risks have mitigations or documented
# exceptions"
#
# ENISA also asks, in the checklist, for an H/M/L priority assigned "using a
# documented method". The risk block is that method: likelihood x impact
# resolved through threatcl's severity matrix. A threat without one has not
# been prioritised.

invariant "threats_are_prioritised" {
  description   = "ENISA gate 3: every threat carries a risk rating, so priority comes from a documented method rather than opinion"
  target        = "threat"
  condition     = try(item.risk.likelihood, "") != "" && try(item.risk.impact, "") != ""
  error_message = "threat '${item.name}' has no risk block, so it has no documented H/M/L priority"
}

# "high risks have mitigations or documented exceptions" — the hard rule. A
# high or critical threat with no implemented control fails the build. The
# exception path is an `exemption` block on this invariant, which forces the
# justification to be written down and reviewed rather than silently skipped.

invariant "high_risks_are_mitigated" {
  description   = "ENISA gate 3: high and critical threats have at least one implemented control"
  target        = "threat"
  when          = contains(["high", "critical"], try(item.risk.severity, ""))
  condition     = anytrue([for c in item.controls : c.implemented])
  error_message = "threat '${item.name}' is ${try(item.risk.severity, "unrated")} but has no implemented control — mitigate it, or record a documented exception"
}

# ENISA asks for "the top 5 to 10 threat scenarios". Fewer suggests the
# exercise was skipped; many more suggests an unprioritised dump. A warning,
# not an error, because the right number is a judgement call.

invariant "threat_count_in_enisa_range" {
  description   = "ENISA minimum evidence: a top-threats list of roughly 5 to 10 scenarios"
  severity      = "warning"
  target        = "threatmodel"
  condition     = length(item.threats) >= 5 && length(item.threats) <= 10
  error_message = "threat model '${item.name}' lists ${length(item.threats)} threats; ENISA asks for a prioritised top 5 to 10"
}

# ── Gate item 4 ────────────────────────────────────────────────────────────
# "Secure defaults confirmed for new/exposed interfaces (deny by default,
# least privilege)"
#
# ENISA's minimum evidence asks for a control mapping that says *what* the
# control is, *where* it is enforced, and *how* it is verified. "Who owns it"
# comes from the top-threats evidence item. Both live as control attributes,
# so both are checkable.

invariant "controls_have_owners" {
  description   = "ENISA minimum evidence: every control names an accountable owner"
  target        = "threat"
  condition     = alltrue([for c in item.controls : lookup(c.attributes, "owner", "") != ""])
  error_message = "threat '${item.name}' has a control with no owner attribute — ENISA requires an owner per top threat"
}

invariant "controls_map_to_verification" {
  description   = "ENISA gate 4: each control maps to a verification method (test, CI check, config validation)"
  target        = "threat"
  condition     = alltrue([for c in item.controls : lookup(c.attributes, "verification", "") != ""])
  error_message = "threat '${item.name}' has a control with no verification attribute — every control must map to how it is verified"
}

# ── Gate item 5 ────────────────────────────────────────────────────────────
# "Verification in place: at least one negative test per critical boundary /
# privileged path (unauthorised access is denied)"
#
# This is the item most often waved through, so it is enforced rather than
# suggested: a high or critical threat must name the negative test that proves
# the control denies, not merely that the happy path allows.

invariant "critical_paths_have_negative_tests" {
  description   = "ENISA gate 5: high and critical threats name a negative test proving unauthorised access is denied"
  target        = "threat"
  when          = contains(["high", "critical"], try(item.risk.severity, ""))
  condition     = anytrue([for c in item.controls : lookup(c.attributes, "negative_test", "") != ""])
  error_message = "threat '${item.name}' is ${try(item.risk.severity, "unrated")} but names no negative_test — ENISA requires at least one negative test per critical boundary"
}

# ── Gate item 6 ────────────────────────────────────────────────────────────
# "Threat model refresh triggered if any of the following are relevant: new
# API/interface, auth model change, new sensitive data, major dependency /
# supplier change, OTA/update changes, major architecture change."
#
# This one is not a property of the model — it is a property of the diff, so
# it is not expressible as an invariant. It is enforced by the workflow in
# .github/workflows/threat-model.yml, which runs on any pull request touching
# the model, and by /threat-drift for the reverse direction: code changed,
# model did not. See README section "Gate item 6".
