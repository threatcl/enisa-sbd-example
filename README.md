# ENISA Secure by Design - a worked example

ENISA's newly published, [Secure by Design and Default Playbook][enisa], opens with trust
boundaries and threat modelling. Not least privilege, not authentication. Threat modelling is playbook number **01**. It ends with a release gate written as a
six-item checklist, and a "minimum evidence" list of what you should be able to
produce on demand.

If you tease out the evidence they're looking for, it stops looking like documentation:

> - One architecture/data-flow diagram with trust boundaries and entry points (stored in repo/wiki)
> - Top threats list (e.g. the top 5 to 10 threat scenarios) with H/M/L priority and owners
> - Control/default mapping for each top threat (what control, where enforced, how verified)
> - Verification evidence: CI outputs or test results for key negative tests (unauthorised calls fail)

What this sounds like is a schema. This repository implements it.

**SensorHub** is a fictional SME fleet-telemetry product. Devices report over
MQTT/TLS to a cloud ingest API, operators watch fleets on a dashboard, admins
push firmware over the air. It is shaped to hit the exact trust boundaries
ENISA names: device–cloud, internet–back end, tenant–tenant, user–admin.

The entire threat model is [one HCL file](threatmodel/sensorhub.tm.hcl). The
diagram below is generated from it. The release gate is
[executable policy](policy/enisa-release-gate.hcl) that fails the build.

The product is here too — three small Go services, one per process on the
diagram. It exists because ENISA's evidence items are about a product: a model
whose boundaries nothing actually crosses is asserting, not documenting. The
code was written to the model rather than the other way round, so the
boundaries in the picture are boundaries in the binary. See
[The product](#the-product).

![SensorHub data flow diagram](dist/sensorhub-dfd.png)

---

## The release gate, item by item

Playbook 01's release gate, quoted verbatim, against what produces it here.

| ENISA Playbook 01 release gate | Artifact here | Produced by |
| --- | --- | --- |
| Diagram updated for this release (components, flows, dependencies reflect reality) | [`dist/sensorhub-dfd.png`](dist/sensorhub-dfd.png) | Generated from the model. CI regenerates it and **fails if the committed copy is stale**, so the picture cannot drift from the model it claims to describe. |
| Trust boundaries and privileged paths clearly marked | `trust_zone` blocks in the DFD; every flow carries an explicit `protocol` | Model source. Three invariants fail the build if any element sits outside a zone, one more if a flow's protocol is unstated. |
| Top threat scenarios reviewed; high risks have mitigations or documented exceptions | Six `threat` blocks, each with a `risk` block and a control | `high_risks_are_mitigated`. A high or critical threat with no implemented control exits non-zero. |
| Secure defaults confirmed for new/exposed interfaces (deny by default, least privilege) | `control` blocks, each with an `owner` and `verification` attribute | `controls_have_owners` and `controls_map_to_verification`. |
| Verification in place: at least one negative test per critical boundary / privileged path | `negative_test` attribute on each control, and the tests it names in [`tests/`](tests/) | `critical_paths_have_negative_tests` checks the attribute is there. [`scripts/negative-tests.sh`](scripts/negative-tests.sh) then reads the attribute and **runs the test it names**, so the string has to resolve to code that passes. |
| Threat model refresh triggered if any of the following are relevant: new API/interface, auth model change, new sensitive data, major dependency/supplier change, OTA/update changes, major architecture change | The model lives in the repo, so every trigger is visible in a diff | [`threat-model.yml`](.github/workflows/threat-model.yml) re-runs the gate on any PR touching the model, and [`threat-drift.yml`](.github/workflows/threat-drift.yml) reviews the reverse direction — code changed, model did not. See [Gate item 6](#gate-item-6-refresh-triggers). |

Eleven invariants, one per checkbox plus the sub-checks each one implies.

## Run it

Requires [threatcl][cli], graphviz, Go and jq.

```
make validate   # does the model still parse against the spec?
make gate       # does it pass ENISA Playbook 01's release gate?
make dfd        # regenerate the diagram after changing the model
make build      # compile the three services
make test       # run the whole test suite
make evidence   # run the negative tests the model names, and keep the output
make check      # everything CI runs
```

A passing gate is quiet:

```
$ make gate
Validated 1 threatmodels in 1 files
Checked 11 invariants against 1 threatmodels: 0 errors, 0 warnings, 0 exemptions
```

## Watch it fail

A checklist you tick by hand is a checklist you tick by hand. The point of
writing the gate as policy is that it is *hostile*. It fails on the omissions
that a human reviewer waves through at 5pm on a Friday.

Delete the `negative_test` attribute from the RBAC control, which is exactly
the kind of thing that disappears in a rushed refactor, and:

```
$ threatcl validate -invariants=policy/enisa-release-gate.hcl threatmodel/sensorhub.tm.hcl
Validated 1 threatmodels in 1 files
Invariant violation [error] 'critical_paths_have_negative_tests': threat
'operator_escalates_to_admin' in threatmodel 'SensorHub'
(threatmodel/sensorhub.tm.hcl): threat 'operator_escalates_to_admin' is high
but names no negative_test — ENISA requires at least one negative test per
critical boundary

Checked 11 invariants against 1 threatmodels: 1 errors, 0 warnings, 0 exemptions
$ echo $?
1
```

Non-zero exit, so the pull request goes red. The same happens if you drop a
risk rating, leave a service outside a trust zone, forget a control owner, or
mark a mitigation on a high-severity threat as unimplemented.

Genuine exceptions are not forbidden. ENISA allows "documented exceptions", 
but they have to be written into the policy file as an `exemption` block with a
justification, where a reviewer can see them. The waiver becomes a diff.

## The product

Three processes on the diagram, three binaries. There is no fourth, so what
runs and what is drawn are the same list.

| On the diagram | In the tree | Entry points |
| --- | --- | --- |
| Ingest API | [`cmd/ingest`](cmd/ingest) | MQTT over mutual TLS. The only thing the `field_site` zone can reach, and it has no plaintext mode |
| Dashboard API | [`cmd/dashboard`](cmd/dashboard) | `GET /api/fleet`, `GET /api/devices/{id}/telemetry` — operator and admin |
| Rollout Service | [`cmd/rollout`](cmd/rollout) | `POST /api/rollouts`, `GET /api/rollouts` — admin only |

`go.mod` has no requirements. Everything is standard library, including the
slice of MQTT the devices speak, so the supply-chain story in this repo is not
undercut by the code it ships.

Three of the model's six controls are enforced here; the other three are
device-side and live in firmware. Each is written so the failure it prevents is
a compile error or a startup failure rather than a review comment somebody has
to remember to make:

- **Mutual TLS with per-device certificates.** `ingest.TLSConfig` is a pure
  function of the key material, returning `RequireAndVerifyClientCert`. The
  tests call that function rather than assembling a config of their own, so
  what they exercise is the production policy. Device identity comes from the
  certificate's common name; a packet cannot claim a different one, and the
  topic a device publishes to has to match the certificate it presented.

- **Server-side RBAC, deny by default.** `authz.Router.Handle` takes the role
  grant as a required argument, so a route without one does not compile, and a
  route with an empty one panics at startup. Unauthenticated routes go through
  a separate `HandlePublic` and have to appear on an allowlist in the test
  file. `TestEveryRegisteredRouteCarriesARoleGrant` walks what the services
  actually registered, not a list maintained by hand.

- **Tenant scoping in the data layer.** `store.Scope` is an interface with an
  unexported method, so it cannot be constructed outside the store package —
  the only source is `store.ScopeFor(identity)`, which takes the organisation
  from the credential. Every read demands one and there is no unscoped variant
  to reach for at 5pm on a Friday. "Read all telemetry" is not a query this
  codebase can express.

### The model chooses which tests run

The gate invariant checks that a high threat *names* a negative test. That is
satisfied by a string. [`scripts/negative-tests.sh`](scripts/negative-tests.sh)
reads the `verification` and `negative_test` attributes back out of the model
and runs exactly what it finds:

```
$ make evidence
Negative tests named by threatmodel/sensorhub.tm.hcl:

  run     spoofed_device_telemetry         tests/ingest_authn_test.go :: TestIngestRejectsUntrustedCert
  skip    malicious_firmware_via_cdn       firmware/tests/signature_test.c (verified in another repository)
  run     operator_escalates_to_admin      tests/api_rbac_test.go :: TestOperatorTokenOnAdminRouteIs403
  run     cross_tenant_telemetry_read      tests/tenant_isolation_test.go :: TestFleetQueryAcrossOrgsReturnsEmpty
  skip    replayed_stale_commands          firmware/tests/replay_test.c (verified in another repository)
  skip    device_credential_extraction     firmware/tests/provisioning_test.c (verified in another repository)

--- PASS: TestIngestRejectsUntrustedCert (0.01s)
    --- PASS: TestIngestRejectsUntrustedCert/no_client_certificate_at_all (0.00s)
    --- PASS: TestIngestRejectsUntrustedCert/certificate_issued_by_the_fleet_CA_but_expired_yesterday (0.00s)
    --- PASS: TestIngestRejectsUntrustedCert/well-formed_certificate_signed_by_a_foreign_CA (0.00s)
    --- PASS: TestIngestRejectsUntrustedCert/valid_fleet_certificate_for_a_device_that_is_not_enrolled (0.00s)

negative-tests: 3 of 3 named negative tests passed; evidence in evidence/negative-tests.txt
```

Rename a test without amending the model, or point the model at a file nobody
wrote, and it exits non-zero. `go test -run` reports success when its pattern
matches nothing, so the script also checks each named test actually ran — an
attribute pointing at a test that no longer exists is drift, not a pass.

The tests are load-bearing, which is worth confirming rather than assuming.
Downgrade the ingest listener to `RequestClientCert`, add `RoleOperator` to the
rollout grant, or drop the organisation predicate from the fleet query, and the
matching negative test goes red — one control each, no overlap.

### Run the services

The dashboard is the quickest thing to poke at. Credentials are stored as
digests, so mint one rather than committing it:

```
mkdir -p dev && TOKEN=$(openssl rand -hex 16)
printf '{"tokens":[{"token_sha256":"%s","subject":"you@example.com","org":"northwind","role":"admin"}]}\n' \
  "$(printf %s "$TOKEN" | shasum -a 256 | cut -d' ' -f1)" > dev/tokens.json

go run ./cmd/dashboard -tokens dev/tokens.json -fleet examples/fleet.json \
  -allow-plaintext -addr 127.0.0.1:8080
```

```
$ curl -s localhost:8080/api/fleet -o /dev/null -w '%{http_code}\n'
401
$ curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/api/fleet
{"devices":[{"id":"dev-northwind-001",...},{"id":"dev-northwind-002",...}]}
```

`examples/fleet.json` also enrols `dev-contoso-001`. It is absent above, and no
handler had to remember to exclude it.

`-allow-plaintext` is opt-in by name because both flows into these services are
https in the model; without it, and without `-tls-cert`/`-tls-key`, the service
refuses to start. Ingest has no equivalent flag at all. Running it needs a
device CA and a server keypair, which the tests generate for themselves —
[`tests/helpers_test.go`](tests/helpers_test.go) is the worked example, and no
key material is committed here.

## Prioritisation - the documented method

ENISA asks for H/M/L priority "using a documented method appropriate to the
product, such as assessing impact, likelihood, plausibility, exploitability and
exposure". Prose in a wiki is not a method. Here it is a `risk` block:

```hcl
risk {
  likelihood = "medium"
  impact     = "high"
  rationale  = "Operator accounts are numerous and comparatively easy to
                obtain via phishing. Reaching rollout endpoints lets an
                attacker push firmware to customer fleets."
}
```

`likelihood` and `impact` are ordinal enums (`very_low` … `very_high`).
threatcl resolves the pair through a severity matrix, so the H/M/L band is
computed the same way for every threat rather than argued case by case. The
`rationale` is where exploitability, exposure and plausibility get recorded;
it is required reading in review, and it is versioned alongside the rating it
justifies.

For SensorHub that yields:

| Threat | Likelihood | Impact | Severity | Owner |
| --- | --- | --- | --- | --- |
| Spoofed device publishes fabricated telemetry | medium | high | **high** | platform |
| Malicious firmware via compromised CDN | low | very_high | **high** | firmware |
| Operator escalates to admin rollout functions | medium | high | **high** | app |
| Cross-tenant telemetry read | medium | high | **high** | app |
| Device credential extraction from flash | medium | medium | medium | firmware |
| Replay of stale device commands | low | medium | low | firmware |

Six threats, inside the 5-to-10 band ENISA asks for, which is itself checked
by a warning-severity invariant.

Because the ratings are structured, "show me every unmitigated high across all
our products" is a query rather than a reading exercise.

## Minimum evidence

| ENISA minimum evidence | Where it is |
| --- | --- |
| One architecture/data-flow diagram with trust boundaries and entry points, stored in repo | [`dist/sensorhub-dfd.png`](dist/sensorhub-dfd.png), generated from [`data_flow_diagram_v2`](threatmodel/sensorhub.tm.hcl) |
| Top threats list with H/M/L priority and owners | Six `threat` blocks with `risk` blocks; owners as control attributes |
| Control/default mapping for each top threat — what, where enforced, how verified | `control` blocks: `description` says what and where, `verification` says how |
| Verification evidence: CI outputs for key negative tests | [The code workflow](.github/workflows/code.yml) runs the negative tests the model names and uploads their output as `negative-test-evidence`; [the model workflow](.github/workflows/threat-model.yml) publishes the diagram |

## Gate item 6: refresh triggers

The last checkbox is the one that quietly decays. ENISA wants the model
refreshed on a new interface, an auth change, new sensitive data, a major
dependency change, an OTA change, or an architecture change.

Every one of those is visible in a diff. Two directions, two mechanisms:

- **Model changed, gate not re-run.** [`threat-model.yml`](.github/workflows/threat-model.yml)
  triggers on any pull request touching `threatmodel/` or `policy/`, so the
  gate re-runs before the change can merge.
- **Code changed, model did not.** The harder and more common direction — the
  new endpoint ships and nobody opens the `.tm.hcl`. Now that there is a
  product here to drift, [`threat-drift.yml`](.github/workflows/threat-drift.yml)
  runs [drift-action][drift] on every pull request: it reads the diff against
  the model and comments with what the model no longer covers, `file:line`
  evidence included. Configured in [`.threatcl-ci.hcl`](.threatcl-ci.hcl).
  [`/threat-drift`][plugin] is the same question asked locally, before you open
  the PR.

The two are not symmetrical, and the config file says so at length. The gate is
deterministic: eleven invariants, each a property of the model, each exiting
non-zero. The drift review is a judgement about whether a diff outgrew its
model, so it is set to `fail_mode = "never"` — it comments, it does not block.
This repo already treats judgement as a warning rather than an error, which is
why the threat-count check is `severity = "warning"`. One word in the config
changes that if you disagree.

Neither is a substitute for review. Both remove the excuse that nobody noticed.

## What is here

```
.
├─ threatmodel/
│  └─ sensorhub.tm.hcl          # the model - one file, the source of everything else
├─ policy/
│  └─ enisa-release-gate.hcl    # ENISA Playbook 01's release gate as executable policy
├─ cmd/                         # one binary per process on the diagram
│  ├─ ingest/                   #   Ingest API      - MQTT over mutual TLS
│  ├─ dashboard/                #   Dashboard API   - operator reads, tenant scoped
│  └─ rollout/                  #   Rollout Service - admin only, signed firmware
├─ internal/
│  ├─ authn/                    # who is calling: credential -> identity
│  ├─ authz/                    # what they may reach: deny-by-default router
│  ├─ store/                    # Telemetry DB + Audit Log; tenant scoping lives here
│  ├─ ingest/                   # mTLS policy and the device session
│  ├─ mqtt/                     # the slice of MQTT the fleet actually speaks
│  ├─ rollout/                  # release manifests, signatures, CDN publish
│  ├─ dashboard/                # fleet read handlers
│  └─ httpserve/                # shared transport defaults for both APIs
├─ tests/                       # named by the model's `verification` attributes
│  ├─ ingest_authn_test.go
│  ├─ api_rbac_test.go
│  └─ tenant_isolation_test.go
├─ scripts/
│  └─ negative-tests.sh         # runs the tests the model names, fails if they are missing
├─ .github/workflows/
│  ├─ threat-model.yml          # validate → gate → staleness check → publish diagram
│  ├─ code.yml                  # build → vet → test → negative tests → publish evidence
│  └─ threat-drift.yml          # the reverse check: did this diff outgrow the model?
├─ .threatcl-ci.hcl             # drift-action config, and why it comments rather than blocks
├─ dist/
│  ├─ sensorhub-dfd.png         # generated diagram (rendered above)
│  └─ sensorhub-dfd.dot         # deterministic source, used for the staleness check
├─ examples/fleet.json          # enrolled devices, for running the services locally
└─ Makefile
```

Use this as a starting point via **Use this template**, or copy the two files
that matter, the model and the policy, into a repo you already have.

Worth knowing if you adapt it:

- The workflow installs a **pinned** threatcl version and verifies its
  checksum, rather than pulling `latest`. A release gate whose meaning can
  change underneath you is not a gate. (ENISA playbook 14 is supply chain
  controls; it would be a poor look to skip it here.)
- The staleness check compares generated **DOT**, not PNG bytes, because PNG
  output shifts with the graphviz version and would produce false failures.
- The gate runs the CLI directly rather than via [`threatcl-action`][action],
  which does not currently expose the `-invariants` flag.
- The negative-test runner reads the model rather than hard-coding a list of
  tests. That is the whole trick: the invariant proves an attribute is present,
  the script proves it still points at something real. Both directions of that
  pair have to hold, or the evidence is a string.

## Links

- [ENISA Secure by Design and Default Playbook][enisa] - the source. Playbook 01 is [`01-trust-boundaries-and-threat-modelling.md`](https://github.com/enisaeu/enisa-sbd-playbook/blob/main/playbooks/01-trust-boundaries-and-threat-modelling.md)
- [threatcl][cli] - the CLI. Threat modelling as HCL, in your repo
- [threatcl spec][spec] - the schema these files are written against
- [drift-action][drift] - the drift review that runs on pull requests here
- [threatcl Claude plugin][plugin] - `/threat-drift`, `/threat-for-code`
- [Threatcl Cloud][cloud] - the org layer: models across repos, a shared control library, and threat model status workflow

Under the [CRA][cra], reporting obligations begin **11 September 2026**, with
the full essential requirements following in December 2027. Annex C of the
ENISA playbook maps each of its principles to CRA Annex I. Whatever tooling you
choose, the evidence it asks for is easier to produce continuously than to
reconstruct in an audit.

[enisa]: https://github.com/enisaeu/enisa-sbd-playbook
[cli]: https://threatcl.dev/
[spec]: https://github.com/threatcl/spec
[action]: https://github.com/threatcl/threatcl-action
[drift]: https://github.com/threatcl/drift-action
[plugin]: https://github.com/threatcl/claude-plugin
[cloud]: https://threatcl.com/?utm_source=github&utm_medium=readme&utm_campaign=enisa-sbd
[cra]: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
