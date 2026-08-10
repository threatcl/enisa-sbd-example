spec_version = "0.7.0"

threatmodel "SensorHub" {
  description = <<EOT
Fleet telemetry for an SME device manufacturer. Field devices report over
MQTT/TLS to a cloud ingest API; operators view fleets via a web dashboard;
admins manage firmware rollout over an OTA channel.

Modelled against ENISA Secure by Design and Default Playbook 01 —
"Trust boundaries and threat modelling". Every item on that playbook's
release gate is produced from this file. See ../README.md for the mapping.
EOT

  author = "@xntrik"

  attributes {
    new_initiative  = false
    internet_facing = true
    initiative_size = "Small"
  }

  # ── Critical assets ────────────────────────────────────────────────────
  # ENISA checklist: "List critical assets" — credentials/keys, customer PII,
  # device control functions, audit logs.

  information_asset "device_credentials" {
    description                = "Per-device X.509 client certs and private keys used for MQTT mutual TLS"
    information_classification = "Confidential"
  }

  information_asset "telemetry_data" {
    description                = "Fleet telemetry including customer site locations and device health"
    information_classification = "Restricted"
  }

  information_asset "firmware_signing_key" {
    description                = "Offline key used to sign OTA firmware images. Compromise is unrecoverable in the field."
    information_classification = "Confidential"
  }

  information_asset "audit_log" {
    description                = "Admin and firmware-rollout actions. Evidence for CRA incident reporting."
    information_classification = "Restricted"
  }

  third_party_dependency "firmware_cdn" {
    description       = "CDN distributing signed firmware images to the fleet"
    saas              = true
    infrastructure    = false
    uptime_dependency = "degraded"
  }

  # ── Top threats ────────────────────────────────────────────────────────
  # ENISA asks for 5-10 prioritised scenarios, each with an owner, a
  # documented prioritisation method, and a control mapped to a verification
  # method.
  #
  # Priority comes from the `risk` block: likelihood x impact, resolved to a
  # severity band by threatcl's built-in matrix. That is the "documented
  # method" ENISA requires — see README section "Prioritisation".
  #
  # Owner and verification live as `attribute` blocks on each control, so
  # they are queryable rather than prose. policy/enisa-release-gate.hcl
  # fails the build if either is missing.

  threat "spoofed_device_telemetry" {
    description            = "An attacker with a cloned or self-issued certificate publishes fabricated telemetry to the ingest API, corrupting fleet dashboards and any downstream billing or alerting built on them."
    stride                 = ["Spoofing", "Tampering"]
    impacts                = ["Integrity"]
    information_asset_refs = ["telemetry_data", "device_credentials"]

    risk {
      likelihood = "medium"
      impact     = "high"
      rationale  = "Ingest is internet-facing and its endpoint is discoverable from firmware strings, but forging a fleet-issued client cert requires the device CA. Corrupted telemetry feeds customer-visible dashboards."
    }

    control "Mutual TLS with per-device certificates" {
      description          = "Ingest terminates mTLS and rejects any connection without a currently-valid, fleet-issued client certificate. Deny by default: unknown CAs and expired certs are refused at the TLS layer, before application code runs."
      implemented          = true
      risk_reduction       = 60
      implementation_notes = "Negative tests assert that a no-cert connect, an expired-cert connect, and a cert signed by a foreign CA are all refused."

      attribute "owner" {
        value = "platform"
      }

      attribute "verification" {
        value = "tests/ingest_authn_test.go"
      }

      attribute "negative_test" {
        value = "TestIngestRejectsUntrustedCert"
      }
    }
  }

  threat "malicious_firmware_via_cdn" {
    description            = "A compromise of the firmware CDN, or of the pipeline that publishes to it, delivers an attacker-controlled image to the fleet. This is the highest-consequence path in the system: it converts a supplier compromise into persistent code execution on every device."
    stride                 = ["Tampering", "Elevation Of Privilege"]
    impacts                = ["Integrity", "Availability"]
    information_asset_refs = ["firmware_signing_key"]

    risk {
      likelihood = "low"
      impact     = "very_high"
      rationale  = "Requires compromising a third-party CDN or the release pipeline, so likelihood is low. Impact is fleet-wide, persistent, and not remotely recoverable once malicious firmware is flashed."
    }

    control "Signed firmware verified on-device before flash" {
      description          = "Devices verify the image signature against a key pinned in ROM before writing to the boot partition, and refuse images whose version is lower than the running one. The CDN is treated as untrusted transport, not as a trust anchor."
      implemented          = true
      risk_reduction       = 70
      implementation_notes = "Signing key is held offline; CI only ever handles detached signatures. Negative tests cover unsigned, wrongly-signed, and downgrade images."

      attribute "owner" {
        value = "firmware"
      }

      attribute "verification" {
        value = "firmware/tests/signature_test.c"
      }

      attribute "negative_test" {
        value = "test_rejects_unsigned_and_downgrade_images"
      }
    }
  }

  threat "operator_escalates_to_admin" {
    description            = "An authenticated operator reaches admin-only firmware-rollout endpoints by guessing or replaying object identifiers, because authorisation is checked in the dashboard UI rather than server-side on every route."
    stride                 = ["Elevation Of Privilege"]
    impacts                = ["Integrity"]
    information_asset_refs = ["audit_log"]

    risk {
      likelihood = "medium"
      impact     = "high"
      rationale  = "Operator accounts are numerous and comparatively easy to obtain via phishing. Reaching rollout endpoints lets an attacker push firmware to customer fleets."
    }

    control "Server-side RBAC enforced per route" {
      description          = "Authorisation middleware denies by default: a route with no explicit role grant is unreachable. Admin routes reject operator tokens regardless of what the UI offers."
      implemented          = true
      risk_reduction       = 50
      implementation_notes = "The default-deny behaviour is itself tested, so a newly added route without a grant fails CI rather than shipping open."

      attribute "owner" {
        value = "app"
      }

      attribute "verification" {
        value = "tests/api_rbac_test.go"
      }

      attribute "negative_test" {
        value = "TestOperatorTokenOnAdminRouteIs403"
      }
    }
  }

  threat "cross_tenant_telemetry_read" {
    description            = "A fleet query that omits an organisation predicate returns another customer's telemetry, exposing site locations across the tenant-tenant boundary."
    stride                 = ["Info Disclosure"]
    impacts                = ["Confidentiality"]
    information_asset_refs = ["telemetry_data"]

    risk {
      likelihood = "medium"
      impact     = "high"
      rationale  = "A single missed predicate in one handler is enough, which is why scoping is enforced at the data layer instead. Telemetry reveals customer site locations, so disclosure is reportable."
    }

    control "Tenant scoping enforced in the data layer" {
      description          = "Every fleet query is scoped by organisation id at the repository layer, not per-handler. A query built without a tenant scope fails to compile rather than returning unscoped rows."
      implemented          = true
      risk_reduction       = 60
      implementation_notes = "Enforced structurally so that new handlers inherit the control by default."

      attribute "owner" {
        value = "app"
      }

      attribute "verification" {
        value = "tests/tenant_isolation_test.go"
      }

      attribute "negative_test" {
        value = "TestFleetQueryAcrossOrgsReturnsEmpty"
      }
    }
  }

  threat "replayed_stale_commands" {
    description            = "An attacker captures a legitimate control message and re-sends it later, so a device acts on a stale but correctly-signed command. ENISA calls this out explicitly alongside injection of fabricated data."
    stride                 = ["Tampering", "Repudiation"]
    impacts                = ["Integrity"]
    information_asset_refs = ["telemetry_data"]

    risk {
      likelihood = "low"
      impact     = "medium"
      rationale  = "Requires a position on the network path, which TLS already makes expensive. A replayed command can drive a device into an unintended state but cannot install code."
    }

    control "Monotonic sequence numbers with a bounded freshness window" {
      description          = "Each command carries a monotonically increasing counter and a timestamp. Devices reject any counter at or below the last accepted value, and any command outside the freshness window."
      implemented          = true
      risk_reduction       = 50
      implementation_notes = "Counter state survives reboot, so a power cycle cannot be used to reset the replay window."

      attribute "owner" {
        value = "firmware"
      }

      attribute "verification" {
        value = "firmware/tests/replay_test.c"
      }

      attribute "negative_test" {
        value = "test_replayed_command_is_rejected"
      }
    }
  }

  threat "device_credential_extraction" {
    description            = "An attacker with physical possession of a device reads the private key out of flash and uses it to impersonate that device, or — if the key is shared across a production batch — the whole fleet."
    stride                 = ["Spoofing", "Info Disclosure"]
    impacts                = ["Confidentiality", "Integrity"]
    information_asset_refs = ["device_credentials"]

    risk {
      likelihood = "medium"
      impact     = "medium"
      rationale  = "Field devices are physically accessible on customer sites, so extraction is plausible for a motivated attacker. Impact is bounded to one device because keys are unique per unit."
    }

    control "Per-device keys generated in a secure element" {
      description          = "Private keys are generated inside the secure element during manufacture and are not exportable. No key material is shared across units, so extracting one device does not yield fleet-wide access."
      implemented          = true
      risk_reduction       = 60
      implementation_notes = "Provisioning refuses to enrol a device presenting a key it has already seen, which catches an accidental shared-key regression on the production line."

      attribute "owner" {
        value = "firmware"
      }

      attribute "verification" {
        value = "firmware/tests/provisioning_test.c"
      }

      attribute "negative_test" {
        value = "test_duplicate_device_key_is_refused"
      }
    }
  }

  # ── Data flow diagram ──────────────────────────────────────────────────
  # ENISA evidence item 1: one diagram, trust boundaries and entry points
  # marked. Trust zones are nested blocks, so the generated diagram draws
  # each boundary as a cluster rather than leaving it to the reader.
  # Every flow carries an explicit protocol.

  data_flow_diagram_v2 "sensorhub" {
    trust_zone "field_site" {
      external_element "Field Device" {}
    }

    trust_zone "internet" {
      external_element "Operator" {}
      external_element "Admin" {}
    }

    trust_zone "cloud_backend" {
      process "Ingest API" {}
      process "Dashboard API" {}
      process "Rollout Service" {}

      data_store "Telemetry DB" {
        information_asset = "telemetry_data"
      }

      data_store "Audit Log" {
        information_asset = "audit_log"
      }
    }

    trust_zone "third_party" {
      process "Firmware CDN" {}
    }

    flow "telemetry publish" {
      from     = "Field Device"
      to       = "Ingest API"
      protocol = "mqtts"
    }

    flow "fleet dashboard" {
      from     = "Operator"
      to       = "Dashboard API"
      protocol = "https"
    }

    flow "firmware rollout" {
      from     = "Admin"
      to       = "Rollout Service"
      protocol = "https"
    }

    flow "telemetry write" {
      from     = "Ingest API"
      to       = "Telemetry DB"
      protocol = "sql"
    }

    flow "telemetry read" {
      from     = "Dashboard API"
      to       = "Telemetry DB"
      protocol = "sql"
    }

    flow "admin audit write" {
      from     = "Rollout Service"
      to       = "Audit Log"
      protocol = "sql"
    }

    flow "publish signed image" {
      from     = "Rollout Service"
      to       = "Firmware CDN"
      protocol = "https"
    }

    flow "ota download" {
      from     = "Field Device"
      to       = "Firmware CDN"
      protocol = "https"
    }
  }
}
