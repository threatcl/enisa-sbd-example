// Package tests holds SensorHub's verification evidence.
//
// The files here are not arranged for convenience. Each one is named by a
// control in threatmodel/sensorhub.tm.hcl, in that control's `verification`
// attribute, and each contains the negative test that control's
// `negative_test` attribute names:
//
//	ingest_authn_test.go     TestIngestRejectsUntrustedCert
//	api_rbac_test.go         TestOperatorTokenOnAdminRouteIs403
//	tenant_isolation_test.go TestFleetQueryAcrossOrgsReturnsEmpty
//
// scripts/negative-tests.sh reads those attributes out of the model and runs
// exactly the tests it finds, so renaming a test here without amending the
// model - or the reverse - fails CI rather than quietly leaving the model
// pointing at nothing. That is ENISA Playbook 01's gate item 5, wired up.
//
// The model's other three controls are device-side and verified in the
// firmware repository; their `verification` attributes name C tests, which the
// script skips.
package tests
