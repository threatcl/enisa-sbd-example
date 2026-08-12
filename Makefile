.PHONY: help validate gate dfd dfd-check build test evidence check clean

MODEL  := threatmodel/sensorhub.tm.hcl
POLICY := policy/enisa-release-gate.hcl

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# ── the model ──────────────────────────────────────────────────────────────

validate: ## Check the model parses against the threatcl spec
	threatcl validate $(MODEL)

gate: ## Run the ENISA Playbook 01 release gate
	threatcl validate -invariants=$(POLICY) $(MODEL)

dfd: ## Regenerate the committed diagram (run this after changing the model)
	threatcl dfd -out dist/sensorhub-dfd.png -overwrite -protocol-style=both $(MODEL)
	threatcl dfd -format=dot -stdout -protocol-style=both $(MODEL) > dist/sensorhub-dfd.dot

dfd-check: ## Fail if the committed diagram is no longer what the model produces
	@threatcl dfd -format=dot -stdout -protocol-style=both $(MODEL) > /tmp/sensorhub-dfd.dot
	@diff -u dist/sensorhub-dfd.dot /tmp/sensorhub-dfd.dot \
		&& echo "diagram is current" \
		|| { echo "dist/ is stale — run 'make dfd'"; exit 1; }

# ── the product ────────────────────────────────────────────────────────────

build: ## Compile the three services
	go build ./...

test: ## Vet and run the whole test suite
	go vet ./...
	go test -race -count=1 ./...

evidence: ## Run the negative tests the model names, and keep the output
	@./scripts/negative-tests.sh $(MODEL)

# ── everything ─────────────────────────────────────────────────────────────

check: validate gate dfd-check build test evidence ## Everything CI runs, minus the diagram render

clean: ## Remove generated scratch files
	rm -f /tmp/sensorhub-dfd.dot
	rm -rf evidence
