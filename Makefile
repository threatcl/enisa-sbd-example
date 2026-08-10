.PHONY: help validate gate dfd check clean

MODEL  := threatmodel/sensorhub.tm.hcl
POLICY := policy/enisa-release-gate.hcl

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

validate: ## Check the model parses against the threatcl spec
	threatcl validate $(MODEL)

gate: ## Run the ENISA Playbook 01 release gate
	threatcl validate -invariants=$(POLICY) $(MODEL)

dfd: ## Regenerate the committed diagram (run this after changing the model)
	threatcl dfd -out dist/sensorhub-dfd.png -overwrite -protocol-style=both $(MODEL)
	threatcl dfd -format=dot -stdout -protocol-style=both $(MODEL) > dist/sensorhub-dfd.dot

check: validate gate ## Everything CI runs, minus the diagram render
	@threatcl dfd -format=dot -stdout -protocol-style=both $(MODEL) > /tmp/sensorhub-dfd.dot
	@diff -u dist/sensorhub-dfd.dot /tmp/sensorhub-dfd.dot \
		&& echo "diagram is current" \
		|| { echo "dist/ is stale — run 'make dfd'"; exit 1; }

clean: ## Remove generated scratch files
	rm -f /tmp/sensorhub-dfd.dot
