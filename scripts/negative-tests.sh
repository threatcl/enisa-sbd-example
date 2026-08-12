#!/usr/bin/env bash
#
# ENISA Playbook 01, gate item 5: "Verification in place: at least one negative
# test per critical boundary / privileged path (unauthorised access is denied)".
#
# policy/enisa-release-gate.hcl already fails the build if a high or critical
# threat names no negative_test. That check is satisfied by a string. This
# script closes the remaining gap: it reads the `verification` and
# `negative_test` attributes out of the model and runs exactly the tests the
# model claims exist.
#
# So the model decides which tests CI runs. Rename a test without amending the
# model - or point the model at a file nobody wrote - and this exits non-zero.
#
# Controls verified outside this repository (the device-side C tests) are
# reported and skipped; their evidence comes from the firmware repository's CI.
#
# Usage: scripts/negative-tests.sh [model.tm.hcl]

set -euo pipefail

MODEL="${1:-threatmodel/sensorhub.tm.hcl}"
EVIDENCE="${EVIDENCE_OUT:-evidence/negative-tests.txt}"

for tool in threatcl jq go; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "negative-tests: $tool is not installed" >&2
		exit 127
	}
done

# One line per control: threat, the file that verifies it, the negative test.
pairs="$(threatcl export -format=json "$MODEL" | jq -r '
  .[].threat[]?
  | .name as $threat
  | .expandedControl[]?
  | {
      threat:        $threat,
      verification:  ([.attribute[]? | select(.name == "verification")  | .value] | first // ""),
      negative_test: ([.attribute[]? | select(.name == "negative_test") | .value] | first // "")
    }
  | [.threat, .verification, .negative_test]
  | @tsv')"

echo "Negative tests named by ${MODEL}:"
echo

tests=()
broken=0

while IFS=$'\t' read -r threat verification negative_test; do
	[ -n "$threat" ] || continue

	case "$verification" in
	*.go) ;;
	"")
		printf '  %-7s %-32s control names no verification\n' "BROKEN" "$threat"
		broken=1
		continue
		;;
	*)
		printf '  %-7s %-32s %s\n' "skip" "$threat" "$verification (verified in another repository)"
		continue
		;;
	esac

	if [ ! -f "$verification" ]; then
		printf '  %-7s %-32s %s does not exist\n' "BROKEN" "$threat" "$verification"
		broken=1
		continue
	fi
	if [ -z "$negative_test" ]; then
		printf '  %-7s %-32s %s names no negative_test\n' "BROKEN" "$threat" "$verification"
		broken=1
		continue
	fi

	printf '  %-7s %-32s %s :: %s\n' "run" "$threat" "$verification" "$negative_test"
	tests+=("$negative_test")
done <<<"$pairs"

echo

if [ "$broken" -ne 0 ]; then
	echo "negative-tests: the model names verification that does not exist here." >&2
	echo "Either the test was renamed or moved, or the model was never updated." >&2
	exit 1
fi

if [ "${#tests[@]}" -eq 0 ]; then
	echo "negative-tests: the model names no Go negative tests; refusing to report a vacuous pass." >&2
	exit 1
fi

mkdir -p "$(dirname "$EVIDENCE")"

# Anchored alternation, so -run matches these tests and nothing else.
pattern="^($(
	IFS='|'
	echo "${tests[*]}"
))$"

status=0
go test ./tests/ -count=1 -v -run "$pattern" 2>&1 | tee "$EVIDENCE" || status=$?

echo
# `go test -run` reports success when a pattern matches nothing, so passing is
# not enough - each named test has to have actually run.
for name in "${tests[@]}"; do
	if ! grep -qE "^--- PASS: ${name} " "$EVIDENCE"; then
		echo "negative-tests: ${name} did not run, or did not pass" >&2
		status=1
	fi
done

if [ "$status" -eq 0 ]; then
	echo "negative-tests: ${#tests[@]} of ${#tests[@]} named negative tests passed; evidence in ${EVIDENCE}"
fi
exit "$status"
