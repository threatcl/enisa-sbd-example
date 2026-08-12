package store

import (
	"errors"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
)

// Scope is proof that a query is bound to exactly one organisation.
//
// It is an interface with an unexported method, so no package outside this one
// can construct a value that satisfies it. The only source of a Scope is
// ScopeFor, which derives the organisation from an authenticated identity -
// never from a path, body or query parameter.
//
// Every read method on Store demands one. There is no "read everything"
// variant to reach for under time pressure, so a new handler cannot express an
// unscoped fleet query: the method it would need does not exist and the code
// will not compile. That is the structural half of the control named in threat
// "cross_tenant_telemetry_read" (threatmodel/sensorhub.tm.hcl) - "enforced at
// the data layer instead" of per-handler, so new handlers inherit it.
type Scope interface {
	organisation() string
}

type orgScope struct{ org string }

func (s orgScope) organisation() string { return s.org }

// ErrNoScope is returned when a query reaches the store without a tenant
// scope. The interface makes that hard to do; this is the runtime backstop for
// the one remaining way - passing an untyped nil.
var ErrNoScope = errors.New("store: query attempted without a tenant scope")

// ScopeFor derives a query scope from an authenticated caller.
func ScopeFor(id authn.Identity) (Scope, error) {
	if id.OrgID == "" {
		return nil, ErrNoScope
	}
	return orgScope{org: id.OrgID}, nil
}

func orgOf(sc Scope) (string, error) {
	if sc == nil {
		return "", ErrNoScope
	}
	org := sc.organisation()
	if org == "" {
		return "", ErrNoScope
	}
	return org, nil
}
