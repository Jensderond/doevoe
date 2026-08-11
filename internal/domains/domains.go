// Package domains holds domain lifecycle logic shared by the admin UI, the
// hourly DNS recheck loop, and the MCP server: creation (with DKIM keypair
// generation) and verification (with the indeterminate-result guard).
package domains

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

var ErrInvalidName = errors.New("invalid domain name")

// CheckFunc matches the closure main.go builds around dnscheck.Check.
type CheckFunc func(context.Context, *store.Domain) dnscheck.Result

// Create lowercases and validates name, generates a fresh DKIM keypair, and
// inserts the domain with the default "mail1" selector. A duplicate name
// surfaces as the store's UNIQUE-constraint error.
func Create(st *store.Store, name string) (*store.Domain, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || strings.ContainsAny(name, " /@") {
		return nil, ErrInvalidName
	}
	priv, _, err := dkimkeys.Generate()
	if err != nil {
		return nil, err
	}
	return st.CreateDomain(name, "mail1", priv)
}

// Verify runs check and persists the result — unless it is indeterminate.
// A transient resolver failure is not a genuine "record missing" answer:
// persisting it would flip an already-verified domain to unverified (and
// fail-close its sends with 403) on a mere DNS blip, so the write is
// skipped and persisted is false. This is the single home of that rule;
// do not re-implement it at call sites.
func Verify(ctx context.Context, st *store.Store, check CheckFunc, d *store.Domain) (dnscheck.Result, bool, error) {
	res := check(ctx, d)
	if res.Indeterminate {
		slog.Warn("dns verification indeterminate; not persisting", "domain", d.Name)
		return res, false, nil
	}
	if err := st.SetDomainVerification(d.ID, res.SPF.OK, res.DKIM.OK, res.DMARC.OK, store.Now()); err != nil {
		return res, false, err
	}
	return res, true, nil
}
