package store

import (
	"database/sql"
	"errors"
)

// Delivery providers a domain can be set to. ProviderDirect is doevoe's own
// pipeline (DKIM-sign, deliver to the recipient's MX); ProviderEmailEU hands
// each queued email to email.eu's sending API instead (delivery/relay.go).
// The queue, retries, idempotency and logs are the same either way — only the
// last hop differs.
const (
	ProviderDirect  = "direct"
	ProviderEmailEU = "emaileu"
)

type Domain struct {
	ID                                       int64
	Name, DKIMSelector, DKIMPrivateKey       string
	SPFVerified, DKIMVerified, DMARCVerified bool
	LastCheckedAt, CreatedAt                 string
	// Provider is one of the Provider* constants. ProviderAPIKey is the
	// provider's sending key, stored in the clear like DKIMPrivateKey (the
	// worker needs the plaintext on every attempt); it is kept when the
	// domain is switched back to direct so switching again doesn't need it
	// re-entered. Never render it — templates use ProviderKeyHint.
	Provider, ProviderAPIKey string
}

// Verified reports whether doevoe's own SPF/DKIM/DMARC records are in place.
// It is the gate for direct delivery only; see CanSend for the send gate.
func (d *Domain) Verified() bool { return d.SPFVerified && d.DKIMVerified && d.DMARCVerified }

// Relayed reports whether the domain's mail goes out through an external
// provider's API rather than directly to the recipient's MX.
func (d *Domain) Relayed() bool { return d.Provider == ProviderEmailEU }

// CanSend is the fail-closed send gate. A direct domain needs doevoe's DNS
// records verified. A relayed domain does not: its SPF/DKIM point at the
// provider, so doevoe's own check can never pass for it, and the provider
// verifies the domain itself (and refuses the send if it isn't). All doevoe
// can require up front is that a key is configured.
func (d *Domain) CanSend() bool {
	if d.Relayed() {
		return d.ProviderAPIKey != ""
	}
	return d.Verified()
}

// ProviderKeyHint is a display-safe stand-in for ProviderAPIKey: just enough
// of the tail to tell two keys apart.
func (d *Domain) ProviderKeyHint() string {
	k := d.ProviderAPIKey
	if k == "" {
		return ""
	}
	if len(k) < 12 {
		return "…"
	}
	return "…" + k[len(k)-4:]
}

const domainCols = `id, name, dkim_selector, dkim_private_key, spf_verified, dkim_verified, dmarc_verified, last_checked_at, created_at, provider, provider_api_key`

func scanDomain(row interface{ Scan(...any) error }) (*Domain, error) {
	d := &Domain{}
	err := row.Scan(&d.ID, &d.Name, &d.DKIMSelector, &d.DKIMPrivateKey,
		&d.SPFVerified, &d.DKIMVerified, &d.DMARCVerified, &d.LastCheckedAt, &d.CreatedAt, &d.Provider, &d.ProviderAPIKey)
	return d, err
}

func (s *Store) CreateDomain(name, selector, privKeyPEM string) (*Domain, error) {
	res, err := s.db.Exec(`INSERT INTO domains (name, dkim_selector, dkim_private_key, created_at) VALUES (?,?,?,?)`,
		name, selector, privKeyPEM, Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetDomain(id)
}

func (s *Store) GetDomain(id int64) (*Domain, error) {
	return scanDomain(s.db.QueryRow(`SELECT `+domainCols+` FROM domains WHERE id=?`, id))
}

func (s *Store) GetDomainByName(name string) (*Domain, error) {
	d, err := scanDomain(s.db.QueryRow(`SELECT `+domainCols+` FROM domains WHERE name=?`, name))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return d, nil
}

func (s *Store) ListDomains() ([]*Domain, error) {
	rows, err := s.db.Query(`SELECT ` + domainCols + ` FROM domains ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) SetDomainVerification(id int64, spf, dkim, dmarc bool, checkedAt string) error {
	_, err := s.db.Exec(`UPDATE domains SET spf_verified=?, dkim_verified=?, dmarc_verified=?, last_checked_at=? WHERE id=?`,
		spf, dkim, dmarc, checkedAt, id)
	return err
}

func (s *Store) SetDomainProvider(id int64, provider, apiKey string) error {
	_, err := s.db.Exec(`UPDATE domains SET provider=?, provider_api_key=? WHERE id=?`, provider, apiKey, id)
	return err
}
