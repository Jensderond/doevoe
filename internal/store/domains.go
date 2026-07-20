package store

import (
	"database/sql"
	"errors"
)

type Domain struct {
	ID                                       int64
	Name, DKIMSelector, DKIMPrivateKey       string
	SPFVerified, DKIMVerified, DMARCVerified bool
	LastCheckedAt, CreatedAt                 string
}

func (d *Domain) Verified() bool { return d.SPFVerified && d.DKIMVerified && d.DMARCVerified }

const domainCols = `id, name, dkim_selector, dkim_private_key, spf_verified, dkim_verified, dmarc_verified, last_checked_at, created_at`

func scanDomain(row interface{ Scan(...any) error }) (*Domain, error) {
	d := &Domain{}
	err := row.Scan(&d.ID, &d.Name, &d.DKIMSelector, &d.DKIMPrivateKey,
		&d.SPFVerified, &d.DKIMVerified, &d.DMARCVerified, &d.LastCheckedAt, &d.CreatedAt)
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
