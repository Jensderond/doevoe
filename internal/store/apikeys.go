package store

import (
	"database/sql"
	"errors"
)

type APIKey struct {
	ID                    int64
	Name, KeyHash         string
	DomainID              int64
	Revoked               bool
	LastUsedAt, CreatedAt string
}

func (s *Store) CreateAPIKey(name string, domainID int64, keyHash string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO api_keys (name, domain_id, key_hash, created_at) VALUES (?,?,?,?)`,
		name, domainID, keyHash, Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) GetAPIKeyByHash(hash string) (*APIKey, error) {
	k := &APIKey{}
	err := s.db.QueryRow(`SELECT id, name, key_hash, domain_id, revoked, last_used_at, created_at
		FROM api_keys WHERE key_hash=? AND revoked=0`, hash).
		Scan(&k.ID, &k.Name, &k.KeyHash, &k.DomainID, &k.Revoked, &k.LastUsedAt, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return k, err
}

func (s *Store) ListAPIKeys() ([]*APIKey, error) {
	rows, err := s.db.Query(`SELECT id, name, key_hash, domain_id, revoked, last_used_at, created_at FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIKey
	for rows.Next() {
		k := &APIKey{}
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyHash, &k.DomainID, &k.Revoked, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(id int64) error {
	_, err := s.db.Exec(`UPDATE api_keys SET revoked=1 WHERE id=?`, id)
	return err
}

func (s *Store) TouchAPIKey(id int64, at string) error {
	_, err := s.db.Exec(`UPDATE api_keys SET last_used_at=? WHERE id=?`, at, id)
	return err
}
