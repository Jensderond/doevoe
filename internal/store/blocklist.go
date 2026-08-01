package store

import (
	"database/sql"
	"errors"
)

// BlocklistStatus is the current listing state of one (target, zone) pair.
// Target is the egress IP or a domain name; Since is when the current
// Listed value began; LastChecked is the last determinate check.
type BlocklistStatus struct {
	Target, Zone       string
	Listed             bool
	Since, LastChecked string
}

// BlocklistEvent is one listing transition (append-only history).
type BlocklistEvent struct {
	ID           int64
	Target, Zone string
	Listed       bool
	OccurredAt   string
}

// RecordBlocklistCheck persists a determinate check result and reports the
// transition it caused: "listed" (was clean or never seen, now listed),
// "cleared" (was listed, now clean), or "" (steady state). The status upsert
// and the transition event are one transaction so history can never disagree
// with current state. Callers must not call this for indeterminate verdicts
// (see dnsbl.Indeterminate) — only genuine answers belong in the history.
//
// Transitions — not per-check snapshots — are the stored grain: hourly
// snapshots would be thousands of redundant "still clear" rows per month,
// while transitions plus last_checked reconstruct the timeline losslessly.
func (s *Store) RecordBlocklistCheck(target, zone string, listed bool, now string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// MaxOpenConns(1): every statement in here must use tx, never s.db,
	// or the query blocks forever waiting for the connection tx holds.
	var prev bool
	known := true
	err = tx.QueryRow(`SELECT listed FROM blocklist_status WHERE target=? AND zone=?`,
		target, zone).Scan(&prev)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		known = false
	}

	transition := ""
	switch {
	case !known && listed:
		transition = "listed" // first sight already listed: operator was never told
	case known && listed && !prev:
		transition = "listed"
	case known && !listed && prev:
		transition = "cleared"
	}

	if known && transition == "" {
		if _, err := tx.Exec(`UPDATE blocklist_status SET last_checked=? WHERE target=? AND zone=?`,
			now, target, zone); err != nil {
			return "", err
		}
	} else {
		if _, err := tx.Exec(`INSERT INTO blocklist_status (target, zone, listed, since, last_checked)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(target, zone) DO UPDATE SET listed=excluded.listed,
				since=excluded.since, last_checked=excluded.last_checked`,
			target, zone, boolInt(listed), now, now); err != nil {
			return "", err
		}
	}
	if transition != "" {
		if _, err := tx.Exec(`INSERT INTO blocklist_events (target, zone, listed, occurred_at)
			VALUES (?, ?, ?, ?)`, target, zone, boolInt(listed), now); err != nil {
			return "", err
		}
	}
	return transition, tx.Commit()
}

func (s *Store) ListBlocklistStatus() ([]BlocklistStatus, error) {
	rows, err := s.db.Query(`SELECT target, zone, listed, since, last_checked
		FROM blocklist_status ORDER BY listed DESC, target, zone`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlocklistStatus
	for rows.Next() {
		var st BlocklistStatus
		var listed int
		if err := rows.Scan(&st.Target, &st.Zone, &listed, &st.Since, &st.LastChecked); err != nil {
			return nil, err
		}
		st.Listed = listed != 0
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) RecentBlocklistEvents(limit int) ([]BlocklistEvent, error) {
	rows, err := s.db.Query(`SELECT id, target, zone, listed, occurred_at
		FROM blocklist_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlocklistEvent
	for rows.Next() {
		var ev BlocklistEvent
		var listed int
		if err := rows.Scan(&ev.ID, &ev.Target, &ev.Zone, &listed, &ev.OccurredAt); err != nil {
			return nil, err
		}
		ev.Listed = listed != 0
		out = append(out, ev)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
