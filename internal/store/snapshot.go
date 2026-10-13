package store

import (
	"database/sql"
	"fmt"
	"reflect"
)

// Snapshot is a logical, order-independent view used by parity tests and
// future migration tooling. It intentionally excludes serialized JSON and
// whole-file content.
type Snapshot struct {
	ScanStatus      string
	TargetStatus    map[string]string
	ShareStatus     map[string]string
	FileStatus      map[string]string
	MemberKeys      map[string]string
	FindingKeys     map[string]struct{}
	CredentialKeys  map[string]struct{}
	CorrelationKeys map[string]struct{}
}

func (s *ShadowStore) Snapshot() (Snapshot, error) {
	if err := s.Flush(); err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{TargetStatus: map[string]string{}, ShareStatus: map[string]string{}, FileStatus: map[string]string{}, MemberKeys: map[string]string{}, FindingKeys: map[string]struct{}{}, CredentialKeys: map[string]struct{}{}, CorrelationKeys: map[string]struct{}{}}
	if err := s.db.QueryRow(`SELECT status FROM scans WHERE scan_id=?`, s.scanID).Scan(&out.ScanStatus); err != nil {
		return Snapshot{}, err
	}
	if err := readPairs(s.db, `SELECT host,status FROM targets WHERE scan_id=?`, s.scanID, out.TargetStatus); err != nil {
		return Snapshot{}, err
	}
	rows, err := s.db.Query(`SELECT host,share,status FROM shares WHERE scan_id=?`, s.scanID)
	if err != nil {
		return Snapshot{}, err
	}
	for rows.Next() {
		var host, share, status string
		if err := rows.Scan(&host, &share, &status); err != nil {
			rows.Close()
			return Snapshot{}, err
		}
		out.ShareStatus[host+"\x00"+share] = status
	}
	if err := rows.Close(); err != nil {
		return Snapshot{}, err
	}
	if err := readPairs(s.db, `SELECT file_key,status FROM files WHERE scan_id=?`, s.scanID, out.FileStatus); err != nil {
		return Snapshot{}, err
	}
	rows, err = s.db.Query(`SELECT parent_key,member_key,status FROM members WHERE scan_id=?`, s.scanID)
	if err != nil {
		return Snapshot{}, err
	}
	for rows.Next() {
		var parent, member, status string
		if err := rows.Scan(&parent, &member, &status); err != nil {
			rows.Close()
			return Snapshot{}, err
		}
		out.MemberKeys[parent+"\x00"+member] = status
	}
	if err := rows.Close(); err != nil {
		return Snapshot{}, err
	}
	if err := readSet(s.db, `SELECT fingerprint FROM findings WHERE scan_id=?`, s.scanID, out.FindingKeys); err != nil {
		return Snapshot{}, err
	}
	if err := readSet(s.db, `SELECT credential_key FROM credentials WHERE scan_id=?`, s.scanID, out.CredentialKeys); err != nil {
		return Snapshot{}, err
	}
	if err := readSet(s.db, `SELECT correlation_key FROM correlations WHERE scan_id=?`, s.scanID, out.CorrelationKeys); err != nil {
		return Snapshot{}, err
	}
	return out, nil
}

func readPairs(db *sql.DB, query, id string, out map[string]string) error {
	rows, err := db.Query(query, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return err
		}
		out[key] = value
	}
	return rows.Err()
}
func readSet(db *sql.DB, query, id string, out map[string]struct{}) error {
	rows, err := db.Query(query, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return err
		}
		out[key] = struct{}{}
	}
	return rows.Err()
}

func (s Snapshot) Equal(other Snapshot) error {
	if s.ScanStatus != other.ScanStatus {
		return fmt.Errorf("scan status differs: %q != %q", s.ScanStatus, other.ScanStatus)
	}
	items := []struct {
		name        string
		left, right any
	}{
		{"targets", s.TargetStatus, other.TargetStatus},
		{"shares", s.ShareStatus, other.ShareStatus},
		{"files", s.FileStatus, other.FileStatus},
		{"members", s.MemberKeys, other.MemberKeys},
		{"findings", s.FindingKeys, other.FindingKeys},
		{"credentials", s.CredentialKeys, other.CredentialKeys},
		{"correlations", s.CorrelationKeys, other.CorrelationKeys},
	}
	for _, item := range items {
		if !reflect.DeepEqual(item.left, item.right) {
			return fmt.Errorf("%s differ", item.name)
		}
	}
	return nil
}
