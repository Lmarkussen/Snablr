package output

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"snablr/internal/diff"
	"snablr/internal/scanner"
)

func diffFingerprintKey(f scanner.Finding) string {
	b, _ := json.Marshal(diff.Fingerprint(f))
	return string(b)
}

func diffSortKey(f scanner.Finding) string {
	fp := diff.Fingerprint(f)
	return strings.Join([]string{fp.RuleID, fp.Host, fp.Share, fp.FilePath, fp.Match}, "\x1f")
}

// BuildHTMLReportIndexWithBaseline extends the bounded current-report index with
// a disk-backed comparison. Baseline findings are written one at a time and
// are not copied into another Go collection.
type HTMLReportBaselineIterator func(context.Context, func(scanner.Finding) error) error

func BuildHTMLReportIndexWithBaseline(ctx context.Context, iterator HTMLReportFindingIterator, baseline []scanner.Finding) (*HTMLReportIndex, error) {
	index, err := BuildHTMLReportIndex(ctx, iterator)
	if err != nil {
		return nil, err
	}
	if err := index.buildDiff(ctx, func(_ context.Context, visit func(scanner.Finding) error) error {
		for _, finding := range baseline {
			if err := visit(finding); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = index.Close()
		return nil, err
	}
	return index, nil
}

func BuildHTMLReportIndexWithBaselineIterator(ctx context.Context, iterator HTMLReportFindingIterator, baseline HTMLReportBaselineIterator) (*HTMLReportIndex, error) {
	index, err := BuildHTMLReportIndex(ctx, iterator)
	if err != nil {
		return nil, err
	}
	if err := index.buildDiff(ctx, baseline); err != nil {
		_ = index.Close()
		return nil, err
	}
	return index, nil
}

func (i *HTMLReportIndex) buildDiff(ctx context.Context, baseline HTMLReportBaselineIterator) error {
	if i == nil || i.db == nil {
		return errors.New("HTML report index is closed")
	}
	if _, err := i.db.ExecContext(ctx, `
CREATE TABLE baseline_findings (fingerprint TEXT PRIMARY KEY, sort_key TEXT NOT NULL, payload BLOB NOT NULL);
CREATE TABLE html_diff (
  fingerprint TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  sort_key TEXT NOT NULL,
  current_payload BLOB,
  baseline_payload BLOB,
  changed_fields BLOB
);
CREATE INDEX html_diff_status_order_idx ON html_diff(status, sort_key);`); err != nil {
		return err
	}
	i.diffEnabled = true
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	insertBaseline, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO baseline_findings(fingerprint,sort_key,payload) VALUES(?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	err = baseline(ctx, func(finding scanner.Finding) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		payload, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		if _, err := insertBaseline.ExecContext(ctx, diffFingerprintKey(finding), diffSortKey(finding), payload); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		_ = insertBaseline.Close()
		_ = tx.Rollback()
		return err
	}
	if err := insertBaseline.Close(); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	insert, err := i.db.PrepareContext(ctx, `INSERT INTO html_diff(fingerprint,status,sort_key,current_payload,baseline_payload,changed_fields) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer insert.Close()
	lastKey := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var key string
		var currentPayload, baselinePayload []byte
		var baselineKey sql.NullString
		err := i.db.QueryRowContext(ctx, `
SELECT o.fingerprint, o.payload, b.payload, b.fingerprint
FROM observations o
LEFT JOIN baseline_findings b ON b.fingerprint=o.fingerprint
JOIN (SELECT fingerprint,MAX(seq) AS seq FROM observations GROUP BY fingerprint) latest
  ON latest.fingerprint=o.fingerprint AND latest.seq=o.seq
WHERE o.fingerprint > ? ORDER BY o.fingerprint LIMIT 1`, lastKey).Scan(&key, &currentPayload, &baselinePayload, &baselineKey)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		lastKey = key
		var current scanner.Finding
		if err := json.Unmarshal(currentPayload, &current); err != nil {
			return err
		}
		status := diff.StatusNew
		var fields []string
		if baselineKey.Valid {
			var previous scanner.Finding
			if err := json.Unmarshal(baselinePayload, &previous); err != nil {
				return err
			}
			result := diff.Compare([]scanner.Finding{previous}, []scanner.Finding{current})
			if len(result.Changed) > 0 {
				status = diff.StatusChanged
				fields = result.Changed[0].ChangedFields
			} else {
				status = diff.StatusUnchanged
			}
		}
		encodedFields, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		if _, err := insert.ExecContext(ctx, key, string(status), diffSortKey(current), currentPayload, nullableBytes(baselinePayload, baselineKey.Valid), encodedFields); err != nil {
			return err
		}
	}
	// Removed entries are streamed from baseline storage and retain the
	// baseline payload as their authoritative evidence.
	lastRemovedSort := ""
	lastRemovedKey := ""
	for {
		var key, sortKey string
		var payload []byte
		err := i.db.QueryRowContext(ctx, `SELECT b.fingerprint,b.sort_key,b.payload FROM baseline_findings b LEFT JOIN html_diff d ON d.fingerprint=b.fingerprint WHERE d.fingerprint IS NULL AND (b.sort_key > ? OR (b.sort_key = ? AND b.fingerprint > ?)) ORDER BY b.sort_key,b.fingerprint LIMIT 1`, lastRemovedSort, lastRemovedSort, lastRemovedKey).Scan(&key, &sortKey, &payload)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		lastRemovedSort = sortKey
		lastRemovedKey = key
		if _, err := insert.ExecContext(ctx, key, string(diff.StatusRemoved), sortKey, nil, payload, []byte("[]")); err != nil {
			return err
		}
	}
	return nil
}

func nullableBytes(value []byte, valid bool) any {
	if !valid {
		return nil
	}
	return value
}

func (i *HTMLReportIndex) DiffSummary(ctx context.Context) (*diff.Summary, error) {
	var summary diff.Summary
	rows, err := i.db.QueryContext(ctx, `SELECT status,COUNT(*) FROM html_diff GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		switch diff.Status(status) {
		case diff.StatusNew:
			summary.New = count
		case diff.StatusRemoved:
			summary.Removed = count
		case diff.StatusChanged:
			summary.Changed = count
		case diff.StatusUnchanged:
			summary.Unchanged = count
		}
	}
	return &summary, rows.Err()
}

func (i *HTMLReportIndex) DiffStatus(ctx context.Context, finding scanner.Finding) (string, []string, error) {
	if !i.diffEnabled {
		return "", nil, nil
	}
	var status string
	var encoded []byte
	err := i.db.QueryRowContext(ctx, `SELECT status,changed_fields FROM html_diff WHERE fingerprint=?`, diffFingerprintKey(finding)).Scan(&status, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	var fields []string
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return "", nil, fmt.Errorf("decode HTML diff fields: %w", err)
	}
	return status, fields, nil
}

func (i *HTMLReportIndex) streamChanged(ctx context.Context) (<-chan diff.ChangedFinding, <-chan error) {
	out := make(chan diff.ChangedFinding)
	errs := make(chan error, 1)
	go func() {
		defer close(out)
		rows, err := i.db.QueryContext(ctx, `SELECT baseline_payload,current_payload,fingerprint,changed_fields FROM html_diff WHERE status=? ORDER BY sort_key`, string(diff.StatusChanged))
		if err != nil {
			errs <- err
			close(errs)
			return
		}
		defer rows.Close()
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				errs <- err
				close(errs)
				return
			}
			var previousPayload, currentPayload []byte
			var key string
			var encoded []byte
			if err := rows.Scan(&previousPayload, &currentPayload, &key, &encoded); err != nil {
				errs <- err
				close(errs)
				return
			}
			var previous, current scanner.Finding
			if err := json.Unmarshal(previousPayload, &previous); err != nil {
				errs <- err
				close(errs)
				return
			}
			if err := json.Unmarshal(currentPayload, &current); err != nil {
				errs <- err
				close(errs)
				return
			}
			var fields []string
			if err := json.Unmarshal(encoded, &fields); err != nil {
				errs <- err
				close(errs)
				return
			}
			var fp diff.FindingFingerprint
			if err := json.Unmarshal([]byte(key), &fp); err != nil {
				errs <- err
				close(errs)
				return
			}
			select {
			case out <- diff.ChangedFinding{Previous: previous, Current: current, Fingerprint: fp, ChangedFields: fields}:
			case <-ctx.Done():
				errs <- ctx.Err()
				close(errs)
				return
			}
		}
		errs <- rows.Err()
		close(errs)
	}()
	return out, errs
}

func (i *HTMLReportIndex) streamRemoved(ctx context.Context) (<-chan scanner.Finding, <-chan error) {
	out := make(chan scanner.Finding)
	errs := make(chan error, 1)
	go func() {
		defer close(out)
		rows, err := i.db.QueryContext(ctx, `SELECT baseline_payload FROM html_diff WHERE status=? ORDER BY sort_key`, string(diff.StatusRemoved))
		if err != nil {
			errs <- err
			close(errs)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				errs <- err
				close(errs)
				return
			}
			var finding scanner.Finding
			if err := json.Unmarshal(payload, &finding); err != nil {
				errs <- err
				close(errs)
				return
			}
			select {
			case out <- finding:
			case <-ctx.Done():
				errs <- ctx.Err()
				close(errs)
				return
			}
		}
		errs <- rows.Err()
		close(errs)
	}()
	return out, errs
}
