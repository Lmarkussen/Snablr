package output

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"

	"snablr/internal/scanner"
)

const (
	// reportEvidenceInlineMax is the longest evidence field a report's
	// temporary database keeps inside a finding payload. Longer evidence, such
	// as a whole file, is kept once in report_evidence however many findings
	// and tables carry it.
	reportEvidenceInlineMax = 4096
	reportEvidencePrefix    = "snablr-report-evidence:"
	reportEvidenceRecent    = 16
)

const reportEvidenceTableSQL = `CREATE TABLE IF NOT EXISTS report_evidence (digest TEXT PRIMARY KEY, body TEXT NOT NULL)`

type reportExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type reportQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type reportEvidenceValue struct {
	digest string
	value  string
}

// reportPayloads encodes findings for a report's temporary database and
// decodes them back unchanged.
type reportPayloads struct {
	mu      sync.Mutex
	written map[string]struct{}
	recent  []reportEvidenceValue
}

func newReportPayloads() *reportPayloads {
	return &reportPayloads{written: make(map[string]struct{})}
}

func reportEvidenceFields(f *scanner.Finding) []*string {
	return []*string{&f.MatchedText, &f.MatchedTextRedacted, &f.Snippet, &f.Context, &f.ContextRedacted}
}

// encode returns f's payload with each long evidence field replaced by a
// reference, writing the evidence text through exec the first time it is
// seen.
func (r *reportPayloads) encode(ctx context.Context, exec reportExecer, f scanner.Finding) ([]byte, error) {
	for _, field := range reportEvidenceFields(&f) {
		if len(*field) <= reportEvidenceInlineMax {
			continue
		}
		sum := sha256.Sum256([]byte(*field))
		digest := hex.EncodeToString(sum[:])
		r.mu.Lock()
		_, written := r.written[digest]
		r.mu.Unlock()
		if !written {
			if _, err := exec.ExecContext(ctx, `INSERT INTO report_evidence(digest, body) VALUES(?, ?) ON CONFLICT(digest) DO NOTHING`, digest, *field); err != nil {
				return nil, err
			}
			r.mu.Lock()
			r.written[digest] = struct{}{}
			r.mu.Unlock()
		}
		*field = reportEvidencePrefix + digest
	}
	return json.Marshal(f)
}

// decode returns the finding encoded in payload with its evidence back.
// Findings decoded one after another share identical evidence strings.
func (r *reportPayloads) decode(ctx context.Context, query reportQueryer, payload []byte) (scanner.Finding, error) {
	var f scanner.Finding
	if err := json.Unmarshal(payload, &f); err != nil {
		return scanner.Finding{}, err
	}
	for _, field := range reportEvidenceFields(&f) {
		digest, ok := strings.CutPrefix(*field, reportEvidencePrefix)
		if !ok || len(digest) != sha256.Size*2 {
			continue
		}
		value, err := r.evidence(ctx, query, digest)
		if err != nil {
			return scanner.Finding{}, err
		}
		*field = value
	}
	return f, nil
}

func (r *reportPayloads) evidence(ctx context.Context, query reportQueryer, digest string) (string, error) {
	r.mu.Lock()
	for _, cached := range r.recent {
		if cached.digest == digest {
			r.mu.Unlock()
			return cached.value, nil
		}
	}
	r.mu.Unlock()
	var value string
	if err := query.QueryRowContext(ctx, `SELECT body FROM report_evidence WHERE digest=?`, digest).Scan(&value); err != nil {
		return "", err
	}
	r.mu.Lock()
	if len(r.recent) == reportEvidenceRecent {
		copy(r.recent, r.recent[1:])
		r.recent = r.recent[:reportEvidenceRecent-1]
	}
	r.recent = append(r.recent, reportEvidenceValue{digest: digest, value: value})
	r.mu.Unlock()
	return value, nil
}
