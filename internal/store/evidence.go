package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"snablr/internal/scanner"
)

// evidenceInlineMax is the longest evidence field kept inside a finding's
// stored payload. A longer field, such as a whole file kept as
// evidence, is stored once in the evidence table however many findings and
// correlation candidates carry it.
const evidenceInlineMax = 4096

// evidencePlaceholderPrefix marks a field whose text is in the evidence
// table. The placeholder keeps the field at its place in the stored payload,
// so putting the evidence back yields the original payload byte for byte.
const evidencePlaceholderPrefix = "snablr-evidence:"

// knownEvidenceRecent bounds the digests a store remembers having queued, so
// a run of findings with the same large evidence sends its text only once.
const knownEvidenceRecent = 64

// expandedPayloadSQL rebuilds an original payload from a stored row r: each
// field listed in evidence_refs gets its evidence text back in place of the
// placeholder.
// Payloads are stored as blobs holding JSON text, and the view returns them
// as blobs too.
const expandedPayloadSQL = `CASE WHEN r.evidence_refs IS NULL THEN r.payload ELSE (SELECT CAST(json_patch(CAST(r.payload AS TEXT), json_group_object(ref.key, json(e.body))) AS BLOB) FROM json_each(r.evidence_refs) ref JOIN evidence e ON e.digest = ref.value) END`

// evidenceSchemaSQL creates the evidence table and the views that present
// stored rows with their evidence put back. Writes through the findings view
// store payloads as given.
const evidenceSchemaSQL = `
CREATE TABLE IF NOT EXISTS evidence (digest TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE VIEW IF NOT EXISTS findings AS SELECT r.id AS id, r.scan_id AS scan_id, r.fingerprint AS fingerprint, r.host AS host, r.share AS share, r.path AS path, r.rule_id AS rule_id, r.category AS category, ` + expandedPayloadSQL + ` AS payload FROM finding_rows r;
CREATE TRIGGER IF NOT EXISTS findings_insert INSTEAD OF INSERT ON findings BEGIN INSERT INTO finding_rows(id,scan_id,fingerprint,host,share,path,rule_id,category,payload) VALUES(NEW.id,NEW.scan_id,NEW.fingerprint,NEW.host,NEW.share,NEW.path,NEW.rule_id,NEW.category,NEW.payload); END;
CREATE TRIGGER IF NOT EXISTS findings_update INSTEAD OF UPDATE ON findings BEGIN UPDATE finding_rows SET scan_id=NEW.scan_id, fingerprint=NEW.fingerprint, host=NEW.host, share=NEW.share, path=NEW.path, rule_id=NEW.rule_id, category=NEW.category, payload=NEW.payload, evidence_refs=NULL WHERE id=OLD.id; END;
CREATE TRIGGER IF NOT EXISTS findings_delete INSTEAD OF DELETE ON findings BEGIN DELETE FROM finding_rows WHERE id=OLD.id; END;
CREATE VIEW IF NOT EXISTS correlation_state AS SELECT r.id AS id, r.scan_id AS scan_id, r.family AS family, r.group_key AS group_key, r.slot AS slot, r.priority AS priority, r.severity_rank AS severity_rank, r.file_path AS file_path, ` + expandedPayloadSQL + ` AS payload FROM correlation_state_rows r;
`

// storedFinding is a finding payload as written: large evidence fields are
// placeholders and their text is in bodies, keyed by digest.
type storedFinding struct {
	payload []byte
	refs    any
	bodies  map[string][]byte
}

func (s storedFinding) size() int64 {
	size := int64(len(s.payload))
	for _, body := range s.bodies {
		size += int64(len(body))
	}
	return size
}

// compactFinding prepares f for storage. Its stored payload decodes to the
// same finding once the evidence is put back.
type evidenceField struct {
	name  string
	value *string
}

// evidenceFields lists the fields of f that may be stored in the evidence
// table, by their JSON names.
func evidenceFields(f *scanner.Finding) []evidenceField {
	return []evidenceField{
		{"matched_text", &f.MatchedText},
		{"matched_text_redacted", &f.MatchedTextRedacted},
		{"snippet", &f.Snippet},
		{"context", &f.Context},
		{"context_redacted", &f.ContextRedacted},
	}
}

func compactFinding(f scanner.Finding) (storedFinding, error) {
	fields := evidenceFields(&f)
	stored := storedFinding{}
	refs := map[string]string{}
	encoded := map[string]string{}
	for _, field := range fields {
		if len(*field.value) <= evidenceInlineMax {
			continue
		}
		digest, ok := encoded[*field.value]
		if !ok {
			body, err := json.Marshal(*field.value)
			if err != nil {
				return storedFinding{}, err
			}
			sum := sha256.Sum256(body)
			digest = hex.EncodeToString(sum[:])
			encoded[*field.value] = digest
			if stored.bodies == nil {
				stored.bodies = map[string][]byte{}
			}
			stored.bodies[digest] = body
		}
		refs[field.name] = digest
		*field.value = evidencePlaceholderPrefix + digest
	}
	payload, err := json.Marshal(f)
	if err != nil {
		return storedFinding{}, err
	}
	stored.payload = payload
	if len(refs) > 0 {
		encodedRefs, err := json.Marshal(refs)
		if err != nil {
			return storedFinding{}, err
		}
		stored.refs = string(encodedRefs)
	}
	return stored, nil
}

// knownEvidence remembers digests whose text a store already queued.
type knownEvidence struct {
	mu     sync.Mutex
	recent []string
}

// claim reports whether digest still needs its text written, and remembers
// it as written.
func (k *knownEvidence) claim(digest string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, known := range k.recent {
		if known == digest {
			return false
		}
	}
	if len(k.recent) == knownEvidenceRecent {
		copy(k.recent, k.recent[1:])
		k.recent = k.recent[:knownEvidenceRecent-1]
	}
	k.recent = append(k.recent, digest)
	return true
}

// withoutKnownBodies drops evidence texts this store already queued. They are
// written by an earlier write in the same ordered queue.
func (s *SQLiteStore) withoutKnownBodies(stored storedFinding) storedFinding {
	for digest := range stored.bodies {
		if !s.evidence.claim(digest) {
			delete(stored.bodies, digest)
		}
	}
	return stored
}

func writeEvidence(tx *sql.Tx, bodies map[string][]byte) error {
	for digest, body := range bodies {
		if _, err := tx.Exec(`INSERT INTO evidence(digest, body) VALUES(?, ?) ON CONFLICT(digest) DO NOTHING`, digest, string(body)); err != nil {
			return err
		}
	}
	return nil
}

type decodedEvidence struct {
	digest string
	value  string
}

// evidenceDecoder puts stored evidence back into findings read from their
// compact rows. Each evidence text is decoded once while it is recent, and
// findings that carry it share the decoded string.
type evidenceDecoder struct {
	recent []decodedEvidence
}

// restore replaces the placeholders listed in refs with their evidence text.
// It returns the bytes of evidence text it had to read.
func (d *evidenceDecoder) restore(ctx context.Context, db *sql.DB, f *scanner.Finding, refs string) (int, error) {
	var byField map[string]string
	if err := json.Unmarshal([]byte(refs), &byField); err != nil {
		return 0, err
	}
	read := 0
	for _, field := range evidenceFields(f) {
		digest, ok := byField[field.name]
		if !ok {
			continue
		}
		value, size, err := d.text(ctx, db, digest)
		if err != nil {
			return read, fmt.Errorf("read evidence %s: %w", digest, err)
		}
		*field.value = value
		read += size
	}
	return read, nil
}

func (d *evidenceDecoder) text(ctx context.Context, db *sql.DB, digest string) (string, int, error) {
	for _, cached := range d.recent {
		if cached.digest == digest {
			return cached.value, 0, nil
		}
	}
	var body []byte
	if err := db.QueryRowContext(ctx, `SELECT body FROM evidence WHERE digest=?`, digest).Scan(&body); err != nil {
		return "", 0, err
	}
	var value string
	if err := json.Unmarshal(body, &value); err != nil {
		return "", 0, err
	}
	if len(d.recent) == sharedEvidenceRecent {
		copy(d.recent, d.recent[1:])
		d.recent = d.recent[:sharedEvidenceRecent-1]
	}
	d.recent = append(d.recent, decodedEvidence{digest: digest, value: value})
	return value, len(body), nil
}
