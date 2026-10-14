package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"snablr/internal/scanner"
)

type Bookmark struct {
	FileKey   string
	Host      string
	Share     string
	Path      string
	CreatedAt time.Time
}

type BookmarkCredential struct {
	Type     string
	Identity string
	Value    string
	Source   string
}

type BookmarkDetails struct {
	Bookmark    Bookmark
	Findings    []scanner.Finding
	Credentials []BookmarkCredential
}

func (s *SQLiteStore) IsBookmarked(ctx context.Context, key string) (bool, error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("sqlite bookmark store is closed")
	}
	if err := s.Flush(); err != nil {
		return false, err
	}
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM bookmarks WHERE scan_id=? AND file_key=?`, s.scanID, key).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil && exists == 1, err
}

func (s *SQLiteStore) RemoveBookmark(ctx context.Context, key string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite bookmark store is closed")
	}
	if err := s.Flush(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM bookmarks WHERE scan_id=? AND file_key=?`, s.scanID, key)
	return err
}

func (s *SQLiteStore) ToggleBookmark(ctx context.Context, host, share, path string) (Bookmark, bool, error) {
	if s == nil || s.db == nil {
		return Bookmark{}, false, fmt.Errorf("sqlite bookmark store is closed")
	}
	if err := s.Flush(); err != nil {
		return Bookmark{}, false, err
	}
	lookupPath := path
	if index := strings.Index(lookupPath, "!"); index > 0 {
		lookupPath = lookupPath[:index]
	}
	var key string
	if err := s.db.QueryRowContext(ctx, `SELECT file_key FROM files WHERE scan_id=? AND host=? AND share=? AND (path=? OR path=?) LIMIT 1`, s.scanID, host, share, path, lookupPath).Scan(&key); err != nil {
		if err == sql.ErrNoRows {
			return Bookmark{}, false, fmt.Errorf("file is not persisted yet")
		}
		return Bookmark{}, false, err
	}
	return s.ToggleBookmarkKey(ctx, key)
}

func (s *SQLiteStore) ToggleBookmarkKey(ctx context.Context, key string) (Bookmark, bool, error) {
	if s == nil || s.db == nil {
		return Bookmark{}, false, fmt.Errorf("sqlite bookmark store is closed")
	}
	if strings.TrimSpace(key) == "" {
		return Bookmark{}, false, fmt.Errorf("bookmark file identity is empty")
	}
	if err := s.Flush(); err != nil {
		return Bookmark{}, false, err
	}
	var bookmark Bookmark
	var created string
	row := s.db.QueryRowContext(ctx, `SELECT f.file_key,f.host,f.share,f.path,b.created_at FROM bookmarks b JOIN files f ON f.scan_id=b.scan_id AND f.file_key=b.file_key WHERE b.scan_id=? AND b.file_key=?`, s.scanID, key)
	if err := row.Scan(&bookmark.FileKey, &bookmark.Host, &bookmark.Share, &bookmark.Path, &created); err == nil {
		_, err = s.db.ExecContext(ctx, `DELETE FROM bookmarks WHERE scan_id=? AND file_key=?`, s.scanID, key)
		return bookmark, false, err
	} else if err != sql.ErrNoRows {
		return Bookmark{}, false, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT file_key,host,share,path FROM files WHERE scan_id=? AND file_key=?`, s.scanID, key).Scan(&bookmark.FileKey, &bookmark.Host, &bookmark.Share, &bookmark.Path); err != nil {
		return Bookmark{}, false, err
	}
	bookmark.CreatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO bookmarks(scan_id,file_key,created_at) VALUES(?,?,?) ON CONFLICT(scan_id,file_key) DO NOTHING`, s.scanID, key, bookmark.CreatedAt.Format(time.RFC3339Nano))
	return bookmark, err == nil, err
}

func (s *SQLiteStore) ListBookmarks(ctx context.Context, limit, offset int) ([]Bookmark, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("sqlite bookmark store is closed")
	}
	if err := s.Flush(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `SELECT f.file_key,f.host,f.share,f.path,b.created_at FROM bookmarks b JOIN files f ON f.scan_id=b.scan_id AND f.file_key=b.file_key WHERE b.scan_id=? ORDER BY b.created_at,b.file_key LIMIT ? OFFSET ?`, s.scanID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bookmarks := make([]Bookmark, 0, limit)
	for rows.Next() {
		var bookmark Bookmark
		var created string
		if err := rows.Scan(&bookmark.FileKey, &bookmark.Host, &bookmark.Share, &bookmark.Path, &created); err != nil {
			return nil, err
		}
		bookmark.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		bookmarks = append(bookmarks, bookmark)
	}
	return bookmarks, rows.Err()
}

func (s *SQLiteStore) BookmarkDetails(ctx context.Context, key string) (BookmarkDetails, error) {
	if s == nil || s.db == nil {
		return BookmarkDetails{}, fmt.Errorf("sqlite bookmark store is closed")
	}
	if err := s.Flush(); err != nil {
		return BookmarkDetails{}, err
	}
	var detail BookmarkDetails
	var created string
	if err := s.db.QueryRowContext(ctx, `SELECT f.file_key,f.host,f.share,f.path,b.created_at FROM bookmarks b JOIN files f ON f.scan_id=b.scan_id AND f.file_key=b.file_key WHERE b.scan_id=? AND b.file_key=?`, s.scanID, key).Scan(&detail.Bookmark.FileKey, &detail.Bookmark.Host, &detail.Bookmark.Share, &detail.Bookmark.Path, &created); err != nil {
		return detail, err
	}
	detail.Bookmark.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	findingRows, err := s.db.QueryContext(ctx, `SELECT payload FROM findings WHERE scan_id=? AND host=? AND share=? AND (path=? OR path LIKE ? || '!%') ORDER BY id LIMIT 25`, s.scanID, detail.Bookmark.Host, detail.Bookmark.Share, detail.Bookmark.Path, detail.Bookmark.Path)
	if err != nil {
		return detail, err
	}
	for findingRows.Next() {
		var payload []byte
		var finding scanner.Finding
		if err := findingRows.Scan(&payload); err != nil {
			findingRows.Close()
			return detail, err
		}
		if json.Unmarshal(payload, &finding) == nil {
			detail.Findings = append(detail.Findings, finding)
		}
	}
	findingRows.Close()
	credentialRows, err := s.db.QueryContext(ctx, `SELECT credential_type,identity,value,credential_key FROM credentials WHERE scan_id=? AND instr(credential_key, ?) > 0 ORDER BY id LIMIT 25`, s.scanID, "|"+detail.Bookmark.Path+"|")
	if err != nil {
		return detail, err
	}
	for credentialRows.Next() {
		var credential BookmarkCredential
		if err := credentialRows.Scan(&credential.Type, &credential.Identity, &credential.Value, &credential.Source); err != nil {
			credentialRows.Close()
			return detail, err
		}
		detail.Credentials = append(detail.Credentials, credential)
	}
	credentialRows.Close()
	return detail, credentialRows.Err()
}
