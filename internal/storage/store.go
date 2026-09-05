package storage

import (
	"breachrewind/internal/evidence"
	"database/sql"
	"encoding/json"
	"errors"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
)

type Store struct{ db *sql.DB }
type Summary struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Created   string `json:"created"`
	Scenario  string `json:"scenario"`
	Mode      string `json:"mode"`
	Collector string `json:"collector"`
	Events    int    `json:"events"`
	High      int    `json:"high"`
	Digest    string `json:"digest"`
}

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		path = abs
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version > 2 {
		db.Close()
		return nil, errors.New("database schema is newer than this application")
	}
	_, err = db.Exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS recordings (id TEXT PRIMARY KEY, created TEXT NOT NULL, document BLOB NOT NULL); CREATE TABLE IF NOT EXISTS recording_summaries (id TEXT PRIMARY KEY, created TEXT NOT NULL, summary BLOB NOT NULL); CREATE INDEX IF NOT EXISTS recording_summary_order ON recording_summaries(created DESC, id DESC);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	// Backfill one document at a time, keeping migration memory bounded.
	for {
		var id, document string
		err = db.QueryRow("SELECT id,document FROM recordings WHERE id NOT IN (SELECT id FROM recording_summaries) LIMIT 1").Scan(&id, &document)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			db.Close()
			return nil, err
		}
		b, e := evidence.Decode(strings.NewReader(document))
		if e != nil {
			db.Close()
			return nil, e
		}
		sum, _ := json.Marshal(summarize(b))
		if _, e = db.Exec("INSERT INTO recording_summaries(id,created,summary) VALUES(?,?,?)", id, b.Created.Format("2006-01-02T15:04:05.000000000Z07:00"), sum); e != nil {
			db.Close()
			return nil, e
		}
	}
	if _, err = db.Exec("PRAGMA user_version=2"); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Put(b evidence.Bundle) error {
	return s.PutMany([]evidence.Bundle{b})
}
func (s *Store) PutMany(bundles []evidence.Bundle) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, b := range bundles {
		if err = b.Validate(); err != nil {
			return err
		}
		if b.Checksum() != b.Digest {
			return errors.New("invalid checksum")
		}
		data, err := json.Marshal(b)
		if err != nil {
			return err
		}
		if len(data) > evidence.MaxBytes {
			return errors.New("recording too large")
		}
		if _, err = tx.Exec("INSERT INTO recordings(id,created,document) VALUES(?,?,?)", b.ID, b.Created.Format("2006-01-02T15:04:05.000000000Z07:00"), data); err != nil {
			return err
		}
		sum, _ := json.Marshal(summarize(b))
		if _, err = tx.Exec("INSERT INTO recording_summaries(id,created,summary) VALUES(?,?,?)", b.ID, b.Created.Format("2006-01-02T15:04:05.000000000Z07:00"), sum); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) Get(id string) (evidence.Bundle, error) {
	var data string
	err := s.db.QueryRow("SELECT document FROM recordings WHERE id=?", id).Scan(&data)
	if err != nil {
		return evidence.Bundle{}, err
	}
	return evidence.Decode(strings.NewReader(data))
}
func (s *Store) List() ([]Summary, error) {
	rows, err := s.db.Query("SELECT summary FROM recording_summaries ORDER BY created DESC, id DESC LIMIT 500")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Summary{}
	for rows.Next() {
		var data string
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		var summary Summary
		if len(data) > 4096 {
			return nil, errors.New("invalid summary size")
		}
		if err = json.Unmarshal([]byte(data), &summary); err != nil {
			return nil, err
		}
		out = append(out, summary)
	}
	return out, rows.Err()
}
func summarize(b evidence.Bundle) Summary {
	high := 0
	for _, e := range b.Events {
		if evidence.Rank(e.Severity) >= 3 && e.Outcome != "blocked" {
			high++
		}
	}
	return Summary{b.ID, b.Title, b.Created.Format("2006-01-02T15:04:05Z07:00"), b.Scenario, b.Mode, b.Collector, len(b.Events), high, b.Digest}
}
