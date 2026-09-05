package storage

import (
	"breachrewind/internal/evidence"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestMigrateV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("CREATE TABLE recordings(id TEXT PRIMARY KEY,created TEXT,document BLOB); PRAGMA user_version=1;")
	if err != nil {
		t.Fatal(err)
	}
	b := evidence.New("old", "test")
	b.Seal()
	raw, _ := json.Marshal(b)
	db.Exec("INSERT INTO recordings VALUES(?,?,?)", b.ID, b.Created.String(), raw)
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	list, err := s.List()
	if err != nil || len(list) != 1 || list[0].ID != b.ID {
		t.Fatal(list, err)
	}
}
func TestRejectNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	db, _ := sql.Open("sqlite", path)
	db.Exec("PRAGMA user_version=999")
	db.Close()
	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("downgraded newer database")
	}
}
