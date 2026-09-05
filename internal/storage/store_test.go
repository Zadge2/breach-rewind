package storage

import (
	"breachrewind/internal/evidence"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func TestPersistenceAndDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b := evidence.New("persist", "test")
	b.Seal()
	if err = s.Put(b); err != nil {
		t.Fatal(err)
	}
	if s.Put(b) == nil {
		t.Fatal("duplicate overwrote recording")
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Get(b.ID)
	if err != nil || got.Digest != b.Digest {
		t.Fatal(err)
	}
	if _, err = s.Get("' OR 1=1 --"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("SQL parameterization failed", err)
	}
}
func TestBatchAtomic(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := evidence.New("batch", "test")
	b.Seal()
	if s.PutMany([]evidence.Bundle{b, b}) == nil {
		t.Fatal("accepted duplicate batch")
	}
	list, _ := s.List()
	if len(list) != 0 {
		t.Fatal("partial batch persisted")
	}
}
func TestConcurrent(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := evidence.New("concurrent", "test")
			b.Seal()
			if err := s.Put(b); err != nil {
				t.Error(err)
			}
			if _, err := s.List(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	list, err := s.List()
	if err != nil || len(list) != 16 {
		t.Fatal(len(list), err)
	}
}
