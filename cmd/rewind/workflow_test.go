package main

import (
	"breachrewind/internal/evidence"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLIWorkflow(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	e := evidence.Event{ID: "event", Time: time.Now().UTC(), Kind: "request", Summary: "health", Source: "test", Severity: "info", Outcome: "success", Attributes: map[string]string{"route": "/health"}}
	raw, _ := json.Marshal(e)
	input := filepath.Join(dir, "input.jsonl")
	os.WriteFile(input, raw, 0600)
	call := func(args ...string) (string, error) {
		var out bytes.Buffer
		args = append(args, "--db", db)
		err := run(context.Background(), args, &out)
		return out.String(), err
	}
	result, err := call("record", "--input", input, "--title", "CLI workflow")
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(result)
	for _, args := range [][]string{{"list"}, {"inspect", "--id", id}, {"compare", "--before", id, "--after", id}} {
		s, err := call(args...)
		if err != nil || s == "" {
			t.Fatal(s, err)
		}
	}
	jsonPath := filepath.Join(dir, "export.json")
	if _, err = call("export", "--id", id, "--format", "json", "--out", jsonPath); err != nil {
		t.Fatal(err)
	}
	if _, err = call("verify", "--input", jsonPath); err != nil {
		t.Fatal(err)
	}
	if _, err = call("export", "--id", id, "--format", "json", "--out", jsonPath); err == nil {
		t.Fatal("overwrote export")
	}
	htmlPath := filepath.Join(dir, "report.html")
	if _, err = call("export", "--id", id, "--baseline", id, "--out", htmlPath); err != nil {
		t.Fatal(err)
	}
	db = filepath.Join(dir, "imported.db")
	if _, err = call("import", "--input", jsonPath); err != nil {
		t.Fatal(err)
	}
	if _, err = call("inspect", "--id", id); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"record"}, {"verify"}, {"record", "--input", input, "--format", "unknown"}, {"export", "--id", id}, {"export", "--id", id, "--out", filepath.Join(dir, "invalid"), "--format", "exe"}, {"capture", "--timeout", "0"}, {"inspect", "--id", "missing"}, {"compare", "--before", id, "--after", "missing"}} {
		if _, err = call(args...); err == nil {
			t.Fatal("invalid command succeeded", args)
		}
	}
}
