package collector

import (
	"breachrewind/internal/evidence"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNative(t *testing.T) {
	e := evidence.Event{ID: "one", Time: time.Now().UTC(), Kind: "file", Summary: "read", Severity: "info", Source: "test", Outcome: "success", Attributes: map[string]string{"token": "sensitive"}}
	data, _ := json.Marshal(e)
	b, err := Read(strings.NewReader(string(data)+"\n"), "native", "capture")
	if err != nil {
		t.Fatal(err)
	}
	if b.Events[0].Attributes["token"] != "[REDACTED]" {
		t.Fatal("not redacted")
	}
}
func TestTraceeNanosecondPrecision(t *testing.T) {
	data := `{"timestamp":1788600000123456789,"processId":15,"parentProcessId":1,"processName":"python","eventName":"openat","returnValue":3,"args":[{"name":"pathname","value":"/fixture/file"}]}`
	b, err := Read(strings.NewReader(data), "tracee", "capture")
	if err != nil {
		t.Fatal(err)
	}
	e := b.Events[0]
	if e.Time.UnixNano() != 1788600000123456789 || e.Kind != "file" || e.Attributes["path"] != "/fixture/file" {
		t.Fatal(e)
	}
}
func TestTraceeDecimalSeconds(t *testing.T) {
	b, err := Read(strings.NewReader(`{"timestamp":1788600000.123456789,"eventName":"connect","returnValue":-1}`), "tracee", "test")
	if err != nil {
		t.Fatal(err)
	}
	if b.Events[0].Time.Nanosecond() != 123456789 || b.Events[0].Outcome != "failed" {
		t.Fatal(b)
	}
}
func TestRejectMalformed(t *testing.T) {
	for _, s := range []string{"", `{}`, `{"timestamp":1,"eventName":"openat"} {}`, strings.Repeat("x", 130<<10), `{"timestamp":"invalid","eventName":"openat"}`} {
		if _, err := Read(strings.NewReader(s), "tracee", "test"); err == nil {
			t.Fatal("accepted", s[:min(50, len(s))])
		}
	}
	if _, err := Read(strings.NewReader("{}"), "execute", "test"); err == nil {
		t.Fatal("accepted format")
	}
}
func FuzzTracee(f *testing.F) {
	f.Add(`{"timestamp":1788600000123456789,"eventName":"openat"}`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 65536 {
			t.Skip()
		}
		_, _ = Read(strings.NewReader(s), "tracee", "fuzz")
	})
}
