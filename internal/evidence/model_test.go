package evidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixture() Bundle {
	b := New("Test capture", "native")
	b.Events = []Event{{ID: "first", Time: time.Now().UTC(), Kind: "request", Summary: "Request", Severity: "info", Outcome: "success", Source: "test", PID: 1, Attributes: map[string]string{"route": "/health"}}}
	_ = b.Seal()
	return b
}
func TestRoundTrip(t *testing.T) {
	b := fixture()
	data, _ := json.Marshal(b)
	got, err := Decode(bytes.NewReader(data))
	if err != nil || got.Digest != b.Digest {
		t.Fatal(got, err)
	}
}
func TestTamperRejected(t *testing.T) {
	b := fixture()
	b.Title = "modified"
	data, _ := json.Marshal(b)
	if _, err := Decode(bytes.NewReader(data)); err == nil {
		t.Fatal("tampered evidence accepted")
	}
}
func TestInvalidBundles(t *testing.T) {
	cases := map[string]func(*Bundle){"version": func(b *Bundle) { b.Schema = "2" }, "id": func(b *Bundle) { b.ID = "../../escape" }, "duplicate": func(b *Bundle) { b.Events = append(b.Events, b.Events[0]) }, "parent": func(b *Bundle) { b.Events[0].ParentID = "missing" }, "severity": func(b *Bundle) { b.Events[0].Severity = "urgent" }, "kind": func(b *Bundle) { b.Events[0].Kind = "shell" }, "outcome": func(b *Bundle) { b.Events[0].Outcome = "unknown" }, "large-field": func(b *Bundle) { b.Events[0].Attributes["foo"] = strings.Repeat("x", 4097) }, "negative-pid": func(b *Bundle) { b.Events[0].PID = -1 }, "zero-time": func(b *Bundle) { b.Events[0].Time = time.Time{} }, "year": func(b *Bundle) { b.Events[0].Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			f(&b)
			if b.Validate() == nil {
				t.Fatal("accepted invalid bundle")
			}
		})
	}
}
func TestDecodeLimits(t *testing.T) {
	b := fixture()
	data, _ := json.Marshal(b)
	for _, bad := range [][]byte{append(data, []byte(` {}`)...), []byte(strings.Replace(string(data), `"schema":`, `"unknown":true,"schema":`, 1)), bytes.Repeat([]byte(" "), MaxBytes+1), []byte(`{"schema":"1.0","schema":"1.0"}`)} {
		if _, err := Decode(bytes.NewReader(bad)); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}
func TestRedaction(t *testing.T) {
	b := fixture()
	b.Title = `C:\Users\alice\file token=abc123`
	b.Events[0].Summary = "Bearer abcdefgh ghp_TEST_FIXTURE BR_DECOY_test"
	b.Events[0].Attributes = map[string]string{"cookie": "secret data", "path": "/home/alice/key", "authorization": "Bearer xxxx", "message": "api_key=abcdefghijkl"}
	b.Redact()
	raw, _ := json.Marshal(b)
	for _, secret := range []string{"alice", "abc123", "abcdefgh", "secret data", "BR_DECOY_"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("leaked %s", secret)
		}
	}
	if b.Events[0].Attributes["cookie"] != "[REDACTED]" {
		t.Fatal("secret not removed")
	}
}
func TestGraphConfidenceAndHostIsolation(t *testing.T) {
	b := fixture()
	e := b.Events[0]
	e.ID = "next"
	e.ParentID = "first"
	b.Events = append(b.Events, e)
	e.ID = "inferred"
	e.ParentID = ""
	b.Events = append(b.Events, e)
	e.ID = "elsewhere"
	e.Host = "different"
	b.Events = append(b.Events, e)
	g := Graph(b)
	if len(g) != 2 || g[0].Confidence != "observed" || g[1].Confidence != "inferred" {
		t.Fatal(g)
	}
}
func TestComparisonNormalization(t *testing.T) {
	a := fixture()
	b := fixture()
	b.Events[0].PID = 900
	b.Events[0].ID = "changed"
	b.Events[0].Time = b.Events[0].Time.Add(time.Hour)
	c := Compare(a, b)
	if c.Added != 0 || c.Removed != 0 || c.Unchanged != 1 {
		t.Fatal(c)
	}
	e := a.Events[0]
	e.ID = "read"
	e.Kind = "file"
	e.Severity = "high"
	e.Attributes = map[string]string{"path": "/private/key", "operation": "read"}
	a.Events = append(a.Events, e)
	c = Compare(a, b)
	if c.Removed != 1 || len(c.Changes) != 2 || c.Changes[0].Kind != "file" {
		t.Fatal(c)
	}
}
func TestParentTimeOrder(t *testing.T) {
	b := fixture()
	child := b.Events[0]
	child.ID = "child"
	child.ParentID = "first"
	child.Time = child.Time.Add(-time.Second)
	b.Events = append(b.Events, child)
	if b.Validate() == nil {
		t.Fatal("time-inverted link accepted")
	}
}
func FuzzDecode(f *testing.F) {
	b := fixture()
	raw, _ := json.Marshal(b)
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		b, err := Decode(bytes.NewReader(data))
		if err == nil {
			if err = b.Validate(); err != nil {
				t.Fatal(err)
			}
			if b.Digest != b.Checksum() {
				t.Fatal("unverified checksum")
			}
		}
	})
}
