package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStrictJSON(t *testing.T) {
	for _, s := range []string{`{"x":1,"x":2}`, `{"nested":{"x":1,"x":2}}`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), `[] []`} {
		if CheckJSON([]byte(s)) == nil {
			t.Fatal("accepted ambiguous JSON")
		}
	}
	if CheckJSON([]byte(`{"x":[1,{"x":2}]}`)) != nil {
		t.Fatal("valid nesting rejected")
	}
}
func TestIdentifierRedactionPreservesLinks(t *testing.T) {
	b := fixture()
	b.ID = "ghp_abcdefghijklmnop"
	b.Events[0].ID = "ghp_firstsecret"
	child := b.Events[0]
	child.ID = "child"
	child.ParentID = b.Events[0].ID
	child.TraceID = "ghp_anothersecret"
	b.Events = append(b.Events, child)
	b.Redact()
	if b.Events[1].ParentID != b.Events[0].ID {
		t.Fatal("redaction broke links")
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), "ghp_") {
		t.Fatal("secret identifier leaked")
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
}
func BenchmarkCompareTenThousand(b *testing.B) {
	before := fixture()
	before.Events = nil
	for i := 0; i < 10000; i++ {
		e := Event{ID: fmt.Sprint(i), Time: time.Now().UTC(), Kind: "file", Summary: "file", Severity: "info", Outcome: "observed", Source: "benchmark", Attributes: map[string]string{"path": fmt.Sprintf("/file/%d", i%200)}}
		before.Events = append(before.Events, e)
	}
	after := before
	after.Events = after.Events[:9000]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compare(before, after)
	}
}
