package evidence

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNullCollectionsRejected(t *testing.T) {
	for _, mutate := range []func(*Bundle){func(b *Bundle) { b.Events = nil }, func(b *Bundle) { b.Notes = nil }, func(b *Bundle) { b.Events[0].Attributes = nil }} {
		b := fixture()
		mutate(&b)
		b.Digest = b.Checksum()
		raw, _ := json.Marshal(b)
		if _, err := Decode(bytes.NewReader(raw)); err == nil {
			t.Fatal("null collection could crash downstream consumers")
		}
	}
}
func TestInvalidUTF8(t *testing.T) {
	if CheckJSON([]byte{'"', 0xff, '"'}) == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}
