package main

import (
	"bytes"
	"context"
	"testing"
)

func TestHelpAndErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"version"}, {"--help"}} {
		var out bytes.Buffer
		if err := run(context.Background(), args, &out); err != nil || out.Len() == 0 {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"unknown"}, {"serve", "--unknown"}, {"list", "unexpected"}} {
		if err := run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatal("bad CLI accepted")
		}
	}
}
