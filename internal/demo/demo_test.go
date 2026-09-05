package demo

import (
	"breachrewind/internal/evidence"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAllScenarios(t *testing.T) {
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("Python is not installed")
	}
	for _, s := range Scenarios {
		t.Run(s, func(t *testing.T) {
			for _, mode := range []string{"vulnerable", "patched"} {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				b, err := Run(ctx, "python", s, mode)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				high, blocks, health := 0, 0, 0
				for _, e := range b.Events {
					if evidence.Rank(e.Severity) >= 3 {
						high++
					}
					if e.Kind == "policy" && e.Outcome == "blocked" {
						blocks++
					}
					if e.Kind == "response" && e.Attributes["route"] == "/health" && e.Attributes["status"] == "200" {
						health++
					}
				}
				if health != 2 {
					t.Fatal("positive controls missing")
				}
				if mode == "patched" && (high != 0 || blocks == 0) {
					t.Fatal("patch did not block behavior")
				}
				if mode == "vulnerable" && high == 0 {
					t.Fatal("no vulnerable behavior")
				}
				data, _ := json.Marshal(b)
				if strings.Contains(string(data), "BR_DECOY_") {
					t.Fatal("decoy credential leaked")
				}
				if b.Validate() != nil || b.Digest != b.Checksum() {
					t.Fatal("invalid evidence")
				}
			}
		})
	}
}
func TestInvalidInput(t *testing.T) {
	if _, err := Run(context.Background(), "python", "../../outside", "vulnerable"); err == nil {
		t.Fatal("invalid scenario accepted")
	}
	if _, err := Run(context.Background(), "python", Scenarios[0], "shell"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}
func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, "python", Scenarios[0], "patched"); err == nil {
		t.Fatal("cancelled run succeeded")
	}
}
