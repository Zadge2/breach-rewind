package collector

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSDKCapture(t *testing.T) {
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("Python required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	path, err := filepath.Abs("../../sdk/python/example.py")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Capture(ctx, []string{"python", path}, "SDK test")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 3 || b.Collector != "python-sdk" {
		t.Fatal(b)
	}
	if b.Events[1].Kind != "file" || b.Events[1].Outcome != "attempted" {
		t.Fatal("audit attempt misrepresented")
	}
}
func TestCaptureNoTelemetry(t *testing.T) {
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("Python required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := Capture(ctx, []string{"python", "-I", "-c", "pass"}, "empty"); err == nil || !strings.Contains(err.Error(), "no native telemetry") {
		t.Fatal(err)
	}
	if _, err := Capture(ctx, nil, "empty"); err == nil {
		t.Fatal("empty command accepted")
	}
}
