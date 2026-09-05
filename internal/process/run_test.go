package process

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestLifecycle(t *testing.T) {
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("Python required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := Run(exec.CommandContext(ctx, "python", "-I", "-c", "print('ok')")); err != nil {
		t.Fatal(err)
	}
}
func TestTimeout(t *testing.T) {
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("Python required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := Run(exec.CommandContext(ctx, "python", "-I", "-c", "import time; time.sleep(20)")); err == nil {
		t.Fatal("timeout ignored")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("termination took too long")
	}
}
