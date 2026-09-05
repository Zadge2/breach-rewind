package demo

import (
	"breachrewind/internal/collector"
	"breachrewind/internal/evidence"
	"breachrewind/internal/process"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

//go:embed scenario.py
var script []byte
var Scenarios = []string{"diagnostic-export", "path-traversal", "stale-authorization"}

// cappedBuffer bounds subprocess output even if a modified Python runtime misbehaves.
type cappedBuffer struct {
	sync.Mutex
	data     bytes.Buffer
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	if b.data.Len()+len(p) > evidence.MaxBytes {
		b.overflow = true
		return 0, errors.New("demo output limit exceeded")
	}
	return b.data.Write(p)
}
func Run(ctx context.Context, python, scenario, mode string) (evidence.Bundle, error) {
	valid := false
	for _, s := range Scenarios {
		if s == scenario {
			valid = true
		}
	}
	if !valid || (mode != "vulnerable" && mode != "patched") {
		return evidence.Bundle{}, errors.New("unknown scenario or mode")
	}
	dir, err := os.MkdirTemp("", "rewind-runner-")
	if err != nil {
		return evidence.Bundle{}, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "scenario.py")
	if err = os.WriteFile(path, script, 0600); err != nil {
		return evidence.Bundle{}, err
	}
	// Never use a shell. The server accepts only the fixed enums above, not commands.
	cmd := exec.CommandContext(ctx, python, "-I", path, "--scenario", scenario, "--mode", mode)
	var out, stderr cappedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err = process.Run(cmd); err != nil {
		return evidence.Bundle{}, fmt.Errorf("demo failed (%s); ensure Python 3.11+ is available: %s", err, evidence.Clean(stderr.data.String()))
	}
	if out.overflow || stderr.overflow {
		return evidence.Bundle{}, errors.New("demo output exceeded limit")
	}
	b, err := collector.Read(bytes.NewReader(out.data.Bytes()), "native", scenario+" / "+mode)
	if err != nil {
		return b, err
	}
	b.Scenario = scenario
	b.Mode = mode
	b.Collector = "python-instrumentation"
	b.Notes = append(b.Notes, "Executed against disposable synthetic fixtures and loopback-only services. Positive health checks ran before and after the security test.", "Application-reported instrumentation, not kernel tracing. Explicit links describe the instrumented operation. Severity is fixture-authored, not an exploitability verdict.")
	b.Redact()
	return b, b.Seal()
}
