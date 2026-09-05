package collector

import (
	"breachrewind/internal/evidence"
	"breachrewind/internal/process"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Capture runs an explicitly selected local command, never an imported recording.
// The child must use the SDK or otherwise write native JSONL to BREACH_REWIND_EVENTS.
func Capture(ctx context.Context, args []string, title string) (evidence.Bundle, error) {
	if len(args) == 0 {
		return evidence.Bundle{}, errors.New("capture requires a command after --")
	}
	dir, err := os.MkdirTemp("", "rewind-capture-")
	if err != nil {
		return evidence.Bundle{}, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "events.jsonl")
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(e), "BREACH_REWIND_EVENTS=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "BREACH_REWIND_EVENTS="+path)
	// Workload output may contain secrets. Do not copy it into evidence or logs.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	runErr := process.Run(cmd)
	file, err := os.Open(path)
	if err != nil {
		if runErr != nil {
			return evidence.Bundle{}, fmt.Errorf("command failed: %w", runErr)
		}
		return evidence.Bundle{}, errors.New("command produced no native telemetry; instrument it with the Python SDK")
	}
	defer file.Close()
	b, err := Read(file, "native", title)
	if err != nil {
		return b, err
	}
	b.Collector = "python-sdk"
	b.Notes = append(b.Notes, "Command capture uses cooperative application instrumentation. Audit events describe attempts, not guaranteed effects. Workload stdout/stderr are not recorded.")
	if runErr != nil {
		b.Notes = append(b.Notes, "Workload did not exit successfully: "+evidence.Clean(runErr.Error()))
	}
	b.Redact()
	return b, b.Seal()
}
