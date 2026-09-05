// Package process bounds the lifetime of trusted, explicitly launched workloads.
// It is lifecycle management, not an isolation or security sandbox.
package process

import (
	"os/exec"
	"time"
)

func Run(cmd *exec.Cmd) error {
	cmd.WaitDelay = 2 * time.Second
	cleanup, err := prepare(cmd)
	if err != nil {
		return err
	}
	defer cleanup()
	if err = cmd.Start(); err != nil {
		return err
	}
	if err = attach(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	defer release(cmd)
	return cmd.Wait()
}
