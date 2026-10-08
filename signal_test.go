//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// signalChildEnv marks the child process TestSecondSignalTerminates starts.
const signalChildEnv = "BEDROCK_TEST_SIGNAL_CHILD"

// exitFirstSignalLost is the child's exit code when the first SIGINT does
// not cancel the context.
const exitFirstSignalLost = 3

// TestSecondSignalTerminates checks that the first SIGINT cancels the scan
// context and a second one kills the process, as it must when a check
// ignores ctx. The signals go to a child process running this test.
func TestSecondSignalTerminates(t *testing.T) {
	if os.Getenv(signalChildEnv) != "" {
		interruptTwice()
		return
	}
	if signal.Ignored(syscall.SIGINT) {
		t.Skip("SIGINT is ignored here (a background job), so its default action cannot be seen")
	}
	//nolint:gosec // G204: re-executes this test binary, not external input.
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecondSignalTerminates$")
	cmd.Env = append(os.Environ(), signalChildEnv+"=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("child: %v; want it killed by the second SIGINT", err)
	}
	if exitErr.ExitCode() == exitFirstSignalLost {
		t.Fatal("the first SIGINT did not cancel the context")
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGINT {
		t.Fatalf("child: %v; want it killed by the second SIGINT", err)
	}
}

// interruptTwice signals its own process until it dies. It exits 0 if the
// process survives five seconds of SIGINTs after the first one.
func interruptTwice() {
	ctx, stop := signalContext()
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		os.Exit(exitFirstSignalLost)
	}
	for range 500 {
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	os.Exit(0)
}
