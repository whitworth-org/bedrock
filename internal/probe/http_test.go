package probe

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestGetSurfacesDiagnosticRetryFailure locks in that when both the verified
// fetch and the insecure diagnostic retry fail, Get reports both failures
// instead of silently dropping the retry's error.
func TestGetSurfacesDiagnosticRetryFailure(t *testing.T) {
	t.Setenv(allowPrivateResolverEnv, "1")
	// Reserve a loopback port, then close it so every dial gets an
	// immediate connection-refused — first the verified fetch, then the
	// diagnostic retry.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	h := NewHTTP(time.Second)
	_, err = h.Get(context.Background(), "https://"+addr)
	if err == nil {
		t.Fatal("Get against a closed port must fail")
	}
	if !strings.Contains(err.Error(), "insecure diagnostic retry also failed") {
		t.Errorf("error should carry the retry failure; got %q", err.Error())
	}
}
