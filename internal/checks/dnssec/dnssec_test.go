package dnssec

import (
	"context"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
	"weak"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// TestChainAfterProducerPanic covers the chain data producer panicking under
// one check: that check sees the panic (the registry reports it), and the
// chain check run afterwards reports the chain as unknown instead of
// dereferencing nil chain data.
func TestChainAfterProducerPanic(t *testing.T) {
	env := &probe.Env{Target: "example.test", Timeout: time.Second} // nil DNS panics
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("algorithms check did not see the producer's panic")
			}
		}()
		runAlgorithms(context.Background(), env)
	}()

	res := runChain(context.Background(), env)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(res), res)
	}
	r := res[0]
	if r.Status != report.Warn || !strings.Contains(r.Evidence, "failed in another DNSSEC check") {
		t.Errorf("got %s %q, want Warn naming the failed fetch", r.Status, r.Evidence)
	}
}

// TestEnsureChainDataReleasesEnv guards against per-Env state kept outside
// the Env: once a scan's Env is dropped, the DS/DNSKEY data must not keep it
// reachable.
func TestEnsureChainDataReleasesEnv(t *testing.T) {
	ref := runEnsureChainData(t)
	runtime.GC()
	runtime.GC()
	if ref.Value() != nil {
		t.Error("Env still reachable after ensureChainData; it keeps per-Env state outside the Env")
	}
}

// runEnsureChainData fetches the chain data on a fresh Env whose resolver is
// a closed loopback port, and returns only a weak reference to the Env.
func runEnsureChainData(t *testing.T) weak.Pointer[probe.Env] {
	t.Helper()
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	addr := pc.LocalAddr().String()
	if err := pc.Close(); err != nil {
		t.Fatalf("release loopback port %s: %v", addr, err)
	}
	env := probe.NewEnv("example.test", 2*time.Second, false, addr)
	if cd := ensureChainData(context.Background(), env); cd.dsErr == nil {
		t.Fatal("DS query to a closed port succeeded")
	}
	return weak.Make(env)
}
