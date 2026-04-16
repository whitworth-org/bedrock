package dns

import "testing"

func TestMaxCNAMEChain_IsConservative(t *testing.T) {
	// Tripwire: don't let someone bump the limit silently. Major recursors
	// (Unbound, BIND) cap at 8-16; we keep the lower end intentionally.
	if maxCNAMEChain > 8 {
		t.Fatalf("maxCNAMEChain=%d exceeds the documented ceiling of 8 (RFC 1912 §2.4 spirit)", maxCNAMEChain)
	}
}
