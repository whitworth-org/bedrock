package probe

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedProducesOncePerKey(t *testing.T) {
	env := &Env{}
	var calls atomic.Int32
	produce := func() *int {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond) // let the other callers pile up
		n := 7
		return &n
	}

	const callers = 50
	got := make([]*int, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = Shared(env, "k", produce)
		}()
	}
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Fatalf("produce ran %d times, want 1", n)
	}
	for i, p := range got {
		if p == nil || p != got[0] {
			t.Fatalf("caller %d got %p, want the shared value %p", i, p, got[0])
		}
	}
	if v, _ := env.CacheGet("k"); v != any(got[0]) {
		t.Errorf("CacheGet(k) = %v, want the produced value", v)
	}
}

func TestSharedKeysProduceConcurrently(t *testing.T) {
	env := &Env{}
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	slow := make(chan string, 1)
	go func() {
		slow <- Shared(env, "slow", func() string {
			close(started)
			<-release
			return "slow"
		})
	}()
	<-started

	// While "slow" is producing, the cache and other keys' producers must
	// not wait for it.
	other := make(chan string, 1)
	go func() {
		env.CachePut("plain", "x")
		v, _ := env.CacheGet("plain")
		s, _ := v.(string)
		other <- s + Shared(env, "fast", func() string { return "y" })
	}()
	select {
	case got := <-other:
		if got != "xy" {
			t.Fatalf("other keys returned %q, want %q", got, "xy")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cache access blocked while another key's producer ran")
	}
	select {
	case got := <-slow:
		t.Fatalf("slow producer returned %q before it was released", got)
	default:
	}
}

func TestSharedReturnsExistingEntry(t *testing.T) {
	env := NewEnv("example.test", time.Second, false, "")
	env.CachePut("k", "seeded")
	got := Shared(env, "k", func() string {
		t.Error("produce called despite a seeded entry")
		return "produced"
	})
	if got != "seeded" {
		t.Errorf("Shared = %q, want the seeded %q", got, "seeded")
	}
}

func TestSharedWrongTypedOrNilEntryYieldsZero(t *testing.T) {
	env := &Env{}
	env.CachePut("wrong", 42)
	env.CachePut("nil", nil)
	mustNotProduce := func() *string {
		t.Error("produce called despite an existing entry")
		return nil
	}

	if got := Shared(env, "wrong", mustNotProduce); got != nil {
		t.Errorf("wrong-typed entry: Shared = %v, want nil", got)
	}
	if got := Shared(env, "nil", mustNotProduce); got != nil {
		t.Errorf("nil entry: Shared = %v, want nil", got)
	}
	if v, _ := env.CacheGet("wrong"); v != any(42) {
		t.Errorf("wrong-typed entry replaced with %v", v)
	}
}

func TestSharedZeroValueEnv(t *testing.T) {
	env := &Env{}
	if _, ok := env.CacheGet("absent"); ok {
		t.Error("CacheGet on a zero-value Env reported an entry")
	}
	env.CachePut("put", "v")
	if v, ok := env.CacheGet("put"); !ok || v != "v" {
		t.Errorf("CacheGet(put) = %v, %v; want v, true", v, ok)
	}
	if got := Shared(env, "shared", func() int { return 3 }); got != 3 {
		t.Errorf("Shared = %d, want 3", got)
	}
}

func TestSharedPanickingProducerYieldsZero(t *testing.T) {
	env := &Env{}
	var calls int
	produce := func() *int {
		calls++
		panic("producer failed")
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Error("first caller did not see the producer's panic")
			}
		}()
		Shared(env, "k", produce)
	}()
	if got := Shared(env, "k", produce); got != nil {
		t.Errorf("later caller got %v, want nil", got)
	}
	if calls != 1 {
		t.Errorf("produce ran %d times, want 1", calls)
	}
}

// TestSharedKeepsValueStoredDuringProduce covers a check that stores key with
// CachePut while another check's producer for key is still running.
func TestSharedKeepsValueStoredDuringProduce(t *testing.T) {
	env := &Env{}
	started := make(chan struct{})
	release := make(chan struct{})
	shared := make(chan string, 1)
	go func() {
		shared <- Shared(env, "k", func() string {
			close(started)
			<-release
			return "produced"
		})
	}()
	<-started
	env.CachePut("k", "stored")
	close(release)

	if got := <-shared; got != "stored" {
		t.Errorf("Shared = %q, want the value CachePut stored first", got)
	}
	if v, _ := env.CacheGet("k"); v != "stored" {
		t.Errorf("CacheGet(k) = %v, want stored", v)
	}
}
