package send

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func countingLookup(n *atomic.Int32, servers []string, err error) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) {
		n.Add(1)
		return servers, err
	}
}

func TestMXCacheAndTTL(t *testing.T) {
	var n atomic.Int32
	mx := NewMX("")
	mx.lookup = countingLookup(&n, []string{"mx1.example.com", "mx2.example.com"}, nil)

	for range 3 {
		servers, port := mx.Get("Example.COM.")
		if !slices.Equal(servers, []string{"mx1.example.com", "mx2.example.com"}) || port != 0 {
			t.Fatalf("Get = %v %d", servers, port)
		}
	}
	if n.Load() != 1 {
		t.Errorf("lookups = %d, want 1", n.Load())
	}

	mx.Get("example.com", true)
	if n.Load() != 2 {
		t.Errorf("reset: lookups = %d, want 2", n.Load())
	}

	// the new TTL applies to the next stored record
	mx.SetTTL(time.Nanosecond)
	mx.Get("example.com", true)
	time.Sleep(time.Millisecond)
	mx.Get("example.com")
	if n.Load() != 4 {
		t.Errorf("expired: lookups = %d, want 4", n.Load())
	}
}

func TestMXStaleOnLookupError(t *testing.T) {
	var n atomic.Int32
	mx := NewMX("")
	mx.SetTTL(time.Nanosecond)
	mx.lookup = countingLookup(&n, []string{"mx1.example.com"}, nil)
	mx.Get("example.com")
	time.Sleep(time.Millisecond)

	mx.lookup = countingLookup(&n, nil, errors.New("dns timeout"))
	if servers, _ := mx.Get("example.com"); !slices.Equal(servers, []string{"mx1.example.com"}) {
		t.Errorf("stale record not served: %v", servers)
	}

	if servers, _ := mx.Get("unknown.example"); servers != nil {
		t.Errorf("failed lookup returned %v", servers)
	}
}

func TestMXStaticPersistAndPromote(t *testing.T) {
	file := filepath.Join(t.TempDir(), "dir", "mx.json")
	var n atomic.Int32

	mx := NewMX(file)
	mx.lookup = countingLookup(&n, nil, errors.New("must not be called"))
	mx.SetTTL(time.Nanosecond)
	if err := mx.Set("example.com.", []string{"a.example.com", "b.example.com", "c.example.com"}, 2525); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)

	// static records never expire and success keeps the whole list
	mx.promote("example.com", "c.example.com", nil)
	servers, port := mx.Get("example.com")
	if !slices.Equal(servers, []string{"c.example.com", "a.example.com", "b.example.com"}) || port != 2525 {
		t.Errorf("Get = %v %d", servers, port)
	}
	if n.Load() != 0 {
		t.Errorf("lookups = %d, want 0", n.Load())
	}

	loaded := NewMX(file)
	loaded.lookup = mx.lookup
	if got, port := loaded.Get("example.com"); !slices.Equal(got, servers) || port != 2525 {
		t.Errorf("loaded = %v %d", got, port)
	}
}

func TestMXConcurrent(t *testing.T) {
	var n atomic.Int32
	mx := NewMX(filepath.Join(t.TempDir(), "mx.json"))
	mx.lookup = countingLookup(&n, []string{"a.example.com", "b.example.com"}, nil)

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			switch i % 3 {
			case 0:
				mx.Get("example.com")
			case 1:
				mx.Set("example.net", []string{"x.example.net"})
			default:
				mx.promote("example.com", "b.example.com", nil)
			}
		})
	}
	wg.Wait()
}
