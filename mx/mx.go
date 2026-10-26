// Package mx caches mail servers of recipient domains, optionally persisted to a JSON file.
package mx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultTTL is how long servers found in DNS stay cached.
const DefaultTTL = 24 * time.Hour

// ErrNullMX means the domain does not accept mail (RFC 7505).
var ErrNullMX = errors.New("domain does not accept mail (null MX)")

// Resolver returns the mail servers of a domain by preference.
type Resolver func(ctx context.Context, domain string) ([]string, error)

// New creates an MX cache persisted to filename; an empty filename keeps it in memory only.
func New(filename string) (a *MX) {
	a = &MX{
		db:       make(map[string]*record),
		filename: filename,
		ttl:      DefaultTTL,
		resolve:  LookupDNS,
		log:      slog.New(slog.DiscardHandler),
	}
	a.load()
	return
}

// record is never modified after it is stored, so it can be read without the lock.
type record struct {
	Domain  string    `json:"domain"`  //gmail.com
	Servers []string  `json:"servers"` // by preference, the last successful first
	Port    int       `json:"port"`
	Expires time.Time `json:"expires,omitzero"`
	Static  bool      `json:"static,omitempty"` // set manually, never expires
}

// MX caches mail servers of recipient domains. It is safe for concurrent use.
type MX struct {
	mu       sync.RWMutex
	db       map[string]*record
	ttl      time.Duration
	resolve  Resolver
	log      *slog.Logger
	saveMu   sync.Mutex
	filename string
}

// SetTTL sets how long servers found in DNS stay cached; it applies to records stored after the call.
func (a *MX) SetTTL(ttl time.Duration) {
	a.mu.Lock()
	a.ttl = ttl
	a.mu.Unlock()
}

// SetResolver replaces the DNS lookup; nil restores LookupDNS.
func (a *MX) SetResolver(r Resolver) {
	if r == nil {
		r = LookupDNS
	}
	a.mu.Lock()
	a.resolve = r
	a.mu.Unlock()
}

// SetLogger sets the logger for cache file errors; nil disables logs.
func (a *MX) SetLogger(l *slog.Logger) {
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	a.mu.Lock()
	a.log = l
	a.mu.Unlock()
}

func (a *MX) load() {
	if a.filename == "" {
		return
	}
	b, err := os.ReadFile(a.filename)
	if err != nil {
		return
	}
	db := make(map[string]*record)
	if json.Unmarshal(b, &db) != nil {
		return
	}
	for k, v := range db {
		if v != nil {
			a.db[k] = v
		}
	}
}

// save writes the cache to disk atomically.
func (a *MX) save() error {
	if a.filename == "" {
		return nil
	}
	a.saveMu.Lock()
	defer a.saveMu.Unlock()

	a.mu.RLock()
	b, err := json.Marshal(a.db)
	a.mu.RUnlock()
	if err != nil {
		return err
	}

	if err = os.MkdirAll(filepath.Dir(a.filename), 0o755); err != nil {
		return err
	}
	tmp := a.filename + ".tmp"
	if err = os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, a.filename)
}

// saveLog saves the cache and logs a failure: the cache keeps working in memory.
func (a *MX) saveLog() {
	if err := a.save(); err != nil {
		a.mu.RLock()
		log := a.log
		a.mu.RUnlock()
		log.Warn("mx save", "file", a.filename, "err", err)
	}
}

// Set pins the servers of a domain, overriding DNS. The record never expires.
func (a *MX) Set(domain string, servers []string, port ...int) error {
	domain = Normalize(domain)
	b := &record{Domain: domain, Servers: slices.Clone(servers), Static: true}
	if port != nil {
		b.Port = port[0]
	}
	a.mu.Lock()
	a.db[domain] = b
	a.mu.Unlock()
	return a.save()
}

// Get returns the mail servers of a domain from the cache or DNS; reset forces a DNS lookup.
// port is 0 unless set with Set.
func (a *MX) Get(domain string, reset ...bool) (servers []string, port int) {
	servers, port, _ = a.Lookup(context.Background(), domain, reset != nil && reset[0])
	return
}

// Lookup is Get with a context and the lookup error.
// On a DNS failure a stale record is returned instead of the error.
func (a *MX) Lookup(ctx context.Context, domain string, reset bool) (servers []string, port int, err error) {
	domain = Normalize(domain)
	now := time.Now()

	a.mu.RLock()
	v := a.db[domain]
	ttl := a.ttl
	resolve := a.resolve
	a.mu.RUnlock()

	fresh := v != nil && len(v.Servers) > 0 && (v.Static || now.Before(v.Expires))
	if fresh && !reset {
		return slices.Clone(v.Servers), v.Port, nil
	}

	servers, err = resolve(ctx, domain)
	if err != nil {
		// serve a stale record rather than fail on a DNS hiccup
		if v != nil && len(v.Servers) > 0 && !errors.Is(err, ErrNullMX) {
			return slices.Clone(v.Servers), v.Port, nil
		}
		return nil, 0, err
	}
	if v != nil {
		port = v.Port
	}

	a.mu.Lock()
	a.db[domain] = &record{Domain: domain, Servers: slices.Clone(servers), Port: port, Expires: now.Add(ttl)}
	a.mu.Unlock()
	a.saveLog()
	return
}

// Promote moves host to the front of the domain servers so it is tried first next time.
func (a *MX) Promote(domain, host string) {
	domain = Normalize(domain)
	a.mu.Lock()
	v := a.db[domain]
	i := -1
	if v != nil {
		i = slices.Index(v.Servers, host)
	}
	if i <= 0 {
		a.mu.Unlock()
		return
	}
	r := *v
	r.Servers = append([]string{host}, slices.Delete(slices.Clone(v.Servers), i, i+1)...)
	a.db[domain] = &r
	a.mu.Unlock()
	a.saveLog()
}

// LookupDNS returns the mail servers of a domain by preference.
// Without MX records the domain itself is used (RFC 5321 5.1); null MX returns ErrNullMX (RFC 7505).
func LookupDNS(ctx context.Context, domain string) (servers []string, err error) {
	records, err := net.DefaultResolver.LookupMX(ctx, domain)
	for _, x := range records {
		host := strings.TrimSuffix(x.Host, ".")
		if host == "" {
			if len(records) == 1 {
				return nil, ErrNullMX
			}
			continue
		}
		servers = append(servers, host)
	}
	if len(servers) > 0 {
		return servers, nil
	}

	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		return nil, err
	}
	if _, err = net.DefaultResolver.LookupHost(ctx, domain); err != nil {
		return nil, err
	}
	return []string{domain}, nil
}

// Normalize lowercases a domain and strips spaces and the trailing dot.
func Normalize(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}
