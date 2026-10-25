package send

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

// DefaultMXTTL is how long servers found in DNS stay cached.
const DefaultMXTTL = 24 * time.Hour

var errNullMX = errors.New("domain does not accept mail (null MX)")

// NewMX creates an MX cache persisted to filename; an empty filename keeps it in memory only.
func NewMX(filename string) (a *MX) {
	a = &MX{
		db:       make(map[string]*mxrecord),
		filename: filename,
		ttl:      DefaultMXTTL,
		lookup:   lookupMX,
	}
	a.load()
	return
}

// mxrecord is never modified after it is stored, so it can be read without the lock.
type mxrecord struct {
	Domain  string    `json:"domain"`  //gmail.com
	Servers []string  `json:"servers"` // by preference, the last successful first
	Port    int       `json:"port"`
	Expires time.Time `json:"expires,omitzero"`
	Static  bool      `json:"static,omitempty"` // set manually, never expires
}

// MX caches mail servers of recipient domains. It is safe for concurrent use.
type MX struct {
	mu       sync.RWMutex
	db       map[string]*mxrecord
	ttl      time.Duration
	saveMu   sync.Mutex
	filename string
	lookup   func(ctx context.Context, domain string) ([]string, error)
}

// SetTTL sets how long servers found in DNS stay cached.
func (a *MX) SetTTL(ttl time.Duration) {
	a.mu.Lock()
	a.ttl = ttl
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
	db := make(map[string]*mxrecord)
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

// Set pins the servers of a domain, overriding DNS. The record never expires.
func (a *MX) Set(domain string, servers []string, port ...int) error {
	domain = normalizeDomain(domain)
	b := &mxrecord{Domain: domain, Servers: slices.Clone(servers), Static: true}
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
	servers, port, _ = a.get(context.Background(), domain, reset != nil && reset[0], nil)
	return
}

func (a *MX) get(ctx context.Context, domain string, reset bool, log *slog.Logger) (servers []string, port int, err error) {
	domain = normalizeDomain(domain)
	now := time.Now()

	a.mu.RLock()
	v := a.db[domain]
	ttl := a.ttl
	a.mu.RUnlock()

	fresh := v != nil && len(v.Servers) > 0 && (v.Static || now.Before(v.Expires))
	if fresh && !reset {
		return slices.Clone(v.Servers), v.Port, nil
	}

	servers, err = a.lookup(ctx, domain)
	if err != nil {
		// serve a stale record rather than fail on a DNS hiccup
		if v != nil && len(v.Servers) > 0 && !errors.Is(err, errNullMX) {
			return slices.Clone(v.Servers), v.Port, nil
		}
		return nil, 0, err
	}
	if v != nil {
		port = v.Port
	}

	a.mu.Lock()
	a.db[domain] = &mxrecord{Domain: domain, Servers: slices.Clone(servers), Port: port, Expires: now.Add(ttl)}
	a.mu.Unlock()
	if er := a.save(); er != nil && log != nil {
		log.Warn("mx save", "err", er)
	}
	return
}

// promote moves host to the front of the domain servers so it is tried first next time.
func (a *MX) promote(domain, host string, log *slog.Logger) {
	domain = normalizeDomain(domain)
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

	if err := a.save(); err != nil && log != nil {
		log.Warn("mx save", "err", err)
	}
}

// lookupMX returns the mail servers of a domain by preference.
// Without MX records the domain itself is used (RFC 5321 5.1); null MX means no mail (RFC 7505).
func lookupMX(ctx context.Context, domain string) (servers []string, err error) {
	records, err := net.DefaultResolver.LookupMX(ctx, domain)
	for _, x := range records {
		host := strings.TrimSuffix(x.Host, ".")
		if host == "" {
			if len(records) == 1 {
				return nil, errNullMX
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
