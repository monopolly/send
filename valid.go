package send

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"send/mx"
)

// DefaultValidFrom is the MAIL FROM address of ValidEmails.
const DefaultValidFrom = "no-reply@apple.com"

// ValidOptions configures CheckEmails.
type ValidOptions struct {
	From      string        // MAIL FROM; any domain, not checked; DefaultValidFrom if empty
	Helo      string        // EHLO name; domain of From if empty
	Proxy     []string      // SOCKS5 proxies ip:port
	All       bool          // also return rejected addresses with Valid false and Err
	VerifyTLS bool          // verify server certificates
	Timeout   time.Duration // dial and per command timeout
}

type EmailScore struct {
	Email    string
	Valid    bool   // accepted by the mail server
	Err      string // server reply or reason for a rejected address
	Private  bool   // mailbox at a public provider: gmail.com, mail.ru
	Business bool   // mailbox at a company domain
	Mass     bool   // domain is a public provider
	Provider string // mail hosting detected by MX: google, microsoft, yandex, ...
}

// ValidEmails returns the addresses accepted by their mail servers, probed with
// MAIL FROM DefaultValidFrom. err is set only if no domain could be checked.
func ValidEmails(list []string, cache *MX, proxylist ...string) (validlist []*EmailScore, err error) {
	return CheckEmails(context.Background(), list, cache, ValidOptions{Proxy: proxylist})
}

// ValidEmails checks addresses as the engine: MAIL FROM no-reply@domain, its HELO and proxies.
func (a *Engine) ValidEmails(ctx context.Context, list []string) ([]*EmailScore, error) {
	return CheckEmails(ctx, list, a.mx, ValidOptions{
		From:      "no-reply@" + a.domain,
		Helo:      a.helo,
		Proxy:     a.proxy,
		VerifyTLS: a.verifyTLS,
		Timeout:   a.timeout,
	})
}

// CheckEmails probes addresses with RCPT TO on their MX servers without sending a message.
// Catch-all domains accept any address. err is set only if no domain could be checked.
func CheckEmails(ctx context.Context, list []string, cache *MX, o ValidOptions) (res []*EmailScore, err error) {
	if cache == nil {
		cache = NewMX("")
	}
	if o.From == "" {
		o.From = DefaultValidFrom
	}

	var domains []string
	groups := make(map[string][]string)
	for _, x := range list {
		x = strings.ToLower(strings.TrimSpace(x))
		if !validAddress(x) {
			if o.All {
				res = append(res, &EmailScore{Email: x, Err: "invalid address"})
			}
			continue
		}
		domain := domainonly(x)
		if _, ok := groups[domain]; !ok {
			domains = append(domains, domain)
		}
		groups[domain] = append(groups[domain], x)
	}

	var errs []error
	for _, domain := range domains {
		r, er := checkDomain(ctx, domain, groups[domain], cache, o)
		if er != nil {
			errs = append(errs, fmt.Errorf("%s: %w", domain, er))
			continue
		}
		res = append(res, r...)
	}
	if len(errs) == len(domains) {
		err = errors.Join(errs...)
	}
	return
}

// checkDomain probes the addresses of one domain on the first MX server that answers.
func checkDomain(ctx context.Context, domain string, list []string, cache *MX, o ValidOptions) (res []*EmailScore, err error) {
	servers, port, err := cache.Lookup(ctx, domain, false)
	if err != nil {
		return
	}
	if len(servers) == 0 {
		return nil, errors.New("mx servers not found")
	}
	if port == 0 {
		port = 25
	}

	opt := deliverOptions{helo: o.Helo, proxies: o.Proxy, verifyTLS: o.VerifyTLS, timeout: o.Timeout}
	for _, host := range servers {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		rejected, er := deliver(ctx, addr, o.From, list, nil, opt)
		if er != nil {
			err = er
			if isPermanent(er) || ctx.Err() != nil {
				return
			}
			continue
		}

		mass := Providers.Check(domain)
		provider := providerByMX(servers)
		for _, x := range list {
			r := &EmailScore{Email: x, Valid: true, Private: mass, Business: !mass, Mass: mass, Provider: provider}
			if er, ok := rejected[x]; ok {
				if !o.All {
					continue
				}
				r.Valid = false
				r.Err = er.Error()
			}
			res = append(res, r)
		}
		return res, nil
	}
	return
}

func validAddress(x string) bool {
	a, err := mail.ParseAddress(x)
	if err != nil || a.Address != x {
		return false
	}
	_, domain, _ := strings.Cut(x, "@")
	return strings.Contains(domain, ".")
}

var mxProviders = []struct{ suffix, name string }{
	{"google.com", "google"},
	{"googlemail.com", "google"},
	{"outlook.com", "microsoft"},
	{"hotmail.com", "microsoft"},
	{"yandex.net", "yandex"},
	{"yandex.ru", "yandex"},
	{"mail.ru", "mailru"},
	{"yahoodns.net", "yahoo"},
	{"icloud.com", "apple"},
	{"zoho.com", "zoho"},
	{"zoho.eu", "zoho"},
	{"protonmail.ch", "proton"},
	{"mimecast.com", "mimecast"},
	{"pphosted.com", "proofpoint"},
}

// providerByMX detects the mail hosting by MX host names.
func providerByMX(servers []string) string {
	for _, host := range servers {
		host = mx.Normalize(host)
		for _, p := range mxProviders {
			if host == p.suffix || strings.HasSuffix(host, "."+p.suffix) {
				return p.name
			}
		}
	}
	return ""
}
