package send

import (
	"context"
	"crypto"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/monopolly/email"
	"github.com/monopolly/errors"

	"github.com/monopolly/send/mx"
)

// FieldTo is the errors.E field with the recipient the error belongs to.
const FieldTo = "to"

var discard = slog.New(slog.DiscardHandler)

// Send signs r and delivers it to all To, CC and BCC recipients through their MX servers.
// helo is the EHLO name (mail.domain.com). It returns the error of the first failed recipient.
func Send(r *email.Email, domain, selector, helo string, signer crypto.Signer, cache *MX) (err errors.E) {
	b, err := build(r, domain, selector, signer)
	if err != nil {
		return
	}
	if cache == nil {
		cache = NewMX("")
	}
	rcpts := recipients(r)
	failed := send(context.Background(), r.From.Address, rcpts, b, cache, sendOptions{deliverOptions: deliverOptions{helo: helo}, log: discard})
	return firstError(rcpts, failed, nil)
}

type sendOptions struct {
	deliverOptions
	log *slog.Logger
}

// recipients returns the unique To, CC and BCC addresses of r.
func recipients(r *email.Email) (list []string) {
	seen := make(map[string]bool)
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		k := strings.ToLower(addr)
		if addr == "" || seen[k] {
			return
		}
		seen[k] = true
		list = append(list, addr)
	}
	add(r.To.Address)
	for _, x := range slices.Concat(r.CC, r.BCC) {
		if x != nil {
			add(x.Address)
		}
	}
	return
}

// firstError calls h for every failed recipient and returns the first error in rcpts order.
func firstError(rcpts []string, failed map[string]errors.E, h func(to string, err errors.E)) (err errors.E) {
	for _, x := range rcpts {
		e, ok := failed[x]
		if !ok {
			continue
		}
		if h != nil {
			h(x, e)
		}
		if err == nil {
			err = e
		}
	}
	return
}

// send delivers body to rcpts grouped by domain and returns the recipients that failed.
func send(ctx context.Context, from string, rcpts []string, body []byte, cache *MX, o sendOptions) (failed map[string]errors.E) {
	failed = make(map[string]errors.E)
	var domains []string
	groups := make(map[string][]string)
	for _, x := range rcpts {
		domain := mx.Normalize(domainonly(x))
		if _, ok := groups[domain]; !ok {
			domains = append(domains, domain)
		}
		groups[domain] = append(groups[domain], x)
	}

	for _, domain := range domains {
		list := groups[domain]
		rejected, err := sendDomain(ctx, from, domain, list, body, cache, o)
		for _, x := range list {
			e := err
			if e == nil {
				er, ok := rejected[x]
				if !ok {
					continue
				}
				e = getSmtpErrorCode(er)
			}
			e = slices.Clone(e)
			e.Set(FieldTo, x)
			failed[x] = e
		}
	}
	return
}

// sendDomain tries the MX servers of domain in order until one accepts the message.
// A 5xx reply stops the loop: other servers of the same domain will answer the same.
func sendDomain(ctx context.Context, from, domain string, rcpts []string, body []byte, cache *MX, o sendOptions) (map[string]error, errors.E) {
	servers, port, er := cache.Lookup(ctx, domain, false)
	if er != nil {
		o.log.Debug("mx", "domain", domain, "err", er)
		return nil, errors.Connection(fmt.Sprintf("mx %s: %v", domain, er))
	}
	if len(servers) == 0 {
		return nil, errors.Connection("mx servers not found")
	}
	if port == 0 {
		port = 25
	}

	var errs []error
	for _, host := range servers {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		o.log.Debug("sendmail", "try", addr, "rcpts", len(rcpts))
		rejected, er := deliver(ctx, addr, from, rcpts, body, o.deliverOptions)
		if er == nil {
			o.log.Debug("sendmail", "success", addr, "rejected", len(rejected))
			cache.Promote(domain, host)
			return rejected, nil
		}
		o.log.Debug("sendmail", "addr", addr, "err", er)
		errs = append(errs, fmt.Errorf("%s: %w", addr, er))
		if isPermanent(er) || ctx.Err() != nil {
			break
		}
	}

	err := getSmtpErrorCode(errs[len(errs)-1])
	if len(errs) > 1 {
		err.Comment(stderrors.Join(errs...).Error())
	}
	return nil, err
}
