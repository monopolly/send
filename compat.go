package send

import (
	"context"

	"github.com/monopolly/send/mx"
	"github.com/monopolly/send/score"
)

// Aliases of the subpackages, kept for compatibility.

// MX caches mail servers of recipient domains, see package mx.
type MX = mx.MX

// NewMX creates an MX cache persisted to filename, see mx.New.
func NewMX(filename string) *MX {
	return mx.New(filename)
}

// EmailScore is the result of a mailbox check, see package score.
type EmailScore = score.EmailScore

// ValidOptions configures CheckEmails, see score.Options.
type ValidOptions = score.Options

// DefaultValidFrom is the MAIL FROM address of ValidEmails.
const DefaultValidFrom = score.DefaultFrom

// Providers is the list of public email providers, see score.Providers.
var Providers = score.Providers

// ValidEmails returns the addresses accepted by their mail servers, see score.ValidEmails.
func ValidEmails(list []string, cache *MX, proxylist ...string) ([]*EmailScore, error) {
	return score.ValidEmails(list, cache, proxylist...)
}

// CheckEmails probes addresses with RCPT TO, see score.Check.
func CheckEmails(ctx context.Context, list []string, cache *MX, o ValidOptions) ([]*EmailScore, error) {
	return score.Check(ctx, list, cache, o)
}

// ValidEmails checks addresses as the engine: MAIL FROM no-reply@domain, its HELO and proxies.
func (a *Engine) ValidEmails(ctx context.Context, list []string) ([]*EmailScore, error) {
	return score.Check(ctx, list, a.mx, score.Options{
		From:      "no-reply@" + a.domain,
		Helo:      a.helo,
		Proxy:     a.proxy,
		VerifyTLS: a.verifyTLS,
		Timeout:   a.timeout,
	})
}
