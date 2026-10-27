package score

import (
	_ "embed"
	"strings"

	"github.com/monopolly/send/mx"
)

// https://gist.github.com/ammarshah/f5c2624d767f91a7cbdc4e54db8dd0bf

// Providers is the list of public email providers: gmail.com, mail.ru, ...
var Providers = newProviders(list)

type providers struct {
	list map[string]struct{}
}

func newProviders(s string) *providers {
	a := &providers{list: make(map[string]struct{})}
	for line := range strings.Lines(s) {
		if domain := mx.Normalize(line); domain != "" {
			a.list[domain] = struct{}{}
		}
	}
	return a
}

// Check reports whether domain belongs to a public email provider.
func (a *providers) Check(domain string) (provider bool) {
	_, provider = a.list[mx.Normalize(domain)]
	return
}
