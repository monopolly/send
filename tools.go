package send

import (
	"strings"
)

func domainonly(email string) (domain string) {
	_, after, ok := strings.Cut(email, "@")
	if !ok {
		return email
	}
	return after
}

// normalizeDomain lowercases a domain and strips spaces and the trailing dot.
func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}
