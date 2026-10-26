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
