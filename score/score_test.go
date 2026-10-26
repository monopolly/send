package score

import (
	"context"
	"strings"
	"testing"

	"github.com/monopolly/send/internal/smtptest"
	"github.com/monopolly/send/mx"
)

func TestCheckEmails(t *testing.T) {
	s := smtptest.New(t, func(s *smtptest.Server) {
		s.Rcpt = func(addr string) string {
			if strings.HasPrefix(addr, "bad@") {
				return "550 no such user"
			}
			return "250 ok"
		}
	})
	cache := mx.New("")
	cache.Set("example.com", []string{"127.0.0.1"}, s.Port)
	list := []string{" Good@Example.com ", "bad@example.com", "not an email"}

	res, err := ValidEmails(list, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Email != "good@example.com" || !res[0].Valid || !res[0].Business || res[0].Mass {
		t.Fatalf("ValidEmails = %+v", res)
	}

	res, err = Check(context.Background(), list, cache, Options{From: "x@any-domain.test", All: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("All: %d results", len(res))
	}
	for _, r := range res {
		switch r.Email {
		case "good@example.com":
			if !r.Valid {
				t.Errorf("%s: %+v", r.Email, r)
			}
		default:
			if r.Valid || r.Err == "" {
				t.Errorf("%s: %+v", r.Email, r)
			}
		}
	}

	st := s.Stats()
	msgs, froms := st.Msgs, st.Froms
	if len(msgs) != 0 {
		t.Errorf("probe sent %d messages", len(msgs))
	}
	if len(froms) != 2 || froms[0] != DefaultFrom || froms[1] != "x@any-domain.test" {
		t.Errorf("MAIL FROM = %v", froms)
	}
}

func TestCheckEmailsUnreachable(t *testing.T) {
	cache := mx.New("")
	cache.SetResolver(func(context.Context, string) ([]string, error) { return nil, mx.ErrNullMX })
	res, err := ValidEmails([]string{"a@example.com"}, cache)
	if err == nil || res != nil {
		t.Errorf("res = %v, err = %v", res, err)
	}
}

func TestProviders(t *testing.T) {
	for domain, want := range map[string]bool{"gmail.com": true, " GMAIL.com. ": true, "mail.ru": true, "example.org": false} {
		if got := Providers.Check(domain); got != want {
			t.Errorf("Check(%q) = %v", domain, got)
		}
	}
	if got := providerByMX([]string{"alt1.gmail-smtp-in.l.google.com."}); got != "google" {
		t.Errorf("providerByMX = %q", got)
	}
	if got := providerByMX([]string{"mx.example.org"}); got != "" {
		t.Errorf("providerByMX = %q", got)
	}
}
