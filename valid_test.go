package send

import (
	"context"
	"errors"
	"io"
	"net/textproto"
	"strings"
	"testing"

	merrors "github.com/monopolly/errors"
)

func TestCheckEmails(t *testing.T) {
	s := newFake(t, func(s *fakeServer) {
		s.rcpt = func(addr string) string {
			if strings.HasPrefix(addr, "bad@") {
				return "550 no such user"
			}
			return "250 ok"
		}
	})
	mx := NewMX("")
	mx.Set("example.com", []string{"127.0.0.1"}, s.port)
	list := []string{" Good@Example.com ", "bad@example.com", "not an email"}

	res, err := ValidEmails(list, mx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Email != "good@example.com" || !res[0].Valid || !res[0].Business || res[0].Mass {
		t.Fatalf("ValidEmails = %+v", res)
	}

	res, err = CheckEmails(context.Background(), list, mx, ValidOptions{From: "x@any-domain.test", All: true})
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

	_, msgs, froms := s.stats()
	if len(msgs) != 0 {
		t.Errorf("probe sent %d messages", len(msgs))
	}
	if len(froms) != 2 || froms[0] != DefaultValidFrom || froms[1] != "x@any-domain.test" {
		t.Errorf("MAIL FROM = %v", froms)
	}
}

func TestEngineValidEmails(t *testing.T) {
	s := newFake(t, nil)
	a := testEngine(t, s, []string{"127.0.0.1"})
	res, err := a.ValidEmails(context.Background(), []string{"b@example.com"})
	if err != nil || len(res) != 1 {
		t.Fatalf("res = %v, err = %v", res, err)
	}
	if _, _, froms := s.stats(); froms[0] != "no-reply@example.org" {
		t.Errorf("MAIL FROM = %v", froms)
	}
}

func TestCheckEmailsUnreachable(t *testing.T) {
	mx := NewMX("")
	mx.lookup = func(context.Context, string) ([]string, error) { return nil, errNullMX }
	res, err := ValidEmails([]string{"a@example.com"}, mx)
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

func TestGetSmtpErrorCode(t *testing.T) {
	cases := []struct {
		err  error
		id   string
		smtp int64
	}{
		{&textproto.Error{Code: 550, Msg: "no such user"}, merrors.IDInvalid, 550},
		{&textproto.Error{Code: 421, Msg: "busy"}, merrors.IDLimit, 421},
		{&textproto.Error{Code: 354, Msg: "?"}, merrors.IDEmail, 354},
		{io.EOF, merrors.IDConn, 0},
		{errors.New("x"), merrors.IDConn, 0},
	}
	for _, c := range cases {
		e := getSmtpErrorCode(c.err)
		if e.ID() != c.id || e.Get(FieldSMTP).Int() != c.smtp {
			t.Errorf("%v: %s", c.err, e)
		}
	}
}

func TestDomainOnly(t *testing.T) {
	if got := domainonly("a@gmail.com"); got != "gmail.com" {
		t.Errorf("domainonly = %q", got)
	}
	if got := normalizeDomain(" Gmail.COM. "); got != "gmail.com" {
		t.Errorf("normalizeDomain = %q", got)
	}
}
