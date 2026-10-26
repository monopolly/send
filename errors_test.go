package send

import (
	"context"
	"errors"
	"io"
	"net/textproto"
	"testing"

	merrors "github.com/monopolly/errors"

	"github.com/monopolly/send/internal/smtptest"
)

func TestEngineValidEmails(t *testing.T) {
	s := smtptest.New(t, nil)
	a := testEngine(t, s, []string{"127.0.0.1"})
	res, err := a.ValidEmails(context.Background(), []string{"b@example.com"})
	if err != nil || len(res) != 1 {
		t.Fatalf("res = %v, err = %v", res, err)
	}
	if froms := s.Stats().Froms; froms[0] != "no-reply@example.org" {
		t.Errorf("MAIL FROM = %v", froms)
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
}
