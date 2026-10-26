package client

import (
	"context"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/monopolly/send/internal/smtptest"
)

func addr(s *smtptest.Server) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port))
}

var msg = []byte("Subject: hi\r\n\r\nbody\r\n")

func TestDeliver(t *testing.T) {
	s := smtptest.New(t, func(s *smtptest.Server) {
		s.Rcpt = func(a string) string {
			if strings.HasPrefix(a, "bad@") {
				return "550 no such user"
			}
			return "250 ok"
		}
	})
	rejected, err := Deliver(context.Background(), addr(s), "a@example.org", []string{"b@example.com", "bad@example.com"}, msg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 1 || !IsPermanent(rejected["bad@example.com"]) {
		t.Errorf("rejected = %v", rejected)
	}
	st := s.Stats()
	if len(st.Msgs) != 1 || len(st.Msgs[0].Rcpts) != 1 || !strings.Contains(st.Msgs[0].Data, "body") {
		t.Errorf("stats = %+v", st)
	}
}

func TestDeliverAllRejected(t *testing.T) {
	s := smtptest.New(t, func(s *smtptest.Server) {
		s.Rcpt = func(string) string { return "451 later" }
	})
	_, err := Deliver(context.Background(), addr(s), "a@example.org", []string{"b@example.com"}, msg, Options{})
	if !IsReply(err) || IsPermanent(err) {
		t.Errorf("err = %v", err)
	}
	if len(s.Stats().Msgs) != 0 {
		t.Error("message sent")
	}
}

func TestDeliverQuitDropped(t *testing.T) {
	s := smtptest.New(t, func(s *smtptest.Server) { s.DropQuit = true })
	if _, err := Deliver(context.Background(), addr(s), "a@example.org", []string{"b@example.com"}, msg, Options{}); err != nil {
		t.Fatalf("accepted message reported as failed: %v", err)
	}
}

func TestDeliverEmpty(t *testing.T) {
	if _, err := Deliver(context.Background(), "127.0.0.1:1", "a@example.org", []string{"b@example.com"}, nil, Options{}); err == nil {
		t.Error("expected error")
	}
	if _, err := Deliver(context.Background(), "127.0.0.1:1", "a@example.org", nil, msg, Options{}); err == nil {
		t.Error("expected error")
	}
	if _, err := Deliver(context.Background(), "127.0.0.1:1", "a@example.org\r\nRSET", []string{"b@example.com"}, msg, Options{}); err == nil {
		t.Error("expected error for CRLF injection")
	}
}

func TestProbe(t *testing.T) {
	s := smtptest.New(t, func(s *smtptest.Server) {
		s.Rcpt = func(string) string { return "550 no such user" }
	})
	rejected, err := Probe(context.Background(), addr(s), "x@any.test", []string{"b@example.com"}, Options{Helo: "probe.test"})
	if err != nil || len(rejected) != 1 {
		t.Fatalf("rejected = %v, err = %v", rejected, err)
	}
	if st := s.Stats(); len(st.Msgs) != 0 || st.Froms[0] != "x@any.test" {
		t.Errorf("stats = %+v", st)
	}
}

func TestStartTLS(t *testing.T) {
	config := smtptest.SelfSigned(t)

	s := smtptest.New(t, func(s *smtptest.Server) { s.TLS = config })
	if _, err := Deliver(context.Background(), addr(s), "a@example.org", []string{"b@example.com"}, msg, Options{}); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.Conns != 1 || st.TLSConns != 1 {
		t.Errorf("stats = %+v", st)
	}

	// a verification failure falls back to plain text
	s = smtptest.New(t, func(s *smtptest.Server) { s.TLS = config })
	if _, err := Deliver(context.Background(), addr(s), "a@example.org", []string{"b@example.com"}, msg, Options{VerifyTLS: true}); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.Conns != 2 || st.TLSConns != 0 || len(st.Msgs) != 1 {
		t.Errorf("verify: stats = %+v", st)
	}
}

func TestTimeoutAndCancel(t *testing.T) {
	s := smtptest.New(t, func(s *smtptest.Server) { s.Silent = true })

	start := time.Now()
	if _, err := Deliver(context.Background(), addr(s), "a@example.org", []string{"b@example.com"}, msg, Options{Timeout: 200 * time.Millisecond}); err == nil || IsReply(err) {
		t.Errorf("timeout: err = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Deliver(ctx, addr(s), "a@example.org", []string{"b@example.com"}, msg, Options{}); err == nil {
		t.Error("cancel: expected error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestIsReply(t *testing.T) {
	if IsReply(io.EOF) || IsPermanent(io.EOF) {
		t.Error("EOF is not a reply")
	}
	if !IsPermanent(&textproto.Error{Code: 554}) || IsPermanent(&textproto.Error{Code: 421}) {
		t.Error("IsPermanent")
	}
}
