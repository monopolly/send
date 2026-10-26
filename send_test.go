package send

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/monopolly/email"
	"github.com/monopolly/errors"

	"github.com/monopolly/send/mx"
)

var testPrivate, _, _ = GenerateKeys("example.org")

// testEngine returns an engine whose MX for example.com points to the fake server via servers.
func testEngine(t *testing.T, s *fakeServer, servers []string, settings ...func(*Settings)) *Engine {
	t.Helper()
	cache := NewMX("")
	cache.Set("example.com", servers, s.port)
	st := Settings{Domain: "example.org", Helo: "mail.example.org", Private: testPrivate, MX: cache, Timeout: 5 * time.Second}
	for _, f := range settings {
		f(&st)
	}
	a, err := NewEngine(st)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func testEmail() *email.Email {
	return email.New().
		From("a@example.org").
		To("b@example.com").
		Subj("Hello").
		Text("Body").
		Done()
}

func TestSendAllRecipients(t *testing.T) {
	s := newFake(t, nil)
	a := testEngine(t, s, []string{"127.0.0.1"})

	m := email.New().
		From("a@example.org").
		To("b@example.com").
		CC("c@example.com").
		BCC("hidden@example.com").
		Subj("Hello").
		Text("Body").
		Done()
	if err := a.Send(m); err != nil {
		t.Fatal(err)
	}

	_, msgs, _ := s.stats()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1", len(msgs))
	}
	got := msgs[0]
	if want := []string{"b@example.com", "c@example.com", "hidden@example.com"}; !slices.Equal(got.rcpts, want) {
		t.Errorf("rcpts = %v, want %v", got.rcpts, want)
	}
	if got.from != "a@example.org" {
		t.Errorf("from = %q", got.from)
	}
	if !strings.Contains(got.data, "DKIM-Signature:") {
		t.Error("message is not DKIM signed")
	}
	if strings.Contains(got.data, "hidden@example.com") {
		t.Error("BCC address leaked into the message")
	}
}

func TestSendQuitFailureNoRedelivery(t *testing.T) {
	s := newFake(t, func(s *fakeServer) { s.dropQuit = true })
	a := testEngine(t, s, []string{"127.0.0.1", "localhost"})

	if err := a.Send(testEmail()); err != nil {
		t.Fatal(err)
	}
	conns, msgs, _ := s.stats()
	if len(msgs) != 1 || conns != 1 {
		t.Fatalf("messages = %d, connections = %d, want 1 and 1", len(msgs), conns)
	}
}

func TestSendPermanentErrorStops(t *testing.T) {
	s := newFake(t, func(s *fakeServer) {
		s.rcpt = func(string) string { return "550 no such user" }
	})
	a := testEngine(t, s, []string{"127.0.0.1", "localhost"})

	var handled []string
	a.ErrorHandler(func(to string, err errors.E) { handled = append(handled, to) })

	err := a.Send(testEmail())
	if err == nil {
		t.Fatal("expected error")
	}
	if err.ID() != errors.IDInvalid || err.Get(FieldSMTP).Int() != 550 || err.Get(FieldTo).String() != "b@example.com" {
		t.Errorf("err = %s", err)
	}
	if conns, _, _ := s.stats(); conns != 1 {
		t.Errorf("connections = %d, want 1: 5xx must not try the next MX", conns)
	}
	if !slices.Equal(handled, []string{"b@example.com"}) {
		t.Errorf("handler got %v", handled)
	}
}

func TestSendTemporaryErrorTriesNext(t *testing.T) {
	s := newFake(t, func(s *fakeServer) {
		s.rcpt = func(string) string { return "451 try later" }
	})
	a := testEngine(t, s, []string{"127.0.0.1", "localhost"})

	err := a.Send(testEmail())
	if err == nil || err.ID() != errors.IDLimit || err.Get(FieldSMTP).Int() != 451 {
		t.Fatalf("err = %s", err)
	}
	if conns, _, _ := s.stats(); conns != 2 {
		t.Errorf("connections = %d, want 2", conns)
	}
}

func TestSendPartialRejection(t *testing.T) {
	s := newFake(t, func(s *fakeServer) {
		s.rcpt = func(addr string) string {
			if strings.HasPrefix(addr, "bad@") {
				return "550 no such user"
			}
			return "250 ok"
		}
	})
	a := testEngine(t, s, []string{"127.0.0.1"})

	var mu sync.Mutex
	var handled []string
	a.ErrorHandler(func(to string, err errors.E) {
		mu.Lock()
		handled = append(handled, to)
		mu.Unlock()
	})

	m := testEmail()
	m.CC = append(m.CC, &email.New().To("bad@example.com").Done().To)
	err := a.Send(m)
	if err == nil || err.Get(FieldTo).String() != "bad@example.com" {
		t.Fatalf("err = %s", err)
	}
	if !slices.Equal(handled, []string{"bad@example.com"}) {
		t.Errorf("handler got %v", handled)
	}
	_, msgs, _ := s.stats()
	if len(msgs) != 1 || !slices.Equal(msgs[0].rcpts, []string{"b@example.com"}) {
		t.Errorf("messages = %+v", msgs)
	}
}

func TestSendStartTLSFallback(t *testing.T) {
	s := newFake(t, func(s *fakeServer) { s.starttls = "454 TLS not available" })
	a := testEngine(t, s, []string{"127.0.0.1"})

	if err := a.Send(testEmail()); err != nil {
		t.Fatal(err)
	}
	conns, msgs, _ := s.stats()
	if conns != 2 || len(msgs) != 1 {
		t.Errorf("connections = %d, messages = %d, want 2 and 1", conns, len(msgs))
	}
}

func TestSendStartTLS(t *testing.T) {
	config := selfSigned(t)

	// opportunistic: the self-signed certificate is accepted
	s := newFake(t, func(s *fakeServer) { s.tls = config })
	if err := testEngine(t, s, []string{"127.0.0.1"}).Send(testEmail()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	conns, tlsConns, msgs := s.conns, s.tlsConns, len(s.msgs)
	s.mu.Unlock()
	if conns != 1 || tlsConns != 1 || msgs != 1 {
		t.Errorf("connections = %d, tls = %d, messages = %d", conns, tlsConns, msgs)
	}

	// verified: the handshake fails and delivery falls back to plain text
	s = newFake(t, func(s *fakeServer) { s.tls = config })
	a := testEngine(t, s, []string{"127.0.0.1"}, func(st *Settings) { st.VerifyTLS = true })
	if err := a.Send(testEmail()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	conns, tlsConns, msgs = s.conns, s.tlsConns, len(s.msgs)
	s.mu.Unlock()
	if conns != 2 || tlsConns != 0 || msgs != 1 {
		t.Errorf("verify: connections = %d, tls = %d, messages = %d", conns, tlsConns, msgs)
	}
}

func TestSendTimeout(t *testing.T) {
	s := newFake(t, func(s *fakeServer) { s.silent = true })
	a := testEngine(t, s, []string{"127.0.0.1"}, func(st *Settings) { st.Timeout = 200 * time.Millisecond })

	start := time.Now()
	err := a.Send(testEmail())
	if err == nil || err.ID() != errors.IDConn {
		t.Fatalf("err = %s", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestSendContextCancel(t *testing.T) {
	s := newFake(t, func(s *fakeServer) { s.silent = true })
	a := testEngine(t, s, []string{"127.0.0.1"})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := a.SendContext(ctx, testEmail()); err == nil {
		t.Fatal("expected error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestSendPackageFunc(t *testing.T) {
	s := newFake(t, nil)
	cache := NewMX("")
	cache.Set("example.com", []string{"127.0.0.1"}, s.port)
	signer, err := ParseSigner(testPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := Send(testEmail(), "example.org", "dkim", "mail.example.org", signer, cache); err != nil {
		t.Fatal(err)
	}
	if _, msgs, _ := s.stats(); len(msgs) != 1 {
		t.Errorf("messages = %d", len(msgs))
	}
}

func TestInvalidKey(t *testing.T) {
	if _, err := NewEngine(Settings{Domain: "example.org", Private: []byte("garbage")}); err == nil {
		t.Error("NewEngine: expected error")
	}
	a := New("example.org", "", "", NewMX(""), []byte("garbage"), nil, nil)
	if err := a.Send(testEmail()); err == nil || err.ID() != errors.IDInvalid {
		t.Errorf("Send: err = %s", err)
	}
	if err := a.CustomSend(testEmail(), "example.org", "", []byte("garbage")); err == nil {
		t.Error("CustomSend: expected error")
	}
	if a.CustomSigner([]byte("garbage")) != nil {
		t.Error("CustomSigner: expected nil")
	}
}

func TestSendNoMX(t *testing.T) {
	cache := NewMX("")
	cache.SetResolver(func(context.Context, string) ([]string, error) { return nil, mx.ErrNullMX })
	a, err := NewEngine(Settings{Domain: "example.org", Private: testPrivate, MX: cache})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(testEmail()); err == nil || err.ID() != errors.IDConn {
		t.Errorf("err = %s", err)
	}
}
