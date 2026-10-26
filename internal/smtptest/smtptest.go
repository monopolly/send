// Package smtptest is a minimal SMTP server for tests.
package smtptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// Server is a minimal SMTP server listening on 127.0.0.1.
type Server struct {
	Port int

	Rcpt     func(addr string) string // RCPT reply, "250 ok" if nil
	StartTLS string                   // STARTTLS reply; not advertised if empty
	DropQuit bool                     // close the connection on QUIT without a reply
	Silent   bool                     // never send the greeting
	TLS      *tls.Config              // real STARTTLS with this config

	mu    sync.Mutex
	stats Stats
}

// Msg is a received message.
type Msg struct {
	From  string
	Rcpts []string
	Data  string
}

// Stats is what the server has seen so far.
type Stats struct {
	Conns    int      // accepted connections
	TLSConns int      // connections upgraded with STARTTLS
	Froms    []string // MAIL FROM addresses
	Msgs     []Msg    // messages accepted with DATA
}

// New starts a server, configured by setup before it accepts connections.
func New(t testing.TB, setup func(s *Server)) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	s := &Server{Port: ln.Addr().(*net.TCPAddr).Port}
	if setup != nil {
		setup(s)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

// Stats returns a copy of the server statistics.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.stats
	r.Froms = append([]string(nil), r.Froms...)
	r.Msgs = append([]Msg(nil), r.Msgs...)
	return r
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	s.mu.Lock()
	s.stats.Conns++
	s.mu.Unlock()

	if s.Silent {
		io.Copy(io.Discard, conn)
		return
	}

	tp := textproto.NewConn(conn)
	tp.PrintfLine("220 fake ready")
	var m Msg
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			tp.PrintfLine("250-fake")
			if s.StartTLS != "" || s.TLS != nil {
				tp.PrintfLine("250-STARTTLS")
			}
			tp.PrintfLine("250 8BITMIME")
		case strings.HasPrefix(cmd, "HELO"):
			tp.PrintfLine("250 fake")
		case cmd == "STARTTLS" && s.TLS != nil:
			tp.PrintfLine("220 go ahead")
			tc := tls.Server(conn, s.TLS)
			if tc.Handshake() != nil {
				return
			}
			s.mu.Lock()
			s.stats.TLSConns++
			s.mu.Unlock()
			tp = textproto.NewConn(tc)
		case cmd == "STARTTLS":
			tp.PrintfLine("%s", s.StartTLS)
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			m = Msg{From: between(line)}
			s.mu.Lock()
			s.stats.Froms = append(s.stats.Froms, m.From)
			s.mu.Unlock()
			tp.PrintfLine("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			addr := between(line)
			reply := "250 ok"
			if s.Rcpt != nil {
				reply = s.Rcpt(addr)
			}
			if strings.HasPrefix(reply, "2") {
				m.Rcpts = append(m.Rcpts, addr)
			}
			tp.PrintfLine("%s", reply)
		case cmd == "DATA":
			tp.PrintfLine("354 go ahead")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			m.Data = string(data)
			s.mu.Lock()
			s.stats.Msgs = append(s.stats.Msgs, m)
			s.mu.Unlock()
			tp.PrintfLine("250 queued")
		case cmd == "QUIT":
			if s.DropQuit {
				return
			}
			tp.PrintfLine("221 bye")
			return
		default:
			tp.PrintfLine("500 unknown command")
		}
	}
}

// SelfSigned returns a TLS config with a self-signed certificate for 127.0.0.1.
func SelfSigned(t testing.TB) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func between(line string) string {
	_, after, _ := strings.Cut(line, "<")
	before, _, _ := strings.Cut(after, ">")
	return before
}
