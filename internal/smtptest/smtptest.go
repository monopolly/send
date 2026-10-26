package send

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

// fakeServer is a minimal SMTP server for tests.
type fakeServer struct {
	port int

	rcpt     func(addr string) string // RCPT reply, "250 ok" if nil
	starttls string                   // STARTTLS reply; not advertised if empty
	dropQuit bool                     // close the connection on QUIT without a reply
	silent   bool                     // never send the greeting
	tls      *tls.Config              // real STARTTLS with this config

	mu       sync.Mutex
	conns    int
	tlsConns int
	froms    []string
	msgs     []fakeMsg
}

type fakeMsg struct {
	from  string
	rcpts []string
	data  string
}

func newFake(t *testing.T, setup func(s *fakeServer)) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	s := &fakeServer{port: ln.Addr().(*net.TCPAddr).Port}
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

func (s *fakeServer) stats() (conns int, msgs []fakeMsg, froms []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns, append([]fakeMsg(nil), s.msgs...), append([]string(nil), s.froms...)
}

func (s *fakeServer) handle(conn net.Conn) {
	defer conn.Close()
	s.mu.Lock()
	s.conns++
	s.mu.Unlock()

	if s.silent {
		io.Copy(io.Discard, conn)
		return
	}

	tp := textproto.NewConn(conn)
	tp.PrintfLine("220 fake ready")
	var m fakeMsg
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			tp.PrintfLine("250-fake")
			if s.starttls != "" || s.tls != nil {
				tp.PrintfLine("250-STARTTLS")
			}
			tp.PrintfLine("250 8BITMIME")
		case strings.HasPrefix(cmd, "HELO"):
			tp.PrintfLine("250 fake")
		case cmd == "STARTTLS" && s.tls != nil:
			tp.PrintfLine("220 go ahead")
			tc := tls.Server(conn, s.tls)
			if tc.Handshake() != nil {
				return
			}
			s.mu.Lock()
			s.tlsConns++
			s.mu.Unlock()
			tp = textproto.NewConn(tc)
		case cmd == "STARTTLS":
			tp.PrintfLine("%s", s.starttls)
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			m = fakeMsg{from: between(line)}
			s.mu.Lock()
			s.froms = append(s.froms, m.from)
			s.mu.Unlock()
			tp.PrintfLine("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			addr := between(line)
			reply := "250 ok"
			if s.rcpt != nil {
				reply = s.rcpt(addr)
			}
			if strings.HasPrefix(reply, "2") {
				m.rcpts = append(m.rcpts, addr)
			}
			tp.PrintfLine("%s", reply)
		case cmd == "DATA":
			tp.PrintfLine("354 go ahead")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			m.data = string(data)
			s.mu.Lock()
			s.msgs = append(s.msgs, m)
			s.mu.Unlock()
			tp.PrintfLine("250 queued")
		case cmd == "QUIT":
			if s.dropQuit {
				return
			}
			tp.PrintfLine("221 bye")
			return
		default:
			tp.PrintfLine("500 unknown command")
		}
	}
}

// selfSigned returns a TLS config with a self-signed certificate for 127.0.0.1.
func selfSigned(t *testing.T) *tls.Config {
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
