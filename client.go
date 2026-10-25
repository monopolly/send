// SMTP client adapted from net/smtp (Copyright 2010 The Go Authors, BSD-style license).

package send

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// defaultTimeout bounds dialing and every single SMTP command (RFC 5321 4.5.3.2 suggests minutes).
const defaultTimeout = 2 * time.Minute

// client is an SMTP client connection.
type client struct {
	text       *textproto.Conn
	conn       net.Conn
	ctx        context.Context
	tls        bool
	serverName string
	ext        map[string]string // supported extensions
	localName  string            // the name to use in HELO/EHLO
	didHello   bool              // whether we've said HELO/EHLO
	helloError error             // the error from the hello
	timeout    time.Duration     // per command I/O timeout
	deadline   time.Time         // context deadline, zero if none
}

// dialConn opens a TCP connection to addr directly or through the first working SOCKS5 proxy.
func dialConn(ctx context.Context, addr string, proxies []string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := new(net.Dialer)
	if len(proxies) == 0 {
		return d.DialContext(ctx, "tcp", addr)
	}

	var errs []error
	for _, x := range proxies {
		conn, err := dialProxy(ctx, d, x, addr)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("proxy %s: %w", x, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// dialProxy connects to addr through the SOCKS5 proxy at proxyAddr ("127.0.0.1:9050").
func dialProxy(ctx context.Context, d *net.Dialer, proxyAddr, addr string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, d)
	if err != nil {
		return nil, err
	}
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("proxy dialer does not support context")
	}
	return cd.DialContext(ctx, "tcp", addr)
}

// newClient reads the server greeting from conn; host is the server name for TLS.
func newClient(ctx context.Context, conn net.Conn, host string, timeout time.Duration) (*client, error) {
	c := &client{
		text:       textproto.NewConn(conn),
		conn:       conn,
		ctx:        ctx,
		serverName: host,
		localName:  "localhost",
		timeout:    timeout,
	}
	c.deadline, _ = ctx.Deadline()
	_, c.tls = conn.(*tls.Conn)
	c.extend()
	if _, _, err := c.text.ReadResponse(220); err != nil {
		c.text.Close()
		return nil, err
	}
	return c, nil
}

// extend moves the I/O deadline one timeout ahead, never past the context deadline.
func (c *client) extend() {
	d := time.Now().Add(c.timeout)
	if !c.deadline.IsZero() && c.deadline.Before(d) {
		d = c.deadline
	}
	c.conn.SetDeadline(d)
	// re-check after setting: a concurrent cancel must win over the new deadline
	if c.ctx.Err() != nil {
		c.conn.SetDeadline(time.Unix(1, 0))
	}
}

// Close closes the connection.
func (c *client) Close() error {
	return c.text.Close()
}

// hello runs a hello exchange if needed.
func (c *client) hello() error {
	if !c.didHello {
		c.didHello = true
		err := c.ehlo()
		if err != nil {
			c.helloError = c.helo()
		}
	}
	return c.helloError
}

// Hello sends a HELO or EHLO to the server as the given host name.
// If Hello is called, it must be called before any of the other methods.
func (c *client) Hello(localName string) error {
	if err := validateLine(localName); err != nil {
		return err
	}
	if c.didHello {
		return errors.New("smtp: Hello called after other methods")
	}
	c.localName = localName
	return c.hello()
}

// cmd is a convenience function that sends a command and returns the response
func (c *client) cmd(expectCode int, format string, args ...any) (int, string, error) {
	c.extend()
	id, err := c.text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.text.StartResponse(id)
	defer c.text.EndResponse(id)
	return c.text.ReadResponse(expectCode)
}

// helo sends the HELO greeting to the server. It should be used only when the
// server does not support ehlo.
func (c *client) helo() error {
	c.ext = nil
	_, _, err := c.cmd(250, "HELO %s", c.localName)
	return err
}

// ehlo sends the EHLO (extended hello) greeting to the server. It
// should be the preferred greeting for servers that support it.
func (c *client) ehlo() error {
	_, msg, err := c.cmd(250, "EHLO %s", c.localName)
	if err != nil {
		return err
	}
	ext := make(map[string]string)
	extList := strings.Split(msg, "\n")
	if len(extList) > 1 {
		for _, line := range extList[1:] {
			k, v, _ := strings.Cut(line, " ")
			ext[strings.ToUpper(k)] = v
		}
	}
	c.ext = ext
	return nil
}

// StartTLS sends the STARTTLS command and encrypts all further communication.
// Only servers that advertise the STARTTLS extension support this function.
func (c *client) StartTLS(config *tls.Config) error {
	if err := c.hello(); err != nil {
		return err
	}
	if _, _, err := c.cmd(220, "STARTTLS"); err != nil {
		return err
	}
	tc := tls.Client(c.conn, config)
	c.extend()
	if err := tc.HandshakeContext(c.ctx); err != nil {
		return err
	}
	c.conn = tc
	c.text = textproto.NewConn(c.conn)
	c.tls = true
	return c.ehlo()
}

// Mail issues a MAIL command to the server using the provided email address.
// If the server supports the 8BITMIME extension, Mail adds the BODY=8BITMIME
// parameter.
func (c *client) Mail(from string) error {
	if err := validateLine(from); err != nil {
		return err
	}
	if err := c.hello(); err != nil {
		return err
	}
	cmdStr := "MAIL FROM:<%s>"
	if _, ok := c.ext["8BITMIME"]; ok {
		cmdStr += " BODY=8BITMIME"
	}
	_, _, err := c.cmd(250, cmdStr, from)
	return err
}

// Rcpt issues a RCPT command to the server using the provided email address.
func (c *client) Rcpt(to string) error {
	if err := validateLine(to); err != nil {
		return err
	}
	_, _, err := c.cmd(25, "RCPT TO:<%s>", to)
	return err
}

type dataCloser struct {
	c *client
	io.WriteCloser
}

func (d *dataCloser) Write(p []byte) (int, error) {
	d.c.extend()
	return d.WriteCloser.Write(p)
}

func (d *dataCloser) Close() error {
	d.c.extend()
	if err := d.WriteCloser.Close(); err != nil {
		return err
	}
	_, _, err := d.c.text.ReadResponse(250)
	return err
}

// Data issues a DATA command to the server and returns a writer that
// can be used to write the mail headers and body. The caller should
// close the writer before calling any more methods on c.
func (c *client) Data() (io.WriteCloser, error) {
	_, _, err := c.cmd(354, "DATA")
	if err != nil {
		return nil, err
	}
	return &dataCloser{c, c.text.DotWriter()}, nil
}

// Extension reports whether an extension is support by the server.
func (c *client) Extension(ext string) (bool, string) {
	if err := c.hello(); err != nil {
		return false, ""
	}
	param, ok := c.ext[strings.ToUpper(ext)]
	return ok, param
}

// Quit sends the QUIT command and closes the connection to the server.
func (c *client) Quit() error {
	if err := c.hello(); err != nil {
		return err
	}
	if _, _, err := c.cmd(221, "QUIT"); err != nil {
		return err
	}
	return c.text.Close()
}

// deliverOptions configures one SMTP session.
type deliverOptions struct {
	helo      string        // EHLO name, domain of from if empty
	proxies   []string      // SOCKS5 proxies ip:port, tried in order
	verifyTLS bool          // verify the server certificate
	timeout   time.Duration // dial and per command timeout
}

// startTLSError marks a failed STARTTLS negotiation; delivery may be retried in plain text.
type startTLSError struct{ err error }

func (e *startTLSError) Error() string { return "starttls: " + e.err.Error() }
func (e *startTLSError) Unwrap() error { return e.err }

// deliver sends msg to rcpts through the server at addr (host:port).
// It upgrades to TLS when the server offers STARTTLS and falls back to plain text
// if the upgrade fails; port 465 uses implicit TLS.
// err is nil once the server accepted the message for at least one recipient,
// rejected holds the recipients the server refused.
// A nil msg only probes the recipients: the session ends after RCPT.
func deliver(ctx context.Context, addr, from string, rcpts []string, msg []byte, o deliverOptions) (rejected map[string]error, err error) {
	rejected, err = session(ctx, addr, from, rcpts, msg, o, true)
	var tlsErr *startTLSError
	if errors.As(err, &tlsErr) && ctx.Err() == nil {
		rejected, err = session(ctx, addr, from, rcpts, msg, o, false)
	}
	return
}

func session(ctx context.Context, addr, from string, rcpts []string, msg []byte, o deliverOptions, starttls bool) (map[string]error, error) {
	if len(rcpts) == 0 {
		return nil, errors.New("smtp: no recipients")
	}
	if err := validateLine(from); err != nil {
		return nil, err
	}
	for _, x := range rcpts {
		if err := validateLine(x); err != nil {
			return nil, err
		}
	}
	if o.timeout <= 0 {
		o.timeout = defaultTimeout
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	conn, err := dialConn(ctx, addr, o.proxies, o.timeout)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	config := &tls.Config{ServerName: host, InsecureSkipVerify: !o.verifyTLS}
	if port == "465" {
		conn = tls.Client(conn, config)
	}
	c, err := newClient(ctx, conn, host, o.timeout)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer c.Close()

	helo := o.helo
	if helo == "" {
		helo = domainonly(from)
	}
	if helo == "" {
		helo = "localhost"
	}
	if err = c.Hello(helo); err != nil {
		return nil, err
	}
	if starttls && !c.tls {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err = c.StartTLS(config); err != nil {
				return nil, &startTLSError{err}
			}
		}
	}
	if err = c.Mail(from); err != nil {
		return nil, err
	}

	rejected := make(map[string]error)
	var first error
	for _, x := range rcpts {
		if err = c.Rcpt(x); err != nil {
			if !isReply(err) {
				return nil, err
			}
			rejected[x] = err
			if first == nil {
				first = err
			}
		}
	}
	// probe: only the RCPT answers are needed
	if msg == nil {
		c.Quit()
		return rejected, nil
	}
	if len(rejected) == len(rcpts) {
		c.Quit()
		return rejected, first
	}

	w, err := c.Data()
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(msg); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	// the message is accepted: a failed QUIT must not cause a redelivery
	c.Quit()
	return rejected, nil
}

// validateLine checks to see if a line has CR or LF as per RFC 5321
func validateLine(line string) error {
	if strings.ContainsAny(line, "\n\r") {
		return errors.New("smtp: A line must not contain CR or LF")
	}
	return nil
}
