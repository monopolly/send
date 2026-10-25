// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package smtp implements the Simple Mail Transfer Protocol as defined in RFC 5321.
// It also implements the following extensions:
//
//	8BITMIME  RFC 1652
//	AUTH      RFC 2554
//	STARTTLS  RFC 3207
//
// Additional extensions may be handled by clients.
//
// The smtp package is frozen and is not accepting new features.
// Some external packages provide more functionality. See:
//
//	https://godoc.org/?q=smtp
package send

import (
	"crypto/tls"
	"strings"

	"github.com/monopolly/valid"
)

// valid any emails, err only if server error
func ValidEmails(list []string, mx *MX, proxylist ...string) (validlist []*EmailScore, err error) {
	domains := make(map[string][]string)
	var has bool

	for _, x := range list {
		x = strings.ToLower(x)
		x = strings.TrimSpace(x)
		if !valid.Email(x) {
			continue
		}
		p := strings.Split(x, "@")
		if len(p) != 2 {
			continue
		}
		domain := p[1]
		domains[domain] = append(domains[domain], x)
		has = true
	}

	if !has {
		return
	}

	for domain, emaillist := range domains {
		mxhosts, _ := mx.Get(domain)
		if len(mxhosts) == 0 {
			//wrong mx
			continue
		}

		r, err := validmaildomains(mxhosts, emaillist, proxylist...)
		if err != nil {
			continue
		}
		validlist = append(validlist, r...)
	}

	return
}

func validmaildomains(mxhosts []string, list []string, proxylist ...string) (valid []*EmailScore, err error) {
	var last error
	for _, x := range mxhosts {
		r, last := validdomain(x, list, proxylist...)
		if last != nil {
			continue
		}
		valid = r
		err = nil
		return
	}
	err = last
	return
}

// valid emails for 1 domain
func validdomain(mxhost string, list []string, proxylist ...string) (valid []*EmailScore, err error) {

	from := "no-reply@apple.com"

	c, err := smtpDial(mxhost, proxylist...)
	if err != nil {
		return
	}
	defer c.Close()

	p := strings.Split(from, "@")

	if err = c.Hello(p[1]); err != nil {
		return
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: c.serverName, InsecureSkipVerify: true}
		if testHookStartTLS != nil {
			testHookStartTLS(config)
		}
		if err = c.StartTLS(config); err != nil {
			return
		}
	}

	if err = c.Mail(from); err != nil {
		return
	}

	for _, addr := range list {
		er := c.Rcpt(addr)
		if er != nil {
			continue
		}
		var r EmailScore
		r.Email = addr
		r.Mass = Providers.Check(p[1])
		valid = append(valid, &r)
	}

	err = c.Quit()
	return
}

type EmailScore struct {
	Email    string
	Valid    bool
	Err      string
	Private  bool   //google
	Business bool   //gsuite
	Mass     bool   //google, gsuite,
	Provider string //google, gsuite,

}
