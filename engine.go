package send

import (
	"crypto/rsa"
	"log"
	"os"

	"github.com/monopolly/email"
	"github.com/monopolly/errors"
)

var debug bool
var logger = log.New(os.Stdout, "SEND:", log.Ldate)

const (
	crlf                = "\r\n"
	tab                 = " "
	fws                 = crlf + tab
	maxHeaderLineLength = 70
	timeFormatRFC2822   = "Mon, 02 Jan 2006 15:04:05 -0700 (GMT-00:00)"
	mxbucket            = "domain"
)

func New(domain, helo, volume string, mx *MX, private, public, dkim []byte) (a *Engine) {
	a = new(Engine)
	a.domain = domain
	a.volume = volume
	a.dns.selector = "dkim"
	a.dns.spf = ""
	a.dns.dkim = dkim
	a.keys.private = private
	a.keys.public = public
	a.createSigner()
	a.mx = mx
	a.helo = helo
	return
}

func NewAuto(domain, helo, volume string, mx *MX) (a *Engine) {
	a = new(Engine)
	a.domain = domain
	a.volume = volume
	a.dns.selector = "dkim"
	a.dns.spf = ""
	private, public, dkim := GenerateKeys(domain)
	a.dns.dkim = dkim
	a.keys.private = private
	a.keys.public = public
	a.createSigner()
	a.mx = mx
	a.helo = helo
	return
}

type Engine struct {
	volume string
	domain string
	helo   string
	keys   struct {
		path    string
		private []byte
		public  []byte
		signer  *rsa.PrivateKey
	}
	dns struct {
		selector string
		spf      string
		dkim     []byte
	}
	//mx     *bolt.DB
	errors func(to string, err errors.E)
	proxy  []string //ip:port
	mx     *MX
}

func (a *Engine) Proxy(servers ...string) {
	a.proxy = servers
}

func (a *Engine) IsDebug() bool {
	return debug
}

func (a *Engine) Debug(log ...*log.Logger) {
	debug = true
	if log != nil {
		logger = log[0]
	}
}

func logs(v ...any) {

	if !debug {
		return
	}

	logger.Println(v...)
}

func (a *Engine) Send(r *email.Email) (err errors.E) {

	logs("send", r)

	b, err := build(r, a.domain, a.dns.selector, a.keys.signer)
	if err != nil {
		logs(err)
		return
	}
	return send(r.From.Address, r.To.Address, b, a.mx, a.helo)
}

func (a *Engine) CustomSend(r *email.Email, domain, helo string, private []byte, selectorKey ...string) (err errors.E) {

	logs("send", r)
	sign := a.CustomSigner(private)
	if sign == nil {
		err = errors.Invalid("private key")
		return
	}

	selector := "dkim"
	if selectorKey != nil {
		selector = selectorKey[0]
	}

	b, err := build(r, domain, selector, sign)
	if err != nil {
		logs(err)
		return
	}
	return send(r.From.Address, r.To.Address, b, a.mx, helo)
}

func (a *Engine) CustomSendSign(r *email.Email, domain, helo string, sign *rsa.PrivateKey, selectorKey ...string) (err errors.E) {

	logs("send", r)

	selector := "dkim"
	if selectorKey != nil {
		selector = selectorKey[0]
	}

	b, err := build(r, domain, selector, sign)
	if err != nil {
		logs(err)
		return
	}
	return send(r.From.Address, r.To.Address, b, a.mx, helo)
}
