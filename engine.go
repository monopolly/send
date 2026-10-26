package send

import (
	"context"
	"crypto"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/monopolly/email"
	"github.com/monopolly/errors"

	"github.com/monopolly/send/client"
)

const defaultSelector = "dkim"

// Settings configures an Engine.
type Settings struct {
	Domain    string                        // DKIM signing domain (d=)
	Helo      string                        // EHLO name, mail.domain.com; domain of From if empty
	Selector  string                        // DKIM selector, "dkim" if empty
	Private   []byte                        // PEM private key: PKCS#1 or PKCS#8, RSA or Ed25519
	Public    []byte                        // PEM public key
	DKIM      string                        // DNS TXT value of the DKIM record, shown by Help
	Signer    crypto.Signer                 // used instead of Private if set
	MX        *MX                           // MX cache; Volume/mx.json (or memory) if nil
	Volume    string                        // directory for mx.json
	Proxy     []string                      // SOCKS5 proxies ip:port
	VerifyTLS bool                          // verify server certificates; opportunistic TLS if false
	Timeout   time.Duration                 // dial and per command timeout, 2m if zero
	Logger    *slog.Logger                  // debug logs, none if nil
	Err       func(to string, err errors.E) // called for every recipient not delivered
}

// Engine signs and delivers emails directly to recipient MX servers.
// Configure it before use; Send is safe for concurrent use.
type Engine struct {
	domain    string
	helo      string
	selector  string
	public    []byte
	dkim      []byte
	signer    crypto.Signer
	mx        *MX
	proxy     []string //ip:port
	verifyTLS bool
	timeout   time.Duration
	log       *slog.Logger
	onError   func(to string, err errors.E)
	initErr   errors.E
}

// NewEngine creates an Engine; it fails if the private key is invalid.
func NewEngine(s Settings) (a *Engine, err errors.E) {
	a = newEngine(s)
	if a.initErr != nil {
		return nil, a.initErr
	}
	return a, nil
}

// New creates an Engine from PEM keys. If the private key is invalid, Send returns the error.
func New(domain, helo, volume string, cache *MX, private, public, dkim []byte) (a *Engine) {
	return newEngine(Settings{
		Domain:  domain,
		Helo:    helo,
		Volume:  volume,
		MX:      cache,
		Private: private,
		Public:  public,
		DKIM:    string(dkim),
	})
}

// NewAuto creates an Engine with keys derived from the domain name (see GenerateKeys).
func NewAuto(domain, helo, volume string, cache *MX) (a *Engine) {
	private, public, dkim := GenerateKeys(domain)
	return New(domain, helo, volume, cache, private, public, dkim)
}

func newEngine(s Settings) (a *Engine) {
	a = &Engine{
		domain:    s.Domain,
		helo:      s.Helo,
		selector:  s.Selector,
		public:    s.Public,
		dkim:      []byte(s.DKIM),
		signer:    s.Signer,
		mx:        s.MX,
		proxy:     s.Proxy,
		verifyTLS: s.VerifyTLS,
		timeout:   s.Timeout,
		log:       s.Logger,
		onError:   s.Err,
	}
	if a.selector == "" {
		a.selector = defaultSelector
	}
	if a.log == nil {
		a.log = discard
	}
	if a.mx == nil {
		filename := ""
		if s.Volume != "" {
			filename = filepath.Join(s.Volume, "mx.json")
		}
		a.mx = NewMX(filename)
	}
	if a.signer == nil {
		signer, err := ParseSigner(s.Private)
		if err != nil {
			a.initErr = errors.Invalid("private key: " + err.Error())
		}
		a.signer = signer
	}
	return
}

// Proxy sets SOCKS5 proxies (ip:port) tried in order for every connection.
func (a *Engine) Proxy(servers ...string) {
	a.proxy = servers
}

// IsDebug reports whether debug logs are enabled.
func (a *Engine) IsDebug() bool {
	return a.log.Enabled(context.Background(), slog.LevelDebug)
}

// Debug enables debug logs to stdout or to the writer of the given logger.
func (a *Engine) Debug(l ...*log.Logger) {
	w := io.Writer(os.Stdout)
	if l != nil && l[0] != nil {
		w = l[0].Writer()
	}
	a.log = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})).With("pkg", "send")
}

// SetLogger sets the logger; nil disables logs.
func (a *Engine) SetLogger(l *slog.Logger) {
	if l == nil {
		l = discard
	}
	a.log = l
}

// Send signs r with the engine key and delivers it to all To, CC and BCC recipients.
// Failed recipients go to the ErrorHandler; the first one's error is returned.
func (a *Engine) Send(r *email.Email) (err errors.E) {
	return a.SendContext(context.Background(), r)
}

// SendContext is Send with a context for cancellation and deadline.
func (a *Engine) SendContext(ctx context.Context, r *email.Email) (err errors.E) {
	return a.send(ctx, r, a.domain, a.helo, a.selector, a.signer)
}

// CustomSend signs r for another domain with a PEM private key.
func (a *Engine) CustomSend(r *email.Email, domain, helo string, private []byte, selectorKey ...string) (err errors.E) {
	sign, er := ParseSigner(private)
	if er != nil {
		return errors.Invalid("private key: " + er.Error())
	}
	return a.CustomSendSign(r, domain, helo, sign, selectorKey...)
}

// CustomSendSign signs r for another domain with signer (*rsa.PrivateKey, ed25519.PrivateKey, ...).
func (a *Engine) CustomSendSign(r *email.Email, domain, helo string, sign crypto.Signer, selectorKey ...string) (err errors.E) {
	selector := defaultSelector
	if selectorKey != nil {
		selector = selectorKey[0]
	}
	return a.send(context.Background(), r, domain, helo, selector, sign)
}

func (a *Engine) send(ctx context.Context, r *email.Email, domain, helo, selector string, signer crypto.Signer) (err errors.E) {
	if a.initErr != nil {
		return a.initErr
	}

	b, err := build(r, domain, selector, signer)
	if err != nil {
		a.log.Debug("build", "err", err)
		return
	}

	rcpts := recipients(r)
	a.log.Debug("send", "from", r.From.Address, "rcpts", rcpts)
	failed := send(ctx, r.From.Address, rcpts, b, a.mx, a.options(helo))
	return firstError(rcpts, failed, a.onError)
}

func (a *Engine) options(helo string) sendOptions {
	return sendOptions{
		Options: client.Options{
			Helo:      helo,
			Proxies:   a.proxy,
			VerifyTLS: a.verifyTLS,
			Timeout:   a.timeout,
		},
		log: a.log,
	}
}
