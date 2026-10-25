package send

import (
	"crypto"
	"fmt"

	"github.com/monopolly/email"
	"github.com/monopolly/errors"
)

func Send(r *email.Email, domain, selector, helo string, signer crypto.Signer, mx *MX) (err errors.E) {
	b, err := build(r, domain, selector, signer)
	if err != nil {
		return
	}
	return send(r.From.Address, r.To.Address, b, mx, helo)
}

// helo mail.domain.com
func send(from, to string, body []byte, mx *MX, helo string) (err errors.E) {

	domain := domainonly(to)
	logs("domain", domain)

	//mx
	servers, port := mx.Get(domain)
	var er error
	if servers == nil {
		logs("no mx servers")
		return errors.Connection("mx servers not found")
	}

	//port
	if port == 0 {
		port = 25
	}

	//tls
	if port == 587 {
		return sendTLS(from, to, body, servers)
	}

	logs("port", port)

	//try
	logs("sending...")
	for _, x := range servers {
		host := fmt.Sprintf("%s:%d", x, port)
		// log.Println("sendmail", "try", host)
		logs("sendmail", "try", host)
		er = smtpSendMail(host, nil, from, []string{to}, helo, body)
		switch er {
		case nil:
			logs("sendmail", "success")
			mx.Set(domain, []string{x}, port)
			return
		default:
			// log.Println("sendmail", "error", er)
			logs("sendmail", "error")
		}
	}

	switch er {
	case nil:
		return errors.Email("unknown")
	default:
		return getSmtpErrorCode(er)
	}
}

func sendTLS(from, to string, body []byte, servers []string) (err errors.E) {

	var er error
	for _, x := range servers {
		host := fmt.Sprintf("%s:%d", x, 587)
		logs("sendmail", "try", host)
		er = smtpSendMailTLS(host, nil, from, []string{to}, body)
		switch er {
		case nil:
			logs("sendmail", "success")
			return
		default:
			logs("sendmail", "error", er)
		}
	}

	switch er {
	case nil:
		return errors.Email("unknown")
	default:
		return getSmtpErrorCode(er)
	}
}
