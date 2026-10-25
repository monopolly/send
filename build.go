package send

import (
	"bytes"
	"crypto"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/monopolly/email"
	"github.com/monopolly/errors"
)

/* Purchase receipt messages: receipt@your-company.net
Promotional messages: deals@your-company.net
Account notification messages: alerts@your-company.net */

/* build create and sign email */
func build(r *email.Email, domain, selector string, signer crypto.Signer) (body []byte, err errors.E) {
	if r == nil {
		return nil, errors.Empty("email")
	}

	/* validation */
	err = r.Valid()
	if err != nil {
		return
	}
	if signer == nil {
		return nil, errors.DKIM("no signer")
	}
	if r.Date == nil {
		now := time.Now()
		r.Date = &now
	}

	build := r.Render()
	if build.Len() == 0 {
		return nil, errors.Email("render failed")
	}

	/* create dkim signer */
	options := &dkim.SignOptions{
		Domain:     domain,
		Selector:   selector,
		Signer:     signer,
		Expiration: time.Now().AddDate(0, 1, 0),
	}

	/* dkim sign */
	var signed bytes.Buffer
	if er := dkim.Sign(&signed, &build, options); er != nil {
		return nil, errors.DKIM(er)
	}
	return signed.Bytes(), nil
}
