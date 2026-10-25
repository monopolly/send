package send

import (
	"bytes"
	"crypto"
	"log"
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

	/* validation */
	err = r.Valid()
	if err != nil {
		return
	}

	build := r.Render()

	/* create dkim signer */
	options := &dkim.SignOptions{
		Domain:     domain,
		Selector:   selector,
		Signer:     signer,
		Expiration: time.Now().AddDate(0, 1, 0),
	}

	/* dkim sign */
	var signed bytes.Buffer
	er := dkim.Sign(&signed, &build, options)
	if er != nil {
		log.Println("for sign")
		log.Println(build.String())
		err = errors.DKIM(er)
		return
	}

	body = signed.Bytes()

	//fmt.Println(dkim.Verify(&signed))

	// log.Println("--------- signed ---------")
	// log.Println(string(body))
	return
}
