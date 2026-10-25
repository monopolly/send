package send

import (
	"strconv"

	"github.com/monopolly/errors"
)

func (a *Engine) ErrorHandler(h func(to string, err errors.E)) {
	a.errors = h
}

func getSmtpErrorCode(er error) (err errors.E) {
	e := er.Error()

	code, _ := strconv.Atoi(e[:3])

	switch e[0:1] {
	case "1":
		err = errors.Connection(e)
		if code == 0 {
			err.Code(100)
		}
		return
	case "4":
		err = errors.Limit(e)
		if code == 0 {
			err.Code(400)
		}
		return
	case "5":
		err = errors.Invalid(e)
		if code == 0 {
			err.Code(500)
		}
		return
	default:
		err = errors.Email(e)
		err.Code(code)
		return
	}
}

/* for _, x := range []int{220, 221, 250, 334, 354, 421, 450, 451, 452, 455, 500, 501, 502, 503, 541, 550, 551, 552, 553, 554} {
	if strings.HasPrefix(er, fmt.Sprint(x)) {
		return x
	}
} */

/*
220 – The SMTP server is ready
221 – The SMTP server is closing its transmission channel
250 – The requested action taken and completed (Good news!)
334 – Provide SMTP authentication credentials.
354 – Waiting for the contents of the message
421 – The service is unavailable, try again later
450 – The requested action was not taken because the user’s mailbox was unavailable
451 – The message was not sent due to a server error
452 – The command was aborted because there isn’t enough server storage
455 – The server cannot deal with the command at this time
500 – The server could not recognize the command due to a syntax error
501 – A syntax error was encountered in command parameters or arguments
502 – This command is not implemented
503 – The server has encountered a bad sequence of commands
541 – The message was rejected by the recipient address
550 – The requested command failed because the user’s mailbox was unavailable or the recipient server rejected the message due to high probability of spam
551 – The intended recipient mailbox was not available on the recipient server
552 – The message was not sent because the recipient mailbox does not have adequate storage.
553 – The command was aborted because the mailbox name does not exist.
554 – The transaction failed. No further details are given
501 5.7.0 – Authentication failed.  Username or password is invalid. */
