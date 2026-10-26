package send

import (
	stderrors "errors"
	"net/textproto"

	"github.com/monopolly/errors"
)

// FieldSMTP is the errors.E field with the SMTP reply code (550, 421, ...), if the server answered.
const FieldSMTP = "smtp"

// ErrorHandler sets a callback called for every recipient the message was not delivered to.
func (a *Engine) ErrorHandler(h func(to string, err errors.E)) {
	a.onError = h
}

// getSmtpErrorCode converts a delivery error:
// 4xx -> Limit, 5xx -> Invalid, other replies -> Email, network errors -> Connection.
func getSmtpErrorCode(er error) (err errors.E) {
	var tp *textproto.Error
	if !stderrors.As(er, &tp) {
		return errors.Connection(er.Error())
	}

	switch tp.Code / 100 {
	case 4:
		err = errors.Limit(er.Error())
	case 5:
		err = errors.Invalid(er.Error())
	default:
		err = errors.Email(er.Error())
		err.Code(tp.Code)
	}
	err.Set(FieldSMTP, tp.Code)
	return
}

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
