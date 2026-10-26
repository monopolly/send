// Package send signs emails with DKIM and delivers them directly to the MX servers
// of the recipient domains over SMTP (RFC 5321) with opportunistic STARTTLS.
//
// Subpackages:
//
//	client  one SMTP session: Deliver and Probe
//	keys    DKIM key generation and parsing
//	mx      MX servers cache
//	score   mailbox checks with RCPT TO probes (EmailScore)
//
// The aliases in this package (MX, EmailScore, ValidEmails, GenerateKeys, ...) are kept for compatibility.
package send
