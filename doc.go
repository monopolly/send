// Package send signs emails with DKIM and delivers them directly to the MX servers
// of the recipient domains over SMTP (RFC 5321) with opportunistic STARTTLS.
//
// It also checks mailboxes with RCPT TO probes (ValidEmails) and caches MX servers (MX).
package send
