package send

import "github.com/monopolly/send/mx"

// MX caches mail servers of recipient domains, see package mx.
type MX = mx.MX

// NewMX creates an MX cache persisted to filename, see mx.New.
func NewMX(filename string) *MX {
	return mx.New(filename)
}
