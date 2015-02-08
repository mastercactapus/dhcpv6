package dhcpv6

import (
	"errors"
	"io"
)

var ErrInvalidType = errors.New("Invalid type for message")
var ErrInvalidIpv6Address = errors.New("Invalid IPv6 address")
var ErrUnexpectedEOF = io.ErrUnexpectedEOF
var ErrWontFit = errors.New("The payload would exceed the size limit")
var ErrInvalidData = errors.New("Unexpected or invalid value was encountered")
var ErrDuidTooLong = errors.New("Duid exceeds maximum length of 128 octets")
var ErrNotImplemented = errors.New("Not implemented yet")

const (
	//addresses
	AddressAllDhcpServers               = "FF05::1:3"
	AddressAllDhcpRelayAgentsAndServers = "FF02::1:2"

	//Ports
	PortClient = 546
	PortServer = 547

	//Status Codes
	Success = iota
	UnspecFail
	NoAddrsAvail
	NoBinding
	NotOnLink
	UseMulticast

	Infinity = 0xffffffff
)
