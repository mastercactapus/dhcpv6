package dhcpv6

import (
	"errors"
	"io"
)

var ErrInvalidType = errors.New("Invalid type for message")
var ErrInvalidIpv6Address = errors.New("Invalid IPv6 address")
var ErrUnexpectedEOF = io.ErrUnexpectedEOF
var ErrTooManyOptions = errors.New("No many options set to fit into buffer")
var ErrDuidTooLong = errors.New("Duid exceeds maximum length of 128 octets")

const (
	//addresses
	AddressAllDhcpServers               = "FF05::1:3"
	AddressAllDhcpRelayAgentsAndServers = "FF02::1:2"

	//Ports
	PortClient = 546
	PortServer = 547

	//message types
	_ = iota
	TypeSolicit
	TypeAdvertise
	TypeRequest
	TypeConfirm
	TypeRenew
	TypeRebind
	TypeReply
	TypeRelease
	TypeDecline
	TypeReconfigure
	TypeInformationRequest
	TypeRelayForward
	TypeRelayReply

	//Status Codes
	Success = iota
	UnspecFail
	NoAddrsAvail
	NoBinding
	NotOnLink
	UseMulticast

	Infinity = 0xffffffff
)
