package dhcpv6

import (
	"encoding/binary"
	"net"
)

type DhcpMessageType byte

const (
	//message types
	TypeSolicit            DhcpMessageType = 1
	TypeAdvertise          DhcpMessageType = 2
	TypeRequest            DhcpMessageType = 3
	TypeConfirm            DhcpMessageType = 4
	TypeRenew              DhcpMessageType = 5
	TypeRebind             DhcpMessageType = 6
	TypeReply              DhcpMessageType = 7
	TypeRelease            DhcpMessageType = 8
	TypeDecline            DhcpMessageType = 9
	TypeReconfigure        DhcpMessageType = 10
	TypeInformationRequest DhcpMessageType = 11
	TypeRelayForward       DhcpMessageType = 12
	TypeRelayReply         DhcpMessageType = 13
)

// Client/Server Message Format
type DhcpMessage struct {
	MsgType       DhcpMessageType
	TransactionId [3]byte
	Options       []Option
}

func (d *DhcpMessage) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4, 32768)
	data[0] = byte(d.MsgType)
	copy(data[1:], d.TransactionId[:])
	for _, v := range d.Options {
		optionData, err := v.MarshalBinary()
		if err != nil {
			return nil, err
		}
		data = append(data, optionData...)
	}
	return data, nil
}
func (d *DhcpMessage) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	d.MsgType = DhcpMessageType(data[0])
	d.Options = make([]Option, 0, 10)
	copy(d.TransactionId[:], data[1:4])
	data = data[4:]
	for len(data) > 0 {
		if len(data) < 4 {
			return ErrUnexpectedEOF
		}
		optSize := binary.BigEndian.Uint16(data[2:])
		option, err := UnmarshalBinaryOption(data)
		if err != nil {
			return err
		}
		d.Options = append(d.Options, option)
		data = data[optSize+4:]
	}
	return nil
}

// Relay Agent/Server Message Format
type DhcpRelayMessage struct {
	MsgType     DhcpMessageType
	HopCount    byte
	LinkAddress net.IP
	PeerAddress net.IP
	Options     []Option
}

func (d *DhcpRelayMessage) MarshalBinary() ([]byte, error) {
	if len(d.LinkAddress) != 16 {
		return nil, ErrInvalidIpv6Address
	}
	if len(d.PeerAddress) != 16 {
		return nil, ErrInvalidIpv6Address
	}
	data := make([]byte, 34, 32768)
	data[0] = byte(d.MsgType)
	data[1] = d.HopCount
	copy(data[2:], d.LinkAddress)
	copy(data[18:], d.PeerAddress)
	for _, v := range d.Options {
		optionData, err := v.MarshalBinary()
		if err != nil {
			return nil, err
		}
		data = append(data, optionData...)
	}
	return data, nil
}
func (d *DhcpRelayMessage) UnmarshalBinary(data []byte) error {
	if len(data) < 34 {
		return ErrUnexpectedEOF
	}
	d.MsgType = DhcpMessageType(data[0])
	d.HopCount = data[1]
	d.LinkAddress = data[2:18]
	d.PeerAddress = data[18:34]
	data = data[34:]
	d.Options = nil
	for len(data) > 0 {
		if len(data) < 4 {
			return ErrUnexpectedEOF
		}
		optSize := binary.BigEndian.Uint16(data[2:])
		option, err := UnmarshalBinaryOption(data)
		if err != nil {
			return err
		}
		d.Options = append(d.Options, option)
		data = data[optSize+4:]
	}
	return nil
}
