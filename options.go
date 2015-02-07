package dhcpv6

import (
	"encoding"
	"encoding/binary"
	"io"
	"net"
)

const (
	//Options
	OptionCodeClientId     uint16 = 1
	OptionCodeServerId     uint16 = 2
	OptionCodeIaNa         uint16 = 3
	OptionCodeIaTa         uint16 = 4
	OptionCodeIaAddr       uint16 = 5
	OptionCodeOro          uint16 = 6
	OptionCodePreference   uint16 = 7
	OptionCodeElapsedTime  uint16 = 8
	OptionCodeRelayMsg     uint16 = 9
	OptionCodeAuth         uint16 = 11
	OptionCodeUnicast      uint16 = 12
	OptionCodeStatusCode   uint16 = 13
	OptionCodeRapidCommit  uint16 = 14
	OptionCodeUserClass    uint16 = 15
	OptionCodeVendorClass  uint16 = 16
	OptionCodeVendorOpts   uint16 = 17
	OptionCodeInterfaceId  uint16 = 18
	OptionCodeReconfMsg    uint16 = 19
	OptionCodeReconfAccept uint16 = 20
)

type Option interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Code() uint16
}

func UnmarshalBinaryOption(data []byte) (option Option, err error) {
	switch binary.BigEndian.Uint16(data) {
	case OptionCodeClientId:
		option = new(ClientIdOption)
	case OptionCodeServerId:
		option = new(ServerIdOption)
	}
	if option != nil {
		err = option.UnmarshalBinary(data)
	} else {
		err = ErrInvalidType
	}
	return
}

// Client Identifier Option
type ClientIdOption struct {
	Duid Duid
}

func (o *ClientIdOption) Code() uint16 {
	return OptionCodeClientId
}
func (o *ClientIdOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4, 134) //maximum length of a DUID is 128+2
	binary.BigEndian.PutUint16(data, OptionClientId)
	duidData, err := o.Duid.MarshalBinary()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(data[2:], len(duidData))
	data = append(data, duidData...)
	return data, nil
}
func (o *ClientIdOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return io.ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeClientId {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < olen+4 {
		return io.ErrUnexpectedEOF
	}
	duid, err := UnmarshalBinaryDuid(data[4 : olen+4])
	if err != nil {
		return err
	}
	o.Duid = duid
	data = data[olen+4:]
	return nil
}

// Server Identifier Option
type ServerIdOption struct {
	Duid Duid
}

func (o *ServerIdOption) Code() uint16 {
	return OptionCodeServerId
}
func (o *ServerIdOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4, 134) //maximum length of a DUID is 128+2
	binary.BigEndian.PutUint16(data, OptionCodeServerId)
	duidData, err := o.Duid.MarshalBinary()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(data[2:], len(duidData))
	data = append(data, duidData...)
	return data, nil
}
func (o *ServerIdOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return io.ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeServerId {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < olen+4 {
		return io.ErrUnexpectedEOF
	}
	duid, err := UnmarshalBinaryDuid(data[4 : olen+4])
	if err != nil {
		return err
	}
	o.Duid = duid
	data = data[olen+4:]
	return nil
}

// Identity Association for Non-temporary Addresses Option
type IaNaOption struct {
	IAID        [4]byte
	T1          uint32
	T2          uint32
	IaNaOptions []Option
}

func (o *IaNaOption) Code() uint16 {
	return OptionCodeIaNa
}
func (o *IaNaOption) MarshalBinary() ([]byte, error) {
	var data []byte
	if len(o.IaNaOptions) == 0 {
		data = make([]byte, 16)
	} else {
		data = make([]byte, 16, 65539) //65535+4
	}
	binary.BigEndian.PutUint16(data, OptionCodeIaNa)
	copy(data[4:], o.IAID[:])
	binary.BigEndian.PutUint32(data[8:], o.T1)
	binary.BigEndian.PutUint32(data[12:], o.T1)
	for i := range o.IaNaOptions {
		optionData, err := o.IaNaOptions[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(data)+len(optionData) > cap(data) {
			return ErrOutOfRange
		}
		data = append(data, optionData...)
	}
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
	return data, nil
}
func (o *IaNaOption) UnmarshalBinary(data []byte) error {
	if len(data) < 16 {
		return io.ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeIaNa {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < olen+4 {
		return io.ErrUnexpectedEOF
	}

	copy(o.IAID[:], data[4:8])
	o.T1 = binary.BigEndian.Uint32(data[8:])
	o.T2 = binary.BigEndian.Uint32(data[12:])
	if olen == 12 {
		o.IaNaOptions = make([]Option)
	} else {
		//TODO: better more efficient way?
		o.IaNaOptions = make([]Option, 0, 10)
	}

	optionData := data[16 : olen+4] // +16 for the offset, -12 for the parsed values = option-len +4
	for len(optionData) != 0 {
		option, err := UnmarshalBinaryOption(optionData)
		if err != nil {
			return err
		}
		o.IaNaOptions = append(o.IaNaOptions, option)
	}
	data = data[olen+4:]
	return nil
}

// Identity Association for Temporary Addresses Option
type IaTaOption struct {
	IAID        [4]byte
	IaTaOptions []Option
}

func (o *IaTaOption) Code() uint16 {
	return OptionCodeIaTa
}
func (o *IaTaOption) MarshalBinary() ([]byte, error) {
	var data []byte
	if len(o.IaTaOptions) == 0 {
		data = make([]byte, 8)
	} else {
		data = make([]byte, 8, 65539) //65535 + 4
	}
	binary.BigEndian.PutUint16(data, OptionCodeIaTa)
	copy(data[4:], o.IAID[:])
	for i := range o.IaTaOptions {
		optionData, err := o.IaTaOptions[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(data)+len(optionData) > cap(data) {
			return ErrOutOfRange
		}
		data = append(data, optionData...)
	}
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
	return data, nil
}
func (o *IaTaOption) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return io.ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeIaTa {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < olen+4 {
		return io.ErrUnexpectedEOF
	}
	copy(o.IAID[:], data[4:8])

	if olen == 8 {
		o.IaTaOptions = make([]Option)
	} else {
		//TODO: better more efficient way?
		o.IaTaOptions = make([]Option, 0, 10)
	}

	optionData := data[8 : olen+4] // +8 for the offset, -4 for the parsed values = option-len +4
	for len(optionData) != 0 {
		option, err := UnmarshalBinaryOption(optionData)
		if err != nil {
			return err
		}
		o.IaTaOptions = append(o.IaTaOptions, option)
	}
	data = data[olen+4:]
	return nil
}

// IA Address Option
type IaAddrOption struct {
	Ipv6Address       net.IP
	PreferredLifetime uint32
	ValidLifetime     uint32
	IAddrOptions      []Option
}

func (o *IaAddrOption) Code() uint16 {
	return OptionCodeIaAddr
}
func (o *IaAddrOption) MarshalBinary() ([]byte, error) {
	var data []byte
	if len(o.IAddrOptions) == 0 {
		data = make([]byte, 28)
	} else {
		data = make([]byte, 28, 63359) //65535+4
	}
	binary.BigEndian.PutUint16(data, OptionCodeIaAddr)
	if len(o.Ipv6Address) != 16 {
		return nil, ErrInvalidIpv6Address
	}
	copy(data[4:], o.Ipv6Address)
	binary.BigEndian.PutUint32(data[20:], o.PreferredLifetime)
	binary.BigEndian.PutUint32(data[24:], o.ValidLifetime)
	for i := range o.IAddrOptions {
		optionData, err := o.IAddrOptions[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(data)+len(optionData) > cap(data) {
			return ErrOutOfRange
		}
		data = append(data, optionData...)
	}
	binary.BigEndian.PutUint16(data[2:], len(data)-4)
	return data, nil
}
func (o *IaAddrOption) UnmarshalBinary(data []byte) error {
	if len(data) < 28 {
		return io.ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeIaAddr {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < olen+4 {
		return io.ErrUnexpectedEOF
	}
	o.Ipv6Address = net.IP(data[4:20])
	o.PreferredLifetime = binary.BigEndian.Uint32(data[20:])
	o.ValidLifetime = binary.BigEndian.Uint32(data[24:])
	if len(data) == 28 {
		o.IAddrOptions = make([]Option)
	} else {
		//TODO: better way to guess capacity?
		o.IAddrOptions = make([]Option, 0, 10)
	}
	optionData := data[28 : olen+4]
	for len(optionData) != 0 {
		option, err := UnmarshalBinaryOption(optionData)
		if err != nil {
			return err
		}
		o.IAddrOptions = append(o.IAddrOptions, option)
	}
	data = data[olen+4:]
	return nil
}
