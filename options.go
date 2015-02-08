package dhcpv6

import (
	"encoding"
	"encoding/binary"
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
	binary.BigEndian.PutUint16(data, OptionCodeClientId)
	duidData, err := o.Duid.MarshalBinary()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(data[2:], uint16(len(duidData)))
	data = append(data, duidData...)
	return data, nil
}
func (o *ClientIdOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeClientId {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
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
	binary.BigEndian.PutUint16(data[2:], uint16(len(duidData)))
	data = append(data, duidData...)
	return data, nil
}
func (o *ServerIdOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeServerId {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
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
			return nil, ErrWontFit
		}
		data = append(data, optionData...)
	}
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
	return data, nil
}
func (o *IaNaOption) UnmarshalBinary(data []byte) error {
	if len(data) < 16 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeIaNa {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}

	copy(o.IAID[:], data[4:8])
	o.T1 = binary.BigEndian.Uint32(data[8:])
	o.T2 = binary.BigEndian.Uint32(data[12:])
	if olen == 12 {
		o.IaNaOptions = make([]Option, 0)
	} else {
		//TODO: better more efficient way?
		o.IaNaOptions = make([]Option, 0, 10)
	}

	optionData := data[16 : olen+4] // +16 for the offset, -12 for the parsed values = option-len +4
	for len(optionData) != 0 {
		if len(optionData) < 4 {
			return ErrUnexpectedEOF
		}
		nextSize := binary.BigEndian.Uint16(optionData[2:])
		option, err := UnmarshalBinaryOption(optionData[:nextSize+4])
		if err != nil {
			return err
		}
		o.IaNaOptions = append(o.IaNaOptions, option)
		optionData = optionData[nextSize+4:]
	}
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
			return nil, ErrWontFit
		}
		data = append(data, optionData...)
	}
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
	return data, nil
}
func (o *IaTaOption) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeIaTa {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	copy(o.IAID[:], data[4:8])

	if olen == 8 {
		o.IaTaOptions = make([]Option, 0)
	} else {
		//TODO: better more efficient way?
		o.IaTaOptions = make([]Option, 0, 10)
	}

	optionData := data[8 : olen+4] // +8 for the offset, -4 for the parsed values = option-len +4
	for len(optionData) != 0 {
		if len(optionData) < 4 {
			return ErrUnexpectedEOF
		}
		nextSize := binary.BigEndian.Uint16(optionData[2:])
		option, err := UnmarshalBinaryOption(optionData[:nextSize+4])
		if err != nil {
			return err
		}
		o.IaTaOptions = append(o.IaTaOptions, option)
		optionData = optionData[nextSize+4:]
	}
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
			return nil, ErrWontFit
		}
		data = append(data, optionData...)
	}
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
	return data, nil
}
func (o *IaAddrOption) UnmarshalBinary(data []byte) error {
	if len(data) < 28 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeIaAddr {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.Ipv6Address = net.IP(data[4:20])
	o.PreferredLifetime = binary.BigEndian.Uint32(data[20:])
	o.ValidLifetime = binary.BigEndian.Uint32(data[24:])
	if len(data) == 28 {
		o.IAddrOptions = make([]Option, 0)
	} else {
		//TODO: better way to guess capacity?
		o.IAddrOptions = make([]Option, 0, 10)
	}
	optionData := data[28 : olen+4]
	for len(optionData) != 0 {
		if len(optionData) < 4 {
			return ErrUnexpectedEOF
		}
		nextSize := binary.BigEndian.Uint16(optionData[2:])
		option, err := UnmarshalBinaryOption(optionData[:nextSize+4])
		if err != nil {
			return err
		}
		o.IAddrOptions = append(o.IAddrOptions, option)
		optionData = optionData[nextSize+4:]
	}
	return nil
}

// Option Request Option
type OroOption struct {
	RequestedOptionCodes []uint16
}

func (o *OroOption) Code() uint16 {
	return OptionCodeOro
}
func (o *OroOption) MarshalBinary() ([]byte, error) {
	if len(o.RequestedOptionCodes) > 32767 {
		return nil, ErrWontFit
	}
	data := make([]byte, 4+len(o.RequestedOptionCodes)*2)
	binary.BigEndian.PutUint16(data, OptionCodeOro)
	binary.BigEndian.PutUint16(data[2:], uint16(len(o.RequestedOptionCodes)*2))
	for i := range o.RequestedOptionCodes {
		binary.BigEndian.PutUint16(data[4+i*2:], o.RequestedOptionCodes[i])
	}
	return data, nil
}
func (o *OroOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeOro {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.RequestedOptionCodes = make([]uint16, olen/2)
	for i := range o.RequestedOptionCodes {
		o.RequestedOptionCodes[i] = binary.BigEndian.Uint16(data[4+i*2:])
	}
	return nil
}

// Preference Option
type PreferenceOption struct {
	PreferenceValue byte
}

func (o *PreferenceOption) Code() uint16 {
	return OptionCodePreference
}
func (o *PreferenceOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 5)
	binary.BigEndian.PutUint16(data, OptionCodePreference)
	binary.BigEndian.PutUint16(data[2:], 1)
	data[4] = o.PreferenceValue
	return data, nil
}
func (o *PreferenceOption) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodePreference {
		return ErrInvalidType
	}
	if binary.BigEndian.Uint16(data[2:]) != 1 {
		return ErrInvalidData
	}
	o.PreferenceValue = data[4]
	return nil
}

// Elapsed Time Option
type ElapsedTimeOption struct {
	ElapsedTime uint16
}

func (o *ElapsedTimeOption) Code() uint16 {
	return OptionCodeElapsedTime
}
func (o *ElapsedTimeOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 6)
	binary.BigEndian.PutUint16(data, OptionCodeElapsedTime)
	binary.BigEndian.PutUint16(data[2:], 2)
	binary.BigEndian.PutUint16(data[4:], o.ElapsedTime)
	return data, nil
}
func (o *ElapsedTimeOption) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeElapsedTime {
		return ErrInvalidType
	}
	if binary.BigEndian.Uint16(data[2:]) != 2 {
		return ErrInvalidData
	}
	o.ElapsedTime = binary.BigEndian.Uint16(data[4:])
	return nil
}

// Relay Message Option
// TODO: this
type RelayMsgOption struct {
}

func (o *RelayMsgOption) Code() uint16 {
	return OptionCodeRelayMsg
}
func (o *RelayMsgOption) MarshalBinary() ([]byte, error) {
	return nil, ErrNotImplemented
}
func (o *RelayMsgOption) UnmarshalBinary(data []byte) error {
	return ErrNotImplemented
}

// Authentication Option
type AuthOption struct {
	Protocol                  byte
	Algorithm                 byte
	RDM                       byte
	ReplayDetection           [8]byte
	AuthenticationInformation []byte
}

func (o *AuthOption) Code() uint16 {
	return OptionCodeAuth
}
func (o *AuthOption) MarshalBinary() ([]byte, error) {
	if len(o.AuthenticationInformation) > 65524 { //65535-11
		return nil, ErrWontFit
	}
	data := make([]byte, 15+len(o.AuthenticationInformation))
	binary.BigEndian.PutUint16(data, OptionCodeAuth)
	binary.BigEndian.PutUint16(data[2:], uint16(11+len(o.AuthenticationInformation)))
	data[4] = o.Protocol
	data[5] = o.Algorithm
	data[6] = o.RDM
	copy(data[7:], o.ReplayDetection[:])
	copy(data[15:], o.AuthenticationInformation)
	return data, nil
}
func (o *AuthOption) UnmarshalBinary(data []byte) error {
	if len(data) < 15 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeAuth {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.Protocol = data[4]
	o.Algorithm = data[5]
	o.RDM = data[6]
	copy(o.ReplayDetection[:], data[7:15])
	o.AuthenticationInformation = data[15 : olen+4]
	return nil
}

// Server Unicast Option
type UnicastOption struct {
	ServerAddress net.IP
}

func (o *UnicastOption) Code() uint16 {
	return OptionCodeUnicast
}
func (o *UnicastOption) MarshalBinary() ([]byte, error) {
	if len(o.ServerAddress) != 16 {
		return nil, ErrInvalidIpv6Address
	}
	data := make([]byte, 20)
	binary.BigEndian.PutUint16(data, OptionCodeUnicast)
	binary.BigEndian.PutUint16(data[2:], 16)
	copy(data[4:], o.ServerAddress)
	return data, nil
}
func (o *UnicastOption) UnmarshalBinary(data []byte) error {
	if len(data) < 20 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeUnicast {
		return ErrInvalidType
	}
	if binary.BigEndian.Uint16(data[2:]) != 16 {
		return ErrInvalidData
	}
	o.ServerAddress = data[4:20]
	return nil
}

// Status Code Option
type StatusCodeOption struct {
	StatusCode    byte
	StatusMessage string
}

func (o *StatusCodeOption) Code() uint16 {
	return OptionCodeStatusCode
}
func (o *StatusCodeOption) MarshalBinary() ([]byte, error) {
	msgData := []byte(o.StatusMessage)
	if len(msgData) > 65534 {
		return nil, ErrWontFit
	}
	data := make([]byte, 5+len(msgData))
	binary.BigEndian.PutUint16(data, OptionCodeStatusCode)
	binary.BigEndian.PutUint16(data[2:], uint16(len(msgData)+1))
	data[4] = o.StatusCode
	copy(data[5:], msgData)
	return data, nil
}
func (o *StatusCodeOption) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != OptionCodeStatusCode {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.StatusCode = data[4]
	o.StatusMessage = string(data[5 : olen+4])
	return nil
}
