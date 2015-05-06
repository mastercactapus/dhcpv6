package dhcpv6

import (
	"encoding"
	"encoding/binary"
	"net"
)

type OptionCode uint16

const (
	//Options
	OptionCodeClientId     OptionCode = 1
	OptionCodeServerId     OptionCode = 2
	OptionCodeIaNa         OptionCode = 3
	OptionCodeIaTa         OptionCode = 4
	OptionCodeIaAddr       OptionCode = 5
	OptionCodeOro          OptionCode = 6
	OptionCodePreference   OptionCode = 7
	OptionCodeElapsedTime  OptionCode = 8
	OptionCodeRelayMsg     OptionCode = 9
	OptionCodeAuth         OptionCode = 11
	OptionCodeUnicast      OptionCode = 12
	OptionCodeStatusCode   OptionCode = 13
	OptionCodeRapidCommit  OptionCode = 14
	OptionCodeUserClass    OptionCode = 15
	OptionCodeVendorClass  OptionCode = 16
	OptionCodeVendorOpts   OptionCode = 17
	OptionCodeInterfaceId  OptionCode = 18
	OptionCodeReconfMsg    OptionCode = 19
	OptionCodeReconfAccept OptionCode = 20
	OptionCodeIaPd         OptionCode = 25
	OptionCodeIaPrefix     OptionCode = 26
	OptionCodeFQDN         OptionCode = 39
	OptionCodeNextHop      OptionCode = 242
	OptionCodeRtPrefix     OptionCode = 243
	OptionCodeMTU          OptionCode = 244
)

// DHCPv6 options are scoped by using encapsulation.  Some options apply
// generally to the client, some are specific to an IA, and some are
// specific to the addresses within an IA.
type Option interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Code() OptionCode
}

// UnmarshalBinaryOption will take the raw wire-format data and construct
// the correct structure underneath, returning the Option interface.
//
// If the option type is not defined the option will be decoded as an UnknownOption
// allowing raw access to the option code and data.
func UnmarshalBinaryOption(data []byte) (option Option, err error) {
	switch OptionCode(binary.BigEndian.Uint16(data)) {
	case OptionCodeClientId:
		option = new(ClientIdOption)
	case OptionCodeServerId:
		option = new(ServerIdOption)
	case OptionCodeIaNa:
		option = new(IaNaOption)
	case OptionCodeIaTa:
		option = new(IaTaOption)
	case OptionCodeIaAddr:
		option = new(IaAddrOption)
	case OptionCodeOro:
		option = new(OroOption)
	case OptionCodePreference:
		option = new(PreferenceOption)
	case OptionCodeElapsedTime:
		option = new(ElapsedTimeOption)
	case OptionCodeRelayMsg:
		option = new(RelayMsgOption)
	case OptionCodeAuth:
		option = new(AuthOption)
	case OptionCodeUnicast:
		option = new(UnicastOption)
	case OptionCodeStatusCode:
		option = new(StatusCodeOption)
	case OptionCodeRapidCommit:
		option = new(RapidCommitOption)
	case OptionCodeUserClass:
		option = new(UserClassOption)
	case OptionCodeVendorClass:
		option = new(VendorClassOption)
	case OptionCodeVendorOpts:
		option = new(VendorOptsOption)
	case OptionCodeInterfaceId:
		option = new(InterfaceIdOption)
	case OptionCodeReconfMsg:
		option = new(ReconfMsgOption)
	case OptionCodeReconfAccept:
		option = new(ReconfAcceptOption)
	case OptionCodeFQDN:
		option = new(FQDNOption)
	case OptionCodeNextHop:
		option = new(NextHopOption)
	case OptionCodeRtPrefix:
		option = new(RtPrefixOption)
	case OptionCodeMTU:
		option = new(MTUOption)
	default:
		option = new(UnknownOption)
	}
	err = option.UnmarshalBinary(data)
	return
}

// UnknownOption is not a defined type, it is just a placeholder for undefined
// option types.
type UnknownOption struct {
	OptionCode OptionCode
	OptionData []byte
}

func (o *UnknownOption) Code() OptionCode {
	return o.OptionCode
}
func (o *UnknownOption) MarshalBinary() ([]byte, error) {
	if len(o.OptionData) > 65535 {
		return nil, ErrWontFit
	}
	data := make([]byte, 4+len(o.OptionData))
	binary.BigEndian.PutUint16(data, uint16(o.OptionCode))
	binary.BigEndian.PutUint16(data[2:], uint16(len(o.OptionData)))
	copy(data[4:], o.OptionData)
	return data, nil
}
func (o *UnknownOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	o.OptionCode = OptionCode(binary.BigEndian.Uint16(data))
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.OptionData = data[4 : olen+4]
	return nil
}

// Client Identifier Option
// The Client Identifier option is used to carry a DUID (see https://tools.ietf.org/html/rfc3315#section-9)
// identifying a client between a client and a server.
type ClientIdOption struct {
	Duid Duid
}

func (o *ClientIdOption) Code() OptionCode {
	return OptionCodeClientId
}
func (o *ClientIdOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4, 134) //maximum length of a DUID is 128+2
	binary.BigEndian.PutUint16(data, uint16(OptionCodeClientId))
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
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeClientId) {
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
//
// The Server Identifier option is used to carry a DUID (see section 9)
// identifying a server between a client and a server.
type ServerIdOption struct {
	Duid Duid
}

func (o *ServerIdOption) Code() OptionCode {
	return OptionCodeServerId
}
func (o *ServerIdOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4, 134) //maximum length of a DUID is 128+2
	binary.BigEndian.PutUint16(data, uint16(OptionCodeServerId))
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
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeServerId) {
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

func (o *IaNaOption) Code() OptionCode {
	return OptionCodeIaNa
}
func (o *IaNaOption) MarshalBinary() ([]byte, error) {
	var data []byte
	if len(o.IaNaOptions) == 0 {
		data = make([]byte, 16)
	} else {
		data = make([]byte, 16, 65539) //65535+4
	}
	binary.BigEndian.PutUint16(data, uint16(OptionCodeIaNa))
	copy(data[4:], o.IAID[:])
	binary.BigEndian.PutUint32(data[8:], o.T1)
	binary.BigEndian.PutUint32(data[12:], o.T2)
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
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeIaNa) {
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

func (o *IaTaOption) Code() OptionCode {
	return OptionCodeIaTa
}
func (o *IaTaOption) MarshalBinary() ([]byte, error) {
	var data []byte
	if len(o.IaTaOptions) == 0 {
		data = make([]byte, 8)
	} else {
		data = make([]byte, 8, 65539) //65535 + 4
	}
	binary.BigEndian.PutUint16(data, uint16(OptionCodeIaTa))
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
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeIaTa) {
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

func (o *IaAddrOption) Code() OptionCode {
	return OptionCodeIaAddr
}
func (o *IaAddrOption) MarshalBinary() ([]byte, error) {
	var data []byte
	if len(o.IAddrOptions) == 0 {
		data = make([]byte, 28)
	} else {
		data = make([]byte, 28, 63359) //65535+4
	}
	binary.BigEndian.PutUint16(data, uint16(OptionCodeIaAddr))
	if len(o.Ipv6Address) != net.IPv6len {
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
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeIaAddr) {
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

func (o *OroOption) Code() OptionCode {
	return OptionCodeOro
}
func (o *OroOption) MarshalBinary() ([]byte, error) {
	if len(o.RequestedOptionCodes) > 32767 {
		return nil, ErrWontFit
	}
	data := make([]byte, 4+len(o.RequestedOptionCodes)*2)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeOro))
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
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeOro) {
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

func (o *PreferenceOption) Code() OptionCode {
	return OptionCodePreference
}
func (o *PreferenceOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 5)
	binary.BigEndian.PutUint16(data, uint16(OptionCodePreference))
	binary.BigEndian.PutUint16(data[2:], 1)
	data[4] = o.PreferenceValue
	return data, nil
}
func (o *PreferenceOption) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodePreference) {
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

func (o *ElapsedTimeOption) Code() OptionCode {
	return OptionCodeElapsedTime
}
func (o *ElapsedTimeOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 6)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeElapsedTime))
	binary.BigEndian.PutUint16(data[2:], 2)
	binary.BigEndian.PutUint16(data[4:], o.ElapsedTime)
	return data, nil
}
func (o *ElapsedTimeOption) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeElapsedTime) {
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
	DhcpRelayMessage DhcpRelayMessage
}

func (o *RelayMsgOption) Code() OptionCode {
	return OptionCodeRelayMsg
}
func (o *RelayMsgOption) MarshalBinary() ([]byte, error) {
	relayData, err := o.DhcpRelayMessage.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(relayData) > 65535 {
		return nil, ErrWontFit
	}
	data := make([]byte, 4+len(relayData))
	binary.BigEndian.PutUint16(data, uint16(OptionCodeRelayMsg))
	binary.BigEndian.PutUint16(data[2:], uint16(len(relayData)))
	copy(data[4:], relayData)
	return data, nil
}
func (o *RelayMsgOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeRelayMsg) {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	err := o.DhcpRelayMessage.UnmarshalBinary(data[4 : olen+4])
	if err != nil {
		return err
	}
	return nil
}

// Authentication Option
type AuthOption struct {
	Protocol                  byte
	Algorithm                 byte
	RDM                       byte
	ReplayDetection           [8]byte
	AuthenticationInformation []byte
}

func (o *AuthOption) Code() OptionCode {
	return OptionCodeAuth
}
func (o *AuthOption) MarshalBinary() ([]byte, error) {
	if len(o.AuthenticationInformation) > 65524 { //65535-11
		return nil, ErrWontFit
	}
	data := make([]byte, 15+len(o.AuthenticationInformation))
	binary.BigEndian.PutUint16(data, uint16(OptionCodeAuth))
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
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeAuth) {
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

func (o *UnicastOption) Code() OptionCode {
	return OptionCodeUnicast
}
func (o *UnicastOption) MarshalBinary() ([]byte, error) {
	if len(o.ServerAddress) != net.IPv6len {
		return nil, ErrInvalidIpv6Address
	}
	data := make([]byte, 20)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeUnicast))
	binary.BigEndian.PutUint16(data[2:], 16)
	copy(data[4:], o.ServerAddress)
	return data, nil
}
func (o *UnicastOption) UnmarshalBinary(data []byte) error {
	if len(data) < 20 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeUnicast) {
		return ErrInvalidType
	}
	if binary.BigEndian.Uint16(data[2:]) != net.IPv6len {
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

func (o *StatusCodeOption) Code() OptionCode {
	return OptionCodeStatusCode
}
func (o *StatusCodeOption) MarshalBinary() ([]byte, error) {
	msgData := []byte(o.StatusMessage)
	if len(msgData) > 65534 {
		return nil, ErrWontFit
	}
	data := make([]byte, 5+len(msgData))
	binary.BigEndian.PutUint16(data, uint16(OptionCodeStatusCode))
	binary.BigEndian.PutUint16(data[2:], uint16(len(msgData)+1))
	data[4] = o.StatusCode
	copy(data[5:], msgData)
	return data, nil
}
func (o *StatusCodeOption) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeStatusCode) {
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

// Rapid Commit Option
type RapidCommitOption struct{}

func (o *RapidCommitOption) Code() OptionCode {
	return OptionCodeRapidCommit
}
func (o *RapidCommitOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeRapidCommit))
	binary.BigEndian.PutUint16(data[2:], 0)
	return data, nil
}
func (o *RapidCommitOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeRapidCommit) {
		return ErrInvalidType
	}
	if binary.BigEndian.Uint16(data[2:]) != 0 {
		return ErrInvalidData
	}
	return nil
}

// User Class Option
type UserClassOption struct {
	UserClassData [][]byte
}

func (o *UserClassOption) Code() OptionCode {
	return OptionCodeUserClass
}
func (o *UserClassOption) MarshalBinary() ([]byte, error) {
	size := 0
	for i := range o.UserClassData {
		size += 2 + len(o.UserClassData[i])
	}
	if size > 65539 {
		return nil, ErrWontFit
	}
	data := make([]byte, 4+size)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeUserClass))
	binary.BigEndian.PutUint16(data[2:], uint16(size))
	pos := 4
	for i := range o.UserClassData {
		binary.BigEndian.PutUint16(data[pos:], uint16(len(o.UserClassData[i])))
		copy(data[pos+2:], o.UserClassData[i])
		pos += len(o.UserClassData[i]) + 2
	}
	return data, nil
}
func (o *UserClassOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeUserClass) {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.UserClassData = make([][]byte, 0)
	data = data[4:]
	for len(data) > 0 {
		size := binary.BigEndian.Uint16(data)
		o.UserClassData = append(o.UserClassData, data[2:size+2])
		data = data[size+2:]
	}
	return nil
}

// Vendor Class Option
type VendorClassOption struct {
	VendorClassData [][]byte
}

func (o *VendorClassOption) Code() OptionCode {
	return OptionCodeVendorClass
}
func (o *VendorClassOption) MarshalBinary() ([]byte, error) {
	size := 0
	for i := range o.VendorClassData {
		size += 2 + len(o.VendorClassData[i])
	}
	if size > 65535 {
		return nil, ErrWontFit
	}
	data := make([]byte, 4+size)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeVendorClass))
	binary.BigEndian.PutUint16(data[2:], uint16(size))
	pos := 4
	for i := range o.VendorClassData {
		binary.BigEndian.PutUint16(data[pos:], uint16(len(o.VendorClassData[i])))
		copy(data[pos+2:], o.VendorClassData[i])
		pos += len(o.VendorClassData[i]) + 2
	}
	return data, nil
}
func (o *VendorClassOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeVendorClass) {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.VendorClassData = make([][]byte, 0)
	data = data[4:]
	for len(data) > 0 {
		size := binary.BigEndian.Uint16(data)
		o.VendorClassData = append(o.VendorClassData, data[2:size+2])
		data = data[size+2:]
	}
	return nil
}

// Vendor-specific Information Option
type VendorOptsOption struct {
	EnterpriseNumber uint32
	OptionData       []VendorOptsOptionData
}
type VendorOptsOptionData struct {
	OptionCode uint16
	OptionData []byte
}

func (o *VendorOptsOption) Code() OptionCode {
	return OptionCodeVendorOpts
}
func (o *VendorOptsOption) MarshalBinary() ([]byte, error) {
	size := 4 //enterprise number
	for _, v := range o.OptionData {
		size += 4 + len(v.OptionData)
	}
	if size > 65535 {
		return nil, ErrWontFit
	}
	data := make([]byte, size+4)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeVendorOpts))
	binary.BigEndian.PutUint16(data[2:], uint16(size))
	binary.BigEndian.PutUint32(data[4:], o.EnterpriseNumber)
	pos := 8
	for _, v := range o.OptionData {
		binary.BigEndian.PutUint16(data[pos:], v.OptionCode)
		binary.BigEndian.PutUint16(data[pos+2:], uint16(len(v.OptionData)))
		copy(data[pos+4:], v.OptionData)
		pos += 4 + len(v.OptionData)
	}
	return data, nil
}
func (o *VendorOptsOption) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeVendorOpts) {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.EnterpriseNumber = binary.BigEndian.Uint32(data[4:])
	data = data[8:]
	for len(data) > 0 {
		if len(data) < 4 {
			return ErrUnexpectedEOF
		}
		optData := VendorOptsOptionData{}
		optData.OptionCode = binary.BigEndian.Uint16(data)
		optLen := binary.BigEndian.Uint16(data[2:])
		if len(data) < int(optLen)+4 {
			return ErrUnexpectedEOF
		}
		optData.OptionData = data[4 : optLen+4]
		o.OptionData = append(o.OptionData, optData)
		data = data[optLen+4:]
	}
	return nil
}

// Interface-Id Option
type InterfaceIdOption struct {
	InterfaceId []byte
}

func (o *InterfaceIdOption) Code() OptionCode {
	return OptionCodeInterfaceId
}
func (o *InterfaceIdOption) MarshalBinary() ([]byte, error) {
	if len(o.InterfaceId) > 65535 {
		return nil, ErrWontFit
	}
	data := make([]byte, len(o.InterfaceId)+4)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeInterfaceId))
	binary.BigEndian.PutUint16(data[2:], uint16(len(o.InterfaceId)))
	copy(data[4:], o.InterfaceId)
	return data, nil
}
func (o *InterfaceIdOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeInterfaceId) {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.InterfaceId = data[4 : olen+4]
	return nil
}

// Reconfigure Message Option
type ReconfMsgOption struct {
	MsgType byte
}

func (o *ReconfMsgOption) Code() OptionCode {
	return OptionCodeReconfMsg
}
func (o *ReconfMsgOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 5)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeReconfMsg))
	binary.BigEndian.PutUint16(data[2:], 1)
	data[4] = o.MsgType
	return data, nil
}
func (o *ReconfMsgOption) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeReconfMsg) {
		return ErrInvalidType
	}
	if binary.BigEndian.Uint16(data[2:]) != 1 {
		return ErrInvalidData
	}
	o.MsgType = data[4]
	return nil
}

// Reconfigure Accept Option
type ReconfAcceptOption struct{}

func (o *ReconfAcceptOption) Code() OptionCode {
	return OptionCodeReconfAccept
}
func (o *ReconfAcceptOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeReconfAccept))
	binary.BigEndian.PutUint16(data[2:], 0)
	return data, nil
}
func (o *ReconfAcceptOption) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeReconfAccept) {
		return ErrInvalidType
	}
	if binary.BigEndian.Uint16(data[2:]) != 0 {
		return ErrInvalidData
	}
	return nil
}

// Next Hop Option
type NextHopOption struct {
	NextHop        net.IP
	NextHopOptions []Option
}

func (o *NextHopOption) Code() OptionCode {
	return OptionCodeNextHop
}

func (o *NextHopOption) MarshalBinary() ([]byte, error) {
	var data []byte
	if len(o.NextHopOptions) == 0 {
		data = make([]byte, 20)
	} else {
		data = make([]byte, 20, 65539) //65535+4
	}
	binary.BigEndian.PutUint16(data, uint16(OptionCodeNextHop))
	if len(o.NextHop) != net.IPv6len {
		return nil, ErrInvalidIpv6Address
	}
	copy(data[4:20], o.NextHop[0:net.IPv6len])

	for i := range o.NextHopOptions {
		optionData, err := o.NextHopOptions[i].MarshalBinary()
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

func (o *NextHopOption) UnmarshalBinary(data []byte) error {
	if len(data) < 20 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeNextHop) {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	o.NextHop = net.IP(data[4:20])
	if len(data) == 20 {
		o.NextHopOptions = make([]Option, 0)
	} else {
		//TODO: better way to guess capacity?
		o.NextHopOptions = make([]Option, 0, 10)
	}
	optionData := data[20 : olen+4]
	for len(optionData) != 0 {
		if len(optionData) < 4 {
			return ErrUnexpectedEOF
		}
		nextSize := binary.BigEndian.Uint16(optionData[2:])
		option, err := UnmarshalBinaryOption(optionData[:nextSize+4])
		if err != nil {
			return err
		}
		o.NextHopOptions = append(o.NextHopOptions, option)
		optionData = optionData[nextSize+4:]
	}
	return nil
}

// RtPrefix Option
type RtPrefixOption struct {
	Lifetime	uint32
	Prefixlen	uint8
	Metric		uint8
	Prefix		net.IP
}

func (o *RtPrefixOption) Code() OptionCode {
	return OptionCodeRtPrefix
}

func (o *RtPrefixOption) MarshalBinary() ([]byte, error) {
	if len(o.Prefix) != net.IPv6len {
		return nil, ErrInvalidIpv6Address
	}

	if o.Prefixlen > 128 {
		return nil, ErrInvalidIpv6Address
	}

	data := make([]byte, 4 + 4 + 1 + 1 + net.IPv6len)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeRtPrefix))
	binary.BigEndian.PutUint16(data[2:], uint16(4 + 1 + 1 + net.IPv6len))
	binary.BigEndian.PutUint32(data[4:], o.Lifetime)
	data[8] = o.Prefixlen
	data[9] = o.Metric
	copy(data[10:], o.Prefix)

	return data, nil
}

func (o *RtPrefixOption) UnmarshalBinary(data []byte) error {
	if len(data) < 26 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeRtPrefix) {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen)+4 {
		return ErrUnexpectedEOF
	}
	if data[8] > 128 {
		return ErrInvalidIpv6Address
	}
	o.Lifetime = binary.BigEndian.Uint32(data[4:])
	o.Prefixlen = data[8]
	o.Metric = data[9]
	o.Prefix = net.IP(data[10:])
	return nil
}

// FQDN Option
type FQDNOption struct {
	Flags      uint8
	DomainName string
}

func (o *FQDNOption) Code() OptionCode {
	return OptionCodeFQDN
}

func (o *FQDNOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4 + 1 + len(o.DomainName))
	binary.BigEndian.PutUint16(data, uint16(OptionCodeFQDN))
	binary.BigEndian.PutUint16(data[2:], uint16(1 + len(o.DomainName)))
	data[4] = o.Flags
	copy(data[5:], o.DomainName)

	return data, nil
}

func (o *FQDNOption) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeFQDN) {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen) + 4 {
		return ErrUnexpectedEOF
	}
//	o.Flags = data[4] ???
	o.DomainName = string(data[4 : olen + 4])
	return nil
}

// MTU Option
type MTUOption struct {
	MTU	uint16
}

func (o *MTUOption) Code() OptionCode {
	return OptionCodeMTU
}

func (o *MTUOption) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4 + 2)
	binary.BigEndian.PutUint16(data, uint16(OptionCodeMTU))
	binary.BigEndian.PutUint16(data[2:], uint16(2))
	binary.BigEndian.PutUint16(data[4:], o.MTU)

	return data, nil
}

func (o *MTUOption) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(data) != uint16(OptionCodeMTU) {
		return ErrInvalidType
	}
	olen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(olen) + 4 {
		return ErrUnexpectedEOF
	}
	o.MTU = binary.BigEndian.Uint16(data[4:])
	return nil
}
