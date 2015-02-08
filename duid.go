package dhcpv6

import (
	"encoding"
	"encoding/binary"
)

// The motivation for having more than one type of DUID is that the DUID
// must be globally unique, and must also be easy to generate.  The sort
// of globally-unique identifier that is easy to generate for any given
// device can differ quite widely.  Also, some devices may not contain
// any persistent storage.  Retaining a generated DUID in such a device
// is not possible, so the DUID scheme must accommodate such devices.
type DuidType uint16

const (

	// Link-layer address plus time
	DuidTypeLlt DuidType = 1

	// Vendor-assigned unique ID based on Enterprise Number
	DuidTypeEn DuidType = 2

	// Link-layer address
	DuidTypeLl DuidType = 3
)

// DHCP Unique Identifier (DUID)
// Each DHCP client and server has a DUID.  DHCP servers use DUIDs to
// identify clients for the selection of configuration parameters and in
// the association of IAs with clients.  DHCP clients use DUIDs to
// identify a server in messages where a server needs to be identified.
//
// A DUID consists of a two-octet type code represented in network byte
// order, followed by a variable number of octets that make up the
// actual identifier.  A DUID can be no more than 128 octets long (not
// including the type code).
type Duid interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Type() DuidType
}

// UnmarshalBinaryDuid will take the raw wire-format data and construct
// the correct structure underneath, returning the Duid interface.
func UnmarshalBinaryDuid(data []byte) (duid Duid, err error) {
	dtype := binary.BigEndian.Uint16(data)
	switch DuidType(dtype) {
	case DuidTypeLlt:
		duid = new(LltDuid)
	case DuidTypeEn:
		duid = new(EnDuid)
	case DuidTypeLl:
		duid = new(LlDuid)
	}
	if duid != nil {
		err = duid.UnmarshalBinary(data)
	} else {
		err = ErrInvalidType
	}
	return
}

// DUID Based on Link-layer Address Plus Time [DUID-LLT]
//
// https://tools.ietf.org/html/rfc3315#section-9.2
type LltDuid struct {
	HardwareType uint16
	Time         uint32
	LlAddress    []byte
}

func (d *LltDuid) Type() DuidType {
	return DuidTypeLlt
}
func (d *LltDuid) MarshalBinary() ([]byte, error) {
	if len(d.LlAddress) > 122 {
		return nil, ErrDuidTooLong
	}
	data := make([]byte, 8+len(d.LlAddress))
	binary.BigEndian.PutUint16(data, uint16(DuidTypeLlt))
	binary.BigEndian.PutUint16(data[2:], d.HardwareType)
	binary.BigEndian.PutUint32(data[4:], d.Time)
	copy(data[8:], d.LlAddress)
	return data, nil
}
func (d *LltDuid) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return ErrUnexpectedEOF
	}
	if len(data) > 130 {
		return ErrDuidTooLong
	}
	if binary.BigEndian.Uint16(data) != uint16(DuidTypeLlt) {
		return ErrInvalidType
	}
	d.HardwareType = binary.BigEndian.Uint16(data[2:])
	d.Time = binary.BigEndian.Uint32(data[4:])
	d.LlAddress = data[8:]
	return nil
}

// DUID Assigned by Vendor Based on Enterprise Number [DUID-EN]
//
// https://tools.ietf.org/html/rfc3315#section-9.3
type EnDuid struct {
	EnterpriseNumber uint32
	Identifier       []byte
}

func (d *EnDuid) Type() DuidType {
	return DuidTypeEn
}
func (d *EnDuid) MarshalBinary() ([]byte, error) {
	if len(d.Identifier) > 124 {
		return nil, ErrDuidTooLong
	}
	data := make([]byte, 6+len(d.Identifier))
	binary.BigEndian.PutUint16(data, uint16(DuidTypeEn))
	binary.BigEndian.PutUint32(data[2:], d.EnterpriseNumber)
	copy(data[6:], d.Identifier)
	return data, nil
}
func (d *EnDuid) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return ErrUnexpectedEOF
	}
	if len(data) > 130 {
		return ErrDuidTooLong
	}
	if binary.BigEndian.Uint16(data) != uint16(DuidTypeEn) {
		return ErrInvalidType
	}
	d.EnterpriseNumber = binary.BigEndian.Uint32(data[2:])
	d.Identifier = data[6:]
	data = data[len(data):]
	return nil
}

// DUID Based on Link-layer Address [DUID-LL]
//
// https://tools.ietf.org/html/rfc3315#section-9.4
type LlDuid struct {
	HardwareType uint16
	LlAddress    []byte
}

func (d *LlDuid) Type() DuidType {
	return DuidTypeLl
}
func (d *LlDuid) MarshalBinary() ([]byte, error) {
	if len(d.LlAddress) > 126 {
		return nil, ErrDuidTooLong
	}
	data := make([]byte, 4+len(d.LlAddress))
	binary.BigEndian.PutUint16(data, uint16(DuidTypeLl))
	binary.BigEndian.PutUint16(data[2:], d.HardwareType)
	copy(data[4:], d.LlAddress)
	return data, nil
}
func (d *LlDuid) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return ErrUnexpectedEOF
	}
	if len(data) > 130 {
		return ErrDuidTooLong
	}
	if binary.BigEndian.Uint16(data) != uint16(DuidTypeLl) {
		return ErrInvalidType
	}
	d.HardwareType = binary.BigEndian.Uint16(data[2:])
	d.LlAddress = data[4:]
	return nil
}
