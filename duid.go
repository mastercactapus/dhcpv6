package dhcpv6

import (
	"encoding"
	"encoding/binary"
)

const (
	//DUID Types
	DuidTypeLlt uint16 = 1
	DuidTypeEn  uint16 = 2
	DuidTypeLl  uint16 = 3
)

// DHCP Unique Identifier (DUID)
type Duid interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Type() uint16
}

func UnmarshalBinaryDuid(data []byte) (duid Duid, err error) {
	dtype := binary.BigEndian.Uint16(data)
	switch dtype {
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
type LltDuid struct {
	HardwareType uint16
	Time         uint32
	LlAddress    []byte
}

func (d *LltDuid) Type() uint16 {
	return DuidTypeLlt
}
func (d *LltDuid) MarshalBinary() ([]byte, error) {
	if len(d.LlAddress) > 122 {
		return nil, ErrDuidTooLong
	}
	data := make([]byte, 8+len(d.LlAddress))
	binary.BigEndian.PutUint16(data, DuidTypeLlt)
	binary.BigEndian.PutUint16(data[2:], d.HardwareType)
	binary.BigEndian.PutUint32(data[6:], d.Time)
	copy(data[10:], d.LlAddress)
	return data, nil
}
func (d *LltDuid) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return ErrUnexpectedEOF
	}
	if len(data) > 130 {
		return ErrDuidTooLong
	}
	if binary.BigEndian.Uint16(data) != DuidTypeLlt {
		return ErrInvalidType
	}
	d.HardwareType = binary.BigEndian.Uint16(data[2:])
	d.Time = binary.BigEndian.Uint32(data[4:])
	d.LlAddress = data[10:]
	return nil
}

// DUID Assigned by Vendor Based on Enterprise Number [DUID-EN]
type EnDuid struct {
	EnterpriseNumber uint32
	Identifier       []byte
}

func (d *EnDuid) Type() uint16 {
	return DuidTypeEn
}
func (d *EnDuid) MarshalBinary() ([]byte, error) {
	if len(d.Identifier) > 124 {
		return nil, ErrDuidTooLong
	}
	data := make([]byte, 6+len(d.Identifier))
	binary.BigEndian.PutUint16(data, DuidTypeEn)
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
	if binary.BigEndian.Uint16(data) != DuidTypeEn {
		return ErrInvalidType
	}
	d.EnterpriseNumber = binary.BigEndian.Uint32(data[2:])
	d.Identifier = data[6:]
	data = data[len(data):]
	return nil
}

// DUID Based on Link-layer Address [DUID-LL]
type LlDuid struct {
	HardwareType uint16
	LlAddress    []byte
}

func (d *LlDuid) Type() uint16 {
	return DuidTypeLl
}
func (d *LlDuid) MarshalBinary() ([]byte, error) {
	if len(d.LlAddress) > 126 {
		return nil, ErrDuidTooLong
	}
	data := make([]byte, 4+len(d.LlAddress))
	binary.BigEndian.PutUint16(data, DuidTypeLl)
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
	if binary.BigEndian.Uint16(data) != DuidTypeLl {
		return ErrInvalidType
	}
	d.HardwareType = binary.BigEndian.Uint16(data[2:])
	d.LlAddress = data[4:]
	return nil
}
