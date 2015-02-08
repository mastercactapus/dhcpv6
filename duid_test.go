package dhcpv6

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestLltDuid_Type(t *testing.T) {
	d := LltDuid{}
	assert.Equal(t, 1, d.Type())
}
func TestLltDuid_MarshalBinary(t *testing.T) {
	d := LltDuid{0x42, 0x36, []byte{0x07, 0x08, 0x09, 0x05}}

	expected := []byte{0x00, 0x01, 0x00, 0x42, 0x00, 0x00, 0x00, 0x36, 0x07, 0x08, 0x09, 0x05}
	actual, err := d.MarshalBinary()
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
	d.LlAddress = []byte(strings.Repeat("a", 123))
	_, err = d.MarshalBinary()
	assert.Error(t, err, "Refuse to create a DUID longer than 128 bytes")
}
func TestLltDuid_UnmarshalBinary(t *testing.T) {
	d := new(LltDuid)
	err := d.UnmarshalBinary([]byte{})
	assert.Error(t, err, "return error on short input")
	err = d.UnmarshalBinary([]byte(strings.Repeat("a", 131)))
	assert.Error(t, err, "return error on too long input")
	err = d.UnmarshalBinary([]byte{0x00, 0x01, 0x00, 0x42, 0x00, 0x00, 0x00, 0x36, 0x07, 0x08, 0x09, 0x05})
	assert.NoError(t, err)
	assert.Equal(t, 0x42, d.HardwareType)
	assert.Equal(t, 0x36, d.Time)
	assert.Equal(t, []byte{0x07, 0x08, 0x09, 0x05}, d.LlAddress)
}
