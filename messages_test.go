package dhcpv6

import (
	"encoding/hex"
	"fmt"
)

// Create a DHCPv6 Solicit message from scratch and print it
func ExampleDhcpMessage_MarshalBinary() {
	d := DhcpMessage{
		MsgType:       TypeSolicit,
		TransactionId: [3]byte{0xa0, 0xa7, 0xa2},
		Options: []Option{
			&RapidCommitOption{},
			&IaNaOption{
				IAID: [4]byte{0xaf, 0xaa, 0xac, 0xa3},
				T1:   0,
				T2:   0,
			},
			&OroOption{
				[]uint16{
					23, //DNS recursive name server
					24, //Domain Search List
					56, //NTP Server
				},
			},
			&ClientIdOption{
				Duid: &EnDuid{
					EnterpriseNumber: 43793,
					Identifier:       []byte{0xac, 0xa2, 0xa8, 0xaf, 0xae, 0xa3, 0xa3, 0xaf},
				},
			},
			&ElapsedTimeOption{
				ElapsedTime: 0,
			},
		},
	}
	data, _ := d.MarshalBinary()
	fmt.Println(hex.EncodeToString(data))
	//output: 01a0a7a2000e00000003000cafaaaca30000000000000000000600060017001800380001000e00020000ab11aca2a8afaea3a3af000800020000
}
