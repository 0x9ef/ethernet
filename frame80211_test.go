package ethernet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFrame80211Marshal(t *testing.T) {
	type suite struct {
		name     string
		addr1    HardwareAddr
		addr2    HardwareAddr
		addr3    HardwareAddr
		addr4    *HardwareAddr
		fc       uint16
		duration uint16
		qos      uint16
		ht       uint32
		sc       uint16
		tag8021q *Tag8021q
		payload  []byte
		wantLen  int
	}

	testCases := []suite{
		{
			name:     "positive_minimum",
			addr1:    HardwareAddr{127, 127, 127, 50, 50, 50},
			addr2:    HardwareAddr{255, 255, 255, 50, 50, 50},
			addr3:    HardwareAddr{255, 255, 255, 50, 50, 20},
			fc:       0x16,
			duration: 0x10,
			payload:  []byte("HELLO"),
			wantLen:  26 + 5,
		},
		{
			name:     "positive_4addr",
			addr1:    HardwareAddr{127, 127, 127, 50, 50, 50},
			addr2:    HardwareAddr{255, 255, 255, 50, 50, 50},
			addr3:    HardwareAddr{255, 255, 255, 50, 50, 20},
			addr4:    &HardwareAddr{255, 255, 255, 10, 10, 10},
			fc:       0x16,
			duration: 0x10,
			payload:  []byte("HELLO"),
			wantLen:  32 + 5,
		},
		{
			name:     "positive_sc",
			addr1:    HardwareAddr{127, 127, 127, 50, 50, 50},
			addr2:    HardwareAddr{255, 255, 255, 50, 50, 50},
			addr3:    HardwareAddr{255, 255, 255, 50, 50, 20},
			fc:       0x16,
			duration: 0x10,
			sc:       0x180,
			payload:  []byte("HELLO"),
			wantLen:  28 + 5,
		},
		{
			name:     "positive_qos",
			addr1:    HardwareAddr{127, 127, 127, 50, 50, 50},
			addr2:    HardwareAddr{255, 255, 255, 50, 50, 50},
			addr3:    HardwareAddr{255, 255, 255, 50, 50, 20},
			fc:       0x16,
			duration: 0x10,
			qos:      0x4,
			payload:  []byte("HELLO"),
			wantLen:  28 + 5,
		},
		{
			name:     "positive_ht",
			addr1:    HardwareAddr{127, 127, 127, 50, 50, 50},
			addr2:    HardwareAddr{255, 255, 255, 50, 50, 50},
			addr3:    HardwareAddr{255, 255, 255, 50, 50, 20},
			fc:       0x16,
			duration: 0x10,
			ht:       0x1222,
			payload:  []byte("HELLO"),
			wantLen:  30 + 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFrame80211(tc.addr1, tc.addr2, tc.addr3, tc.addr4, tc.fc, tc.duration, tc.payload)
			f.SetSC(tc.sc)
			f.SetHT(tc.ht)
			f.SetQOS(tc.qos)

			b := f.Marshal()
			assert.NotEmpty(t, b)
			assert.Len(t, b, tc.wantLen, "mismatched encoded frame size")
			assert.Equal(t, tc.wantLen, f.Size())
			//assert.Equal(t, f.Size(), tc.wantLen, "mismatched frame size")
		})
	}
}

func BenchmarkFrame80211Marshal(b *testing.B) {
	payload := generatePayload()
	b.ResetTimer()
	f := NewFrame80211(HardwareAddr{127, 127, 127, 50, 50, 50}, HardwareAddr{255, 255, 255, 50, 50, 50}, HardwareAddr{255, 255, 255, 50, 50, 10}, nil, 0x50, 0x20, payload)
	for i := 0; i < b.N; i++ {
		_ = f.Marshal()
	}
}
