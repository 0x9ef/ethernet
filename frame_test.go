package ethernet

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFrameMarshal(t *testing.T) {
	type suite struct {
		name     string
		src      HardwareAddr
		dst      HardwareAddr
		tag8021q *Tag8021Q
		payload  []byte
		wantLen  int
	}

	testCases := []suite{
		{
			name:    "positive_min_padding",
			src:     HardwareAddr{127, 127, 127, 50, 50, 50},
			dst:     HardwareAddr{255, 255, 255, 50, 50, 50},
			payload: []byte("HELLO"),
			wantLen: 64,
		},
		{
			name: "positive_tag8021q",
			src:  HardwareAddr{127, 127, 127, 50, 50, 50},
			dst:  HardwareAddr{255, 255, 255, 50, 50, 50},
			tag8021q: &Tag8021Q{
				TPID: 0x15,
				TCI:  Encode8021qTCI(PcpBE, 1, 1024),
			},
			payload: []byte("HELLO"),
			wantLen: 68,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFrame(tc.src, tc.dst, EtherTypeIPv4, tc.payload)
			if tc.tag8021q != nil {
				f.SetTag8021Q(tc.tag8021q)
			}
			fmt.Println(f.String())
			b := f.Marshal()
			assert.NotEmpty(t, b)
			assert.Len(t, b, tc.wantLen)
		})
	}
}

func generatePayload() []byte {
	s := make([]byte, 1024)
	rand.Seed(time.Now().Unix())
	rand.Read(s)
	return s
}

func BenchmarkFrameMarshal(b *testing.B) {
	payload := generatePayload()
	b.ResetTimer()
	f := NewFrame(HardwareAddr{127, 127, 127, 50, 50, 50}, HardwareAddr{255, 255, 255, 50, 50, 50}, EtherTypeIPv4, payload)
	for i := 0; i < b.N; i++ {
		_ = f.Marshal()
	}
}

func TestFrameUnmarshal(t *testing.T) {
	type suite struct {
		name            string
		data            []byte
		wantSource      HardwareAddr
		wantDestination HardwareAddr
	}

	testCases := []suite{
		{
			name:            "positive_min_fcs",
			data:            []byte{127, 127, 127, 50, 50, 50, 255, 255, 255, 50, 50, 50, 8, 0, 72, 69, 76, 76, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 123, 123, 123},
			wantSource:      HardwareAddr{255, 255, 255, 50, 50, 50},
			wantDestination: HardwareAddr{127, 127, 127, 50, 50, 50},
		},
		{
			name:            "positive_tag8021q_fcs",
			data:            []byte{127, 127, 127, 50, 50, 50, 255, 255, 255, 50, 50, 50, 0, 21, 0, 85, 8, 0, 72, 69, 76, 76, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 123, 123, 123},
			wantSource:      HardwareAddr{255, 255, 255, 50, 50, 50},
			wantDestination: HardwareAddr{127, 127, 127, 50, 50, 50},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var f Frame
			if err := Unmarshal(tc.data, &f); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.wantSource, f.Source(), "souce mismatch")
			assert.Equal(t, tc.wantDestination, f.Destination(), "destination mismtach")
		})
	}
}

func BenchmarkFrameUnmarshal(b *testing.B) {
	payload := generatePayload()
	data := NewFrame(HardwareAddr{127, 127, 127, 50, 50, 50}, HardwareAddr{255, 255, 255, 50, 50, 50}, EtherTypeIPv4, payload).Marshal()
	for i := 0; i < b.N; i++ {
		var f Frame
		err := Unmarshal(data, &f)
		if err != nil {
			b.Fatal(err)
		}
	}
}
