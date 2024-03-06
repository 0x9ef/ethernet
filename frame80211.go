// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

import (
	"encoding/binary"
	"hash/crc32"
	"io"
	"sync"
)

// IEEE 802.11 is part of the IEEE 802 set of local area network (LAN) technical standards,
// and specifies the set of media access control (MAC) and physical layer (PHY) protocols for
// implementing wireless local area network (WLAN) computer communication.
// IEEE 802.11 uses various frequencies including, but not limited to, 2.4 GHz, 5 GHz, 6 GHz, and 60 GHz
// frequency bands. Although IEEE 802.11 specifications list channels that might be used,
// the radio frequency spectrum availability allowed varies significantly by regulatory domain.
type Frame80211 struct {
	fc       uint16
	duration uint16
	addr1    HardwareAddr
	addr2    HardwareAddr
	addr3    HardwareAddr
	sc       uint16 // sequence control
	addr4    HardwareAddr
	qos      uint16 // QoS control
	// HT Control Field is always present in a Control Wrapper frame and is present in QoS Data
	// and management frames as determined by the order bit of the Frame Control Field.
	// The only Control Frame subtype for which HT Control field present is the Control Wrapper frame.
	//A control frame  that is described as + HTC (eg RTS+HTC, BlockAckReq+HTC, PS-Poll+HTC) implies the use of
	// Control Wrapper frame to carry the control frame. Below show the frame format of a Control Wrapper
	htc     uint32
	payload []byte
	fcs     [4]byte
}

var min80211Size = 30

func NewFrame80211(addr1, addr2, addr3 HardwareAddr, addr4 *HardwareAddr, fc uint16, duration uint16, payload []byte) *Frame80211 {
	f := &Frame80211{
		fc:       fc,
		duration: duration,
		addr1:    addr1,
		addr2:    addr1,
		addr3:    addr3,
		payload:  payload,
	}
	if addr4 != nil {
		f.addr4 = *addr4
	}
	return f
}

// Receiver return Receiver Address (RA)
func (f *Frame80211) Receiver() HardwareAddr { return f.addr1 }

// Transmitter return Transmitter Address (TA)
func (f *Frame80211) Transmitter() HardwareAddr { return f.addr2 }

// Source return source address (SA)
func (f *Frame80211) Source() HardwareAddr {
	var sa HardwareAddr
	if (f.fc>>8)&1 == 0 && (f.fc>>9)&1 == 0 {
		sa = f.addr2
	} else if (f.fc>>8)&1 == 0 && (f.fc>>9)&1 == 1 {
		sa = f.addr3
	} else if (f.fc>>8)&1 == 1 && (f.fc>>9)&1 == 0 {
		sa = f.addr2
	} else if (f.fc>>8)&1 == 1 && (f.fc>>9)&1 == 1 {
		sa = f.addr4
	}
	return sa
}

// Destination return destination address (DA)
func (f *Frame80211) Destination() HardwareAddr {
	var da HardwareAddr
	if (f.fc>>8)&1 == 0 && (f.fc>>9)&1 == 0 {
		da = f.addr1
	} else if (f.fc>>8)&1 == 0 && (f.fc>>9)&1 == 1 {
		da = f.addr1
	} else if (f.fc>>8)&1 == 1 && (f.fc>>9)&1 == 0 {
		da = f.addr3
	} else if (f.fc>>8)&1 == 1 && (f.fc>>9)&1 == 1 {
		da = f.addr3
	}
	return da
}

// Payload return payload data, maximum payload size defined in max80211MSDU
func (f *Frame80211) Payload() []byte { return f.payload }

// Duration field carries the value of the Network Allocation Vector (NAV).
// Access to the medium is restricted for the time specified by the NAV
func (f *Frame80211) Duration() uint16            { return f.duration }
func (f *Frame80211) SetDuration(duration uint16) { f.duration = duration }

// 802.11 Control Frames assist with the delivery of Data & Management frames.
// Unlike management & data frames, Control frames does not have a frame body
func (f *Frame80211) FrameControl() uint16      { return f.fc }
func (f *Frame80211) SetFrameControl(fc uint16) { f.fc = fc }

func (f *Frame80211) SC() uint16      { return f.sc }
func (f *Frame80211) SetSC(sc uint16) { f.sc = sc }

func (f *Frame80211) QOS() uint16       { return f.qos }
func (f *Frame80211) SetQOS(qos uint16) { f.qos = qos }

func (f *Frame80211) HT() uint32      { return f.htc }
func (f *Frame80211) SetHT(ht uint32) { f.htc = ht }

// Frame check sequence (FCS) refers to the extra bits and characters added to
// data packets for error detection and control.
func (f *Frame80211) FCS() [4]byte       { return f.fcs }
func (f *Frame80211) SetFCS(fcs [4]byte) { f.fcs = fcs }

// Size return seriailized size of frame in bytes
func (f *Frame80211) Size() int {
	// MANDATORY!
	// n:2 = frame control
	// n+2 = duration
	// n+6 = receiver address
	// n+6 = transmitter address
	// n+6 = source address
	n := 2 + 2 + 6 + 6 + 6
	// n+2 = sequence control
	if f.sc != 0 {
		n += 2
	}
	// 	// n+(0 or 6) = destination address
	if !f.addr4.IsEmpty() {
		n += 6
	}
	// n+(0 or 2) = QOS Control
	if f.qos != 0 {
		n += 2
	}
	// n+(0 or 4) = HT Control
	if f.htc != 0 {
		n += 4
	}
	// n+len(payload) = payload
	n += len(f.payload)
	// n+4 = FCS
	n += 4 // fcs
	return n
}

// 802.11 frames are capable of transporting frames with an MSDU payload of 2,304 bytes of upper layer data.
const MaxFrame8011Size = 2304

var frame80211Pool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, MaxFrame8011Size)
	},
}

func (f *Frame80211) Marshal() []byte {
	b := frame80211Pool.Get().([]byte)
	defer frame80211Pool.Put(b)

	b = b[:0]
	b = append(b,
		byte(f.fc>>8),
		byte(f.fc),
	)
	b = append(b,
		byte(f.duration>>8),
		byte(f.duration),
	)
	b = append(b, f.addr1[:]...)
	b = append(b, f.addr2[:]...)
	b = append(b, f.addr3[:]...)
	if f.sc != 0 {
		b = append(b,
			byte(f.sc>>8),
			byte(f.sc),
		)
	}
	if !f.addr4.IsEmpty() {
		b = append(b, f.addr4[:]...)
	}
	if f.qos != 0 {
		b = append(b,
			byte(f.qos>>8),
			byte(f.qos),
		)
	}
	if f.htc != 0 {
		b = append(b, byte(f.htc>>24),
			byte(f.htc>>16),
			byte(f.htc>>8),
			byte(f.htc),
		)
	}
	b = append(b, f.payload...)

	sum := crc32.ChecksumIEEE(b[:])
	f.fcs = [4]byte{
		byte(sum >> 24),
		byte(sum >> 16),
		byte(sum >> 8),
		byte(sum),
	}
	b = append(b, f.fcs[:]...)

	return b
}

func Unmarshal80211(b []byte) (*Frame80211, error) {
	f := new(Frame80211)
	sz := len(b)
	pSz := len(f.payload)
	if sz < min80211Size {
		return nil, io.ErrUnexpectedEOF
	}

	var n int
	f.fc = binary.BigEndian.Uint16(b[0:2])
	f.duration = binary.BigEndian.Uint16(b[2:4])
	n += 4
	copy(f.addr1[:], b[n:n+6])
	n += 6
	copy(f.addr2[:], b[n:n+6])
	n += 6
	copy(f.addr3[:], b[n:n+6])
	n += 6
	f.sc = binary.BigEndian.Uint16(b[n : n+2])
	n += 2
	copy(f.addr4[:], b[n:n+6])
	n += 6
	f.payload = b[n : sz-4]
	n += pSz // + payload size
	copy(f.fcs[:], b[n:])
	return f, nil
}
