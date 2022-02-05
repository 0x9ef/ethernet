// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

import (
	"encoding/binary"
	"hash/crc32"
	"io"
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
	ra       HardwareAddr // receiver address
	ta       HardwareAddr // transmitter address
	sa       HardwareAddr // source address
	sc       uint16       // sequence control
	da       HardwareAddr // destination address
	payload  []byte
	fcs      [4]byte
}

var min80211Size = 30
var max80211MSDU = 2304

func NewFrame80211(ra, ta, sa, da HardwareAddr, payload []byte) *Frame80211 {
	f := &Frame80211{
		fc:       0,
		duration: 0,
		ra:       ra,
		ta:       ta,
		sa:       sa,
		da:       da,
		payload:  payload,
	}
	f.fcs = Compute80211FCS(f)
	return f
}

// Receiver return Receiver Address (RA)
func (f *Frame80211) Receiver() HardwareAddr { return f.ra }

// Transmitter return Transmitter Address (TA)
func (f *Frame80211) Transmitter() HardwareAddr { return f.ta }

// Source return source address (SA)
func (f *Frame80211) Source() HardwareAddr { return f.sa }

// Destination return destination address (DA)
func (f *Frame80211) Destination() HardwareAddr { return f.da }

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

// Frame check sequence (FCS) refers to the extra bits and characters added to
// data packets for error detection and control.
func (f *Frame80211) FCS() [4]byte       { return f.fcs }
func (f *Frame80211) SetFCS(fcs [4]byte) { f.fcs = fcs }

func (f *Frame80211) Marshal() []byte {
	sz := f.size()
	pSz := len(f.payload)
	b := make([]byte, sz)
	var n int
	binary.BigEndian.PutUint16(b[0:2], f.fc)
	binary.BigEndian.PutUint16(b[2:4], f.duration)
	n += 4
	copy(b[n:n+6], f.ra[:])
	n += 6
	copy(b[n:n+6], f.ta[:])
	n += 6
	copy(b[n:n+6], f.sa[:])
	n += 6
	binary.BigEndian.PutUint16(b[n:n+2], f.sc)
	n += 2
	copy(b[n:n+6], f.da[:])
	n += 6
	copy(b[n:sz-4], f.payload)
	n += pSz
	binary.BigEndian.PutUint32(b[n:], crc32.ChecksumIEEE(b[0:n]))
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
	copy(f.ra[:], b[n:n+6])
	n += 6
	copy(f.ta[:], b[n:n+6])
	n += 6
	copy(f.sa[:], b[n:n+6])
	n += 6
	f.sc = binary.BigEndian.Uint16(b[n : n+2])
	n += 2
	copy(f.da[:], b[n:n+6])
	n += 6
	f.payload = b[n : sz-4]
	n += pSz // + payload size
	copy(f.fcs[:], b[n:])
	return f, nil
}

func Compute80211FCS(f *Frame80211) (fcs [4]byte) {
	binaryFrame := f.Marshal()
	copy(fcs[:], binaryFrame[len(binaryFrame)-4:])
	return fcs
}

func (f *Frame80211) size() int {
	// n:2 = frame control
	// n+2 = duration
	// n+6 = receiver address
	// n+6 = transmitter address
	// n+6 = source address
	// n+2 = sequence control
	// n+6 = destination address
	// n+len(payload) = payload
	// n+4 = FCS
	pSz := len(f.payload)
	return 2 + 2 + 6 + 6 + 6 + 2 + 6 + pSz + 4
}
