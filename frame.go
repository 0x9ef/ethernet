// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
)

// In computer networking, an Ethernet frame is a data link layer protocol data unit and uses the
// underlying Ethernet physical layer transport mechanisms. In other words, a data unit on an Ethernet link transports
// an Ethernet frame as its payload. An Ethernet frame is preceded by a preamble and start frame delimiter (SFD),
// which are both part of the Ethernet packet at the physical layer.
// Each Ethernet frame starts with an Ethernet header, which contains destination and source MAC addresses
// as its first two fields. The middle section of the frame is payload data including any headers for
// other protocols (for example, Internet Protocol) carried in the frame.
// The frame ends with a frame check sequence (FCS), which is a 32-bit cyclic redundancy check
// used to detect any in-transit  corruption of data.
type Frame struct {
	preamble  [8]byte      // SFD as last octet
	dst       HardwareAddr // destination MAC address
	src       HardwareAddr // source MAC address
	tag8021q  *Tag8021q    // 802.1Q (can be nil)
	etherType EtherType
	payload   []byte
	fcs       [4]byte
}

const minSize = 64
const minPayloadSize = 46

// ethernet native preamble 10101010 10101010 10101010 10101010 10101010 10101010 10101010 10101011
var preamble = [8]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAB, 0xD5}

// NewFrame return constructed ethernet frame with basic source, destination MAC address
// and payload which this frame contains. If payload have lengh which less than minPayloadSize
// we fills remaining bytes with zeroes
func NewFrame(dst HardwareAddr, src HardwareAddr, payload []byte) *Frame {
	var b []byte
	pSz := len(payload)
	if pSz < minPayloadSize {
		b = make([]byte, minPayloadSize)
		copy(b[:pSz], payload)
	} else {
		b = payload
	}

	f := &Frame{
		preamble:  preamble,
		dst:       dst,
		src:       src,
		tag8021q:  nil,
		etherType: 0x0800,
		payload:   b,
	}
	return f
}

// Source return sender source address
func (f *Frame) Source() HardwareAddr { return f.src }

// Destination return destination address from source frame
func (f *Frame) Destination() HardwareAddr { return f.dst }

// EtherType is a two-octet field in an Ethernet frame.
// It is used to indicate which protocol is encapsulated in the payload of the frame
// and is used at the receiving end by the data link layer to determine how the payload is processed.
// The same field is also used to indicate the size of some Ethernet frames.
func (f *Frame) EtherType() EtherType { return f.etherType }

// Payload the minimum payload is 42 octets when an 802.1Q tag (Tag8012q)
// is present and 46 octets when absent. When the actual payload is less,
// padding bytes are added accordingly. The maximum payload is 1500 octets.
// Non-standard jumbo frames allow for larger maximum payload size.
func (f *Frame) Payload() []byte { return f.payload }

// Tag8021q IEEE 802.1Q, often referred to as Dot1q, is the networking standard that
// supports virtual LANs (VLANs) on an IEEE 802.3 Ethernet network.
// The standard defines a system of VLAN tagging for Ethernet frames and the accompanying
// procedures to be used by bridges and switches in handling such frames.
// The standard also contains provisions for a quality-of-service (QOS) prioritization scheme commonly
// known as IEEE 802.1p and defines the Generic Attribute Registration Protocol.
func (f *Frame) Tag8021q() *Tag8021q       { return f.tag8021q }
func (f *Frame) SetTag8021q(tag *Tag8021q) { f.tag8021q = tag }

// Frame check sequence (FCS) refers to the extra bits and characters added to
// data packets for error detection and control.
func (f *Frame) FCS() [4]byte       { return f.fcs }
func (f *Frame) SetFCS(fcs [4]byte) { f.fcs = fcs }

// Check if frame has an valid ethernet preamble
func (f *Frame) Check() error {
	if f.preamble != preamble {
		return errors.New("invalid ethernet preamble")
	}
	return nil
}

// Size return a serialized size of frame in bytes
func (f *Frame) Size() int {
	var tagSize int
	if f.tag8021q != nil {
		tagSize += 4
	}

	// n:8 = preamble length
	// n:n+6 = source MAC address
	// n:n+6 = destination mac address
	// n:n+tagSz = tag 802.1q
	// n:n+2 = etherType
	// n:n+pSz =  payload length
	// n:n+4 = FCS
	return 8 + 6 + 6 + tagSize + 2 + len(f.payload) + 4
}

func (f *Frame) marshal(b []byte) {
	var n int
	copy(b[0:8], f.preamble[:])
	n += 8
	copy(b[8:14], f.dst[:])
	n += 6
	copy(b[14:20], f.src[:])
	n += 6
	if f.tag8021q != nil {
		binary.BigEndian.PutUint16(b[n:n+2], uint16(f.tag8021q.Tpid))
		n += 2
		binary.BigEndian.PutUint16(b[n:n+2], uint16(f.tag8021q.Tci))
		n += 2
	}
	binary.BigEndian.PutUint16(b[n:n+2], uint16(f.etherType))
	n += 2
	copy(b[n:len(b)-4], f.payload) // marshal payload
	n += len(f.payload)            // add calculated payload length
}

// Marshal implements serialization to the byte representation
// of the Frame structure. If the structure contains tag8021q, performs
// additional serialization of the 802.1Q header within Frame
func (f *Frame) Marshal() []byte {
	b := make([]byte, f.Size())
	f.marshal(b)
	return b
}

// MarshalWithFCS same as Marshal, but computing a frame check sequence
// as last 4 octets, which is an error-detecting code added to a frame in a communication protocol.
func (f *Frame) MarshalWithFCS() []byte {
	b := make([]byte, f.Size())
	f.marshal(b)
	n := len(b) - 4
	v := crc32.ChecksumIEEE(b[0:n])
	b[n] = byte(v >> 24)
	b[n+1] = byte(v >> 16)
	b[n+2] = byte(v >> 8)
	b[n+3] = byte(v)
	f.fcs = [4]byte{b[n], b[n+1], b[n+2], b[n+3]}
	return b
}

// Unmarshal unmarshaling a sequence of bytes into a Frame structure representation.
// If array size is less than minSize (64) returns error io.ErrUnexpectedEOF
func Unmarshal(b []byte) (*Frame, error) {
	f := new(Frame)
	sz := len(b)
	if sz < minSize {
		return nil, io.ErrUnexpectedEOF
	}

	var n int
	copy(f.preamble[:], b[n:8])
	n += 8
	copy(f.dst[:], b[n:n+6])
	n += 6
	copy(f.src[:], b[n:n+6])
	n += 6
	etype := EtherType(binary.BigEndian.Uint16(b[n : n+2]))
	if etype == EtherTypeVlan {
		// have a 802.1Q tag
		f.tag8021q = new(Tag8021q)
		f.tag8021q.Tpid = uint16(etype)
		f.tag8021q.Tci = binary.BigEndian.Uint16(b[n+2 : n+4])
		f.etherType = EtherType(binary.BigEndian.Uint16(b[n+4 : n+6]))
		n += 6
	} else {
		f.etherType = etype
		n += 2
	}

	f.payload = b[n : sz-4]
	n += len(f.payload)
	copy(f.fcs[:], b[n:])
	return f, nil
}

// ComputeFCS compute and return a frame check sequence (FCS)
// which is an error-detecting code added to a frame in a communication protocol.
func ComputeFCS(f interface{}) (fcs [4]byte) {
	var b []byte
	switch v := f.(type) {
	case *Frame:
		b = v.Marshal()
	case *Frame80211:
		b = v.Marshal()
	}
	pos := len(b) - 4
	copy(fcs[:], b[pos:])
	return fcs
}
