// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"sync"
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
//
// Preamble and SFD don't count into size of Ethernet frame size, because the physical layer
// determines where the frame starts.
type Frame struct {
	dst       HardwareAddr // destination MAC address
	src       HardwareAddr // source MAC address
	tag8021q  *Tag8021Q    // 802.1Q (can be nil)
	etherType EtherType
	payload   []byte
	fcs       [4]byte
}

func (f *Frame) String() string {
	var sb strings.Builder
	sb.WriteString("dst=" + f.dst.String())
	sb.WriteString(" src=" + f.src.String())
	sb.WriteString(fmt.Sprintf(" etherType=%X", f.EtherType()))
	if f.tag8021q != nil {
		sb.WriteString(fmt.Sprintf(" vlan[tpid=0x%X", f.tag8021q.TPID))
		pcp, dei, vlan := Decode8021qTCI(f.tag8021q.TCI)
		sb.WriteString(fmt.Sprintf(" pcp=0x%X(%s)", uint16(pcp), pcp.String()))
		sb.WriteString(fmt.Sprintf(" dei=0x%X", dei))
		sb.WriteString(fmt.Sprintf(" vlan=0x%X]", vlan))
	}
	sb.WriteString(fmt.Sprintf(" size=%d", f.Size()))
	return sb.String()
}

// minHeaderSize is 6 bytes DST + 6 bytes SRC + 4 bytes FCS
const minHeaderSize = 18
const minPayloadSize = 46

const (
	// The minimal frame size is 64 bytes, comprising an 18-byte header and a payload of 46 bytes.
	MinFrameSize           = 64
	MinFrameSizeWithoutFCS = 60
	// The maximum frame size is 1518 bytes, 18 bytes of which are overhead (header and frame check sequence),
	// resulting in an MTU of 1500 bytes.
	MaxFrameSize = 1518
)

// NewFrame return constructed ethernet frame with basic source, destination MAC address
// and payload which this frame contains. If payload have lengh which less than minPayloadSize
// we fills remaining bytes with zeroes
func NewFrame(src HardwareAddr, dst HardwareAddr, etherType EtherType, payload []byte) *Frame {
	var b []byte
	pSz := len(payload)
	if pSz < minPayloadSize {
		b = make([]byte, minPayloadSize)
		copy(b[:pSz], payload)
	} else {
		b = payload
	}

	f := &Frame{
		dst:       dst,
		src:       src,
		tag8021q:  nil,
		etherType: etherType,
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

// Tag8021Q IEEE 802.1Q, often referred to as Dot1q, is the networking standard that
// supports virtual LANs (VLANs) on an IEEE 802.3 Ethernet network.
// The standard defines a system of VLAN tagging for Ethernet frames and the accompanying
// procedures to be used by bridges and switches in handling such frames.
// The standard also contains provisions for a quality-of-service (QOS) prioritization scheme commonly
// known as IEEE 802.1p and defines the Generic Attribute Registration Protocol.
func (f *Frame) Tag8021Q() *Tag8021Q       { return f.tag8021q }
func (f *Frame) SetTag8021Q(tag *Tag8021Q) { f.tag8021q = tag }

// Frame Check Sequence (FCS) refers to the extra bits and characters added to
// data packets for error detection and control.
func (f *Frame) FCS() [4]byte       { return f.fcs }
func (f *Frame) SetFCS(fcs [4]byte) { f.fcs = fcs }

// Size return a serialized size of frame in bytes
func (f *Frame) Size() int {
	var tsz int
	if f.tag8021q != nil {
		tsz += 4
	}
	// minHeaderSize is
	// 6 bytes DST + 6 bytes SRC + 4 bytes FCS
	return minHeaderSize + tsz + len(f.payload)
}

var framePool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, MaxFrameSize)
	},
}

func (f *Frame) marshal() []byte {
	b := framePool.Get().([]byte)
	defer framePool.Put(b)

	b = b[:0]
	b = append(b, f.dst[:]...)
	b = append(b, f.src[:]...)
	if f.tag8021q != nil {
		b = append(b,
			byte(f.tag8021q.TPID>>8),
			byte(f.tag8021q.TPID),
		)
		b = append(b,
			byte(f.tag8021q.TCI>>8),
			byte(f.tag8021q.TCI),
		)
	}
	b = append(b,
		byte(f.etherType>>8),
		byte(f.etherType),
	)
	b = append(b, f.payload...)

	sum := crc32.ChecksumIEEE(b[:])
	f.fcs = [4]byte{
		byte(sum >> 24),
		byte(sum >> 16),
		byte(sum >> 8), byte(sum),
	}
	b = append(b, f.fcs[:]...)
	return b
}

// Marshal serializes frame into the byte representation.
// If the structure contains 802.1Q tag, performs an additional
// encoding of the 802.1Q header within the frame.
func (f *Frame) Marshal() []byte {
	return f.marshal()
}

// Unmarshal unmarshaling a sequence of bytes into a Frame structure representation.
// If array size is less than minSize (64) returns error io.ErrUnexpectedEOF
func Unmarshal(b []byte, f *Frame) error {
	sz := len(b)
	if sz < MinFrameSizeWithoutFCS {
		return io.ErrUnexpectedEOF
	}

	var n int
	copy(f.dst[:], b[:6])
	n += 6
	copy(f.src[:], b[n:n+6])
	n += 6
	etype := EtherType(binary.BigEndian.Uint16(b[n : n+2]))
	if etype == EtherTypeVlan {
		// have a 802.1Q tag
		f.tag8021q = new(Tag8021Q)
		f.tag8021q.TPID = uint16(etype)
		f.tag8021q.TCI = binary.BigEndian.Uint16(b[n+2 : n+4])
		f.etherType = EtherType(binary.BigEndian.Uint16(b[n+4 : n+6]))
		n += 6
	} else {
		f.etherType = etype
		n += 2
	}

	f.payload = b[n : sz-4]
	n += len(f.payload)
	copy(f.fcs[:], b[n:])
	return nil
}
