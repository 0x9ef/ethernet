// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

// EtherType is a two-octet field in an Ethernet frame.
// It is used to indicate which protocol is encapsulated in the payload
// of the frame and is used at the receiving end by the data link layer to
// determine how the payload is processed.
// The same field is also used to indicate the size of some Ethernet frames.
//
// http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
type EtherType uint16

const (
	EtypeTypeIpv4 EtherType = 0x8000
	EtherTypeIPv6 EtherType = 0x86DD
	EtherTypeVlan EtherType = 0x8100
)
