// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

import (
	"bytes"
	"fmt"
)

// A media access control address (MAC address) is a unique identifier assigned
// to a network interface controller (NIC) for use as a network address in communications
// within a network segment. This use is common in most IEEE 802 networking technologies,
// including Ethernet, Wi-Fi, and Bluetooth. Within the Open Systems Interconnection (OSI) network model,
// MAC addresses are used in the medium access control protocol sublayer of the data link layer.
// As typically represented, MAC addresses are recognizable as six groups of two hexadecimal digits,
// separated by hyphens, colons, or without a separator.
type HardwareAddr [6]byte

// NewHardwareAddr returns a new MAC address as HardwareAddr
func NewHardwareAddr(b0, b1, b2, b3, b4, b5 byte) HardwareAddr {
	return HardwareAddr{b0, b1, b2, b3, b4, b5}
}

var BroadcastAddr = HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
var UnsetupedAddr = HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// Organisationally Unique Identifier
func (h HardwareAddr) Oui() [3]byte { return [3]byte{h[0], h[1], h[2]} }

// Network Interface Controller
func (h HardwareAddr) Nic() [3]byte { return [3]byte{h[3], h[4], h[5]} }

// String stringify hexadecimal MAC address to output string.
// You have to manually check if the mac address is correct
func (h HardwareAddr) String() string {
	return fmt.Sprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		h[0], h[1], h[2], h[3], h[4], h[5],
	)
}

// Compare comparing two MAC address for equality
func (h HardwareAddr) Compare(raddr HardwareAddr) bool {
	return bytes.Compare(h[:], raddr[:]) == 0
}