// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

type Tag8021Q struct {
	TPID uint16
	TCI  uint16
}

const maxPcp = 7     // from 0-7
const maxDei = 1     // from 0-1
const maxVlan = 4095 // from 0-4095

// Encode8021qTCI encodes PCP, DEI, VLAN using bitwise operations.
func Encode8021qTCI(pcp uint16, dei uint16, vlan uint16) uint16 {
	return (vlan << 4) | (dei << 3) | pcp
}

// Decode8021qTCI decodes encoded TCI to 3 universal values PCP, DEI, VLAN
func Decode8021qTCI(encoded uint16) (pcp uint16, dei uint16, vlan uint16) {
	return encoded & maxPcp, (encoded >> 3) & maxDei, (encoded >> 4) & maxVlan
}
