// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

func Encode80211Fc(version uint16, ftype uint16, subtype uint16,
	tds uint16, fds uint16, mf uint16, rt uint16,
	pm uint16, md uint16, wep uint16, order uint16) uint16 {

	encoded := (order << 15) | (wep << 14) |
		(md << 13) | (pm << 12) |
		(rt << 11) | (mf << 10) |
		(fds << 9) | (tds << 8) |
		(subtype << 4) | (ftype << 2) | version
	return encoded
}

func Decode80211Fc(encoded uint16) [11]uint16 {
	return [11]uint16{
		encoded & 3,         // version
		(encoded >> 2) & 3,  // ftype
		(encoded >> 4) & 15, // subtype
		(encoded >> 8) & 1,  // tds
		(encoded >> 9) & 1,  // fds
		(encoded >> 10) & 1, // mf
		(encoded >> 11) & 1, // rt
		(encoded >> 12) & 1, // pm
		(encoded >> 13) & 1, // md
		(encoded >> 14) & 1, // wep
		(encoded >> 15) & 1, // order
	}
}
