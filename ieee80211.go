// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

type FrameType uint16

const (
	Management FrameType = 0b00
	Control    FrameType = 0b01
	Data       FrameType = 0b10
	Reserved   FrameType = 0b11
)

const (
	SubtypeData                = 0b0000
	SubtypeQosData             = 0b1000
	SubtypeAssociationReq      = 0b0000
	SubtypeAssociationResp     = 0b0001
	SubtypeReassociationReq    = 0b0010
	SubtypeReassociationResp   = 0b0011
	SubtypeProbeReq            = 0b0100
	SubtypeProbeResp           = 0b0101
	SubtypeTimingAdvertisement = 0b0110
	SubtypeReserved            = 0b0111
	SubtypeBeacon              = 0b1000
	SubtypeAtim                = 0b1001
	SubtypeDisassociation      = 0b1010
	SubtypeAuthentication      = 0b1011
	SubtypeDeauthentication    = 0b1100
	SubtypeAction              = 0b1101
	SubtypeNack                = 0b1110
	SubtypeTrigger             = 0b0010
	SubtypeTack                = 0b0011
	SubtypeControlWrapper      = 0b0111
	SubtypeRts                 = 0b1011
	SubtypeCts                 = 0b1100
	SubtypeAck                 = 0b1101
)

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
