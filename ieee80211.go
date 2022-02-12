// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

type FrameType uint16

const (
	Management FrameType = iota
	Control
	Data
	Reserved
)

const (
	SubtypeData                = 0x0
	SubtypeQosData             = 0x8
	SubtypeAssociationReq      = 0x0
	SubtypeAssociationResp     = 0x1
	SubtypeReassociationReq    = 0x2
	SubtypeReassociationResp   = 0x3
	SubtypeProbeReq            = 0x4
	SubtypeProbeResp           = 0x5
	SubtypeTimingAdvertisement = 0x6
	SubtypeReserved            = 0x7
	SubtypeBeacon              = 0x8
	SubtypeAtim                = 0x9
	SubtypeDisassociation      = 0xA
	SubtypeAuthentication      = 0xB
	SubtypeDeauthentication    = 0xC
	SubtypeAction              = 0xD
	SubtypeNack                = 0xE
	SubtypeTrigger             = 0x2
	SubtypeTack                = 0x3
	SubtypeControlWrapper      = 0x7
	SubtypeRts                 = 0xB
	SubtypeCts                 = 0xC
	SubtypeAck                 = 0xD
)

func Encode80211Sc(fn uint16, sn uint16) uint16 {
	return (sn << 4) | fn
}

func Decode80211Sc(encoded uint16) (fn uint16, sn uint16) {
	return encoded & 15, (encoded >> 4) & 4095
}

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
