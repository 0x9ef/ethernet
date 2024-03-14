// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

type PCP uint8

const (
	PcpBE      PCP = iota + 1 // Best Effort
	PcpBK                     // Background
	PcpEE                     // Excellent Effort
	PcpCA                     // Critical Applications
	PcpVI                     // Video, < 100 ms latency and jitter
	PcpVO                     // Voice, < 10 ms latency and jitter
	PcpIC                     // Internetwork Control
	PcpNC                     // Network Control (highest)
	LowestPCP  = PcpBE
	HighestPCP = PcpNC
)

func (pcp PCP) String() string {
	switch pcp {
	case PcpBE:
		return "Best Effort"
	case PcpBK:
		return "Background"
	case PcpEE:
		return "Excellent Effort"
	case PcpCA:
		return "Critical Applications"
	case PcpVI:
		return "Video"
	case PcpVO:
		return "Voice"
	case PcpIC:
		return "Internetwork Control"
	case PcpNC:
		return "NetworkControl"
	default:
		return "Undefined"
	}
}
