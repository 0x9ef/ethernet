// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

const (
	PcpBE = iota + 1 // Best Effort
	PcpBK            // Background
	PcpEE            // Excellent Effort
	PcpCA            // Critical Applications
	PcpVI            // Video, < 100 ms latency and jitter
	PcpVO            // Voice, < 10 ms latency and jitter
	PcpIC            // Internetwork Control
	PCpNC            // Network Control (highest)
)
