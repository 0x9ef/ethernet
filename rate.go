// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package ethernet

// Rate of bits per second
type Rate uint64

const (
	Bit  Rate = 1
	Byte Rate = 8 * Bit
	KB   Rate = 128 * Byte
	MB   Rate = 1024 * KB
	GB   Rate = 1024 * MB
)

const (
	// BASE105 (10BASE5) (also known as thick Ethernet or thicknet) was the first commercially available variant of Ethernet.
	// The technology was standardized in 1982 as IEEE 802.3. 10BASE5 uses a thick and stiff coaxial cable up to 500 meters
	// (1,600 ft) in length. Up to 100 stations can be connected to the cable using vampire taps
	// and share a single collision domain with 10 Mbit/s of bandwidth shared among them.
	// The system is difficult to install and maintain.
	BASE105 = 10 * MB

	// BASE100T inn computer networking, Fast Ethernet physical layers carry traffic at the nominal rate of 100 Mbit/s.
	BASE100T = 100 * MB

	// BASE1000T in computer networking, Gigabit Ethernet (GbE or 1 GigE) is the term applied to transmitting Ethernet frames
	// at a rate of a gigabit per second. The most popular variant 1000BASE-T is defined by the IEEE 802.3ab standard.
	// It came into use in 1999, and has replaced Fast Ethernet in wired local networks due to its considerable
	// speed improvement over Fast Ethernet, as well as its use of cables and equipment that are widely available,
	// economical, and similar to previous standards.
	BASE1000T = 1 * GB
)
