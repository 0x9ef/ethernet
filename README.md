# Ethernet
Implementation of Ethernet 2, 802.1Q, 802.1P, 802.11 (Wireless Ethernet) frame serialization/deserialization
- https://en.wikipedia.org/wiki/Ethernet
- https://en.wikipedia.org/wiki/IEEE_802.1Q
- https://en.wikipedia.org/wiki/IEEE_P802.1p
- https://en.wikipedia.org/wiki/IEEE_802.11

## Example of marshaling and unmarshaling Ethernet 2 frames
```go
func main() {
	dstAddr := ethernet.NewHardwareAddr(0x8C, 0x8E, 0xC4, 0xFF, 0x9E, 0xA2)
	srcAddr := ethernet.NewHardwareAddr(0x8C, 0x8E, 0xC4, 0xAA, 0x4E, 0xF1)
	f := ethernet.NewFrame(dstAddr, srcAddr, []byte("Hello :)"))
	f.SetTag8021q(&ethernet.Tag8021q{Tpid: 0x8100, Tci: ethernet.Encode8021qTci(3, 0, 1024)})
	b := f.Marshal()
	uf, err := ethernet.Unmarshal(b)
	if err != nil {
		panic(err)
	}

	fmt.Println("Source address:", uf.Source())
	fmt.Println("Destination address:", uf.Destination())
	fmt.Println("Payload:", string(uf.Payload()))

	pcp, dei, vlan := ethernet.Decode8021qTci(uf.Tag8021q().Tci)
	fmt.Println("PCP:", pcp)
	fmt.Println("DEI:", dei)
	fmt.Println("VLAN ID:", vlan)
	fmt.Println("EtherType:", uf.EtherType())
	fmt.Println("Checksum (FCS):", uf.FCS())
}
```

## License

[MIT](./LICENSE)
