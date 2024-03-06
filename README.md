# Ethernet Frame Serializarion/Deserazization library written in Go
The library implements frame serialization/deserialization in pure Go. The list of the supported Ethernet standards:
* [802.3](https://en.wikipedia.org/wiki/Ethernet)
* [802.1Q](https://en.wikipedia.org/wiki/IEEE_802.1Q)
* [802.1P](https://en.wikipedia.org/wiki/IEEE_P802.1p)
* [802.11/Wireless](https://en.wikipedia.org/wiki/IEEE_802.11)

## Usage Examples
See the `*_test.go` files.

## How to Encode?
```go
	dstAddr := ethernet.NewHardwareAddr(0x8C, 0x8E, 0xC4, 0xFF, 0x9E, 0xA2)
	srcAddr := ethernet.NewHardwareAddr(0x8C, 0x8E, 0xC4, 0xAA, 0x4E, 0xF1)
	f := ethernet.NewFrame(srcAddr, dst, []byte("Hello :)"))
	f.SetTag8021q(&ethernet.Tag8021q{Tpid: 0x8100, Tci: ethernet.Encode8021qTci(3, 0, 1024)})
	b := f.Marshal()
```
## How to Decode?
```go
	b := f.Marshal()

	var f Frame
	err := ethernet.Unmarshal(b, &f)
	if err != nil {
		panic(err)
	}

	pcp, dei, vlan := ethernet.Decode8021qTci(f.Tag8021q().Tci)
	fmt.Println("PCP:", pcp)
	fmt.Println("DEI:", dei)
	fmt.Println("VLAN ID:", vlan)
	fmt.Println("EtherType:", f.EtherType())
	fmt.Println("Checksum (FCS):", f.FCS())
```

## License
[MIT](./LICENSE)
