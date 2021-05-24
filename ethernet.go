package main

// EthField descibes the properties of a Ethernet header field
type EthField struct {
	offset int
	size   int
}

var (
	EFSrcMAC = EthField{
		offset: 0,
		size:   6,
	}
	EFDstMAC = EthField{
		offset: EFSrcMAC.offset + EFSrcMAC.size,
		size:   6,
	}
	EFNextProto = EthField{
		offset: EFDstMAC.offset + EFDstMAC.size,
		size:   2,
	}
)
