package main

// FWLibFunc or firewall library function is a internal bpf-to-bpf helper function which can be used
// by firewall rules to perform common functions like layer/protocol decoding
type FWLibFunc int

func (flf FWLibFunc) Compile() UnlinkedObject {
	return fwLibFuncToObj[flf]
}

const (
	// FWLibGetIPv4Header is a function which takes in a pointer to an xdp_md struct.
	// https://elixir.bootlin.com/linux/v5.12.5/source/include/uapi/linux/bpf.h#L4460
	// And it returns the offset to the start of the IPv4 header relative to xdp_md.data.
	// If there is no IPv4 header found, -1 is returned.
	FWLibGetIPv4Header FWLibFunc = iota
	maxFWLibGetEthHeader
)

// fwLibFuncToObj is an lookup table which translates a FWLibFunc to an UnlinkedObject
var fwLibFuncToObj = [maxFWLibGetEthHeader]UnlinkedObject{
	FWLibGetIPv4Header: getIPv4Header(),
}
