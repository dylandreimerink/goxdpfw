package main

import (
	"fmt"
	"strconv"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

// TCPField is any struct that can generate assembly which puts the contents of a TCP field under test into r1.
// A TCPField can assume that:
// * r0 is a pointer to xpd_md.data
// * r1 is a pointer to xdp_md.data_end
// * r2 is a pointer to xpd_md.data plus the offset to the start of the TCP header
type TCPField interface {
	AssembleTCPFieldCode(nextRuleLabel string) []string
	GetSize() int
}

type genericTCPField struct {
	offset int
	size   int
	mask   int
	shift  int
}

func (gtc *genericTCPField) GetSize() int {
	return gtc.size
}

func (gtc *genericTCPField) AssembleTCPFieldCode(nextRuleLabel string) []string {
	asm := []string{
		// Bounds check up to and including the field +1 byte margin
		fmt.Sprintf("	r2 += %d", int32(gtc.offset)+int32(gtc.size)+1),
		// if xdp_md.data + offsetof(tcphdr->{field}) + sizeof(tcphdr->{field}) > xdp_md.data_end
		"	if r2 > r1 goto " + nextRuleLabel,
		// Load field at offset of size into r1
		fmt.Sprintf("	r1 = *(%s *)(r0 + %d)", bytesToBPFSize[gtc.size], int16(gtc.offset)),
	}

	if gtc.mask != 0 {
		asm = append(asm,
			fmt.Sprintf("	r1 &= %d", gtc.mask),
		)
	}

	if gtc.shift < 0 {
		asm = append(asm,
			fmt.Sprintf("	r1 <<= %d", -gtc.shift),
		)
	}

	if gtc.shift > 0 {
		asm = append(asm,
			fmt.Sprintf("	r1 >>= %d", gtc.shift),
		)
	}

	return asm
}

var (
	TCPSourcePort = &genericTCPField{
		offset: 0,
		size:   2,
	}
	TCPDestinationPort = &genericTCPField{
		offset: TCPSourcePort.offset + TCPSourcePort.size,
		size:   2,
	}
	TCPSequence = &genericTCPField{
		offset: TCPDestinationPort.offset + TCPDestinationPort.size,
		size:   4,
	}
	TCPAcknowlegementNum = &genericTCPField{
		offset: TCPSequence.offset + TCPSequence.size,
		size:   4,
	}
	TCPDataOffset = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size,
		size:   1,
		mask:   0b11110000,
		shift:  4,
	}
	TCPFlagNS = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size,
		size:   1,
		mask:   0b00000001,
	}
	TCPFlagCWR = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size + 1,
		size:   1,
		mask:   0b10000000,
		shift:  7,
	}
	TCPFlagECE = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size + 1,
		size:   1,
		mask:   0b01000000,
		shift:  6,
	}
	TCPFlagURG = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size + 1,
		size:   1,
		mask:   0b00100000,
		shift:  5,
	}
	TCPFlagACK = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size + 1,
		size:   1,
		mask:   0b00010000,
		shift:  4,
	}
	TCPFlagPSH = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size + 1,
		size:   1,
		mask:   0b00001000,
		shift:  3,
	}
	TCPFlagRST = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size + 1,
		size:   1,
		mask:   0b00000100,
		shift:  2,
	}
	TCPFlagSYN = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size + 1,
		size:   1,
		mask:   0b00000010,
		shift:  1,
	}
	TCPFlagFIN = &genericTCPField{
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size + 1,
		size:   1,
		mask:   0b00000001,
		shift:  0,
	}
	TCPWindowSize = &genericTCPField{
		// Additional 2 is for the header length and flags which are 16 bits
		offset: TCPAcknowlegementNum.offset + TCPAcknowlegementNum.size + 2,
		size:   2,
	}
	TCPChecksum = &genericTCPField{
		offset: TCPWindowSize.offset + TCPWindowSize.size,
		size:   2,
	}
	TCPUrgentPointer = &genericTCPField{
		offset: TCPChecksum.offset + TCPChecksum.size,
		size:   2,
	}
	// TODO options
)

var _ Match = (*TCPFieldMatch)(nil)

type TCPFieldMatch struct {
	Field TCPField
	Op    LogicOp
	Value int
}

func (tfm *TCPFieldMatch) Invert() Match {
	return &TCPFieldMatch{
		Field: tfm.Field,
		Op:    tfm.Op.Invert(),
		Value: tfm.Value,
	}
}

func (tfm *TCPFieldMatch) AssembleMatch(counter *IDCounter, nextRuleLabel, actionLabel string) ([]string, error) {
	asm := []string{
		"# TCP field match",
		// Copy R6 to R1 in case R1 has been reused (R6 is always *xdp_md)
		"	r1 = r6",
		// Load the 'cached' header location of the TCP header
		fmt.Sprintf("	r0 = *(u64 *)(r10%+d)", headerLocationVariables[FWLibGetTCPHeader]),
		// If the cached value is not -2, use the cached value and skip the call
		"	if r0 != -2 goto +2",
		// Call FWLibGetTCPHeader
		"	call " + FWLibGetTCPHeader.String(),
		// Cache the result from FWLibGetTCPHeader
		fmt.Sprintf("	*(u64 *)(r10%+d) = r0", headerLocationVariables[FWLibGetTCPHeader]),
		// Jump to next rule/after action if return < 0
		// if return == -1, there is no TCP header, no other negative number is expected
		"	if r0 s< 0 goto " + nextRuleLabel,
		// r2 = xdp_md.data
		"	r2 = *(u32 *)(r6 + 0)",
		// R0 is just the offset of the TCP header, to get a pointer we need to
		// add the xdp_md.data to the offset.
		"	r0 += r2",
		// Load xdp_md->data_end into R1
		"	r1 = *(u32 *)(r6 + 4)",
		// Copy R0 to R2 so we can use R2 for bounds checking
		"	r2 = r0",
	}

	// Gen field specific code
	asm = append(asm, tfm.Field.AssembleTCPFieldCode(nextRuleLabel)...)

	// The value is specified in host byte order, so turn it into network byte order
	// since that is how eBPF needs it.
	networkValue := tfm.Value
	switch tfm.Field.GetSize() {
	case 2:
		networkValue = int(ebpf.Hton16(int16(networkValue)))
	case 4:
		networkValue = int(ebpf.Hton32(int32(networkValue)))
	case 8:
		networkValue = int(ebpf.Hton64(int64(networkValue)))
	}

	// Invert the op. The 'action' code comes after the match, so we want to jump over the
	// the action to the next rule to get the same result.
	opInst := tfm.Op.Invert().Assembly(strconv.Itoa(networkValue), nextRuleLabel)

	asm = append(asm, []string{
		// Compare against the static value
		"	" + opInst,
		"# End TCP field match",
	}...)

	return asm, nil
}

// getTCPHeader returns the offset from xdp_md.data to the TCP header
func getTCPHeader() []string {
	// Arguments
	// r1 = xdp_md

	return []string{
		FWLibGetTCPHeader.String() + ":",
		// Since we are in a function call, we are not allowed to use r6-9 to save r1-5.
		// So write them to our local stack.
		"	*(u64 *)(r10 - 8) = r1          # Save r1 in stack",
		// TODO Let the main program pass the first frame pointer
		//  via r2 so lib functions can lookup offsets. Add L3 offset caching.
		"	call " + FWLibGetIPv4Header.String(),
		// TODO try IPv6 if there is no IPv4 header is found
		"	if r0 s< 0 goto exit            # exit if no IPv4",
		"	r4 = r0							# Store IPv4 offset",
		"	r1 = *(u64 *)(r10 - 8)          # Restore r1(xdp_md) from stack",
		"	r2 = *(u32 *)(r1 + 4)           # r2 = xdp_md.data_end",
		"	r1 = *(u32 *)(r1 + 0)           # r1 = xdp_md.data",
		"	r1 += r0						# r1 = *iph",
		"   r0 = -1							# set default return value to -1",
		"	r3 = r1                         # r3 = iphdr (bound checking)",
		fmt.Sprintf("	r3 += %d                        # r3 = iphdr.protocol + sizeof(iphdr->protocol)",
			IPv4Protocol.offset+IPv4Protocol.size,
		),
		" 	if r3 > r2 goto exit            # if iphdr.protocol + sizeof(iphdr->protocol) > xdp_md.data_end",
		fmt.Sprintf("	r3 = *(%s *)(r1 + %d)           # r3 = iphdr->protocol",
			bytesToBPFSize[IPv4Protocol.size],
			IPv4Protocol.offset,
		),
		"	if r3 != 6 goto exit            # if iphdr->protocol != TCP",
		"	r0 = *(u8 *)(r1 + 0)            # r0 = iph->version|iph->ihl",
		"   r0 &= 0x0F					    # r0 = iph->ihl (mask of the last nibble)",
		"   r0 *= 4							# r0 = iph->ihl * 4 (IPv4 data)",
		"	r0 += r4						# r0 = offset from xdp_md.data to start of TCP header",
		"exit:",
		"	exit",
	}
}
