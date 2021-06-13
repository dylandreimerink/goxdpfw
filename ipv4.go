package main

import (
	"fmt"
	"strconv"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

// IPv4Field descibes the properties of a IPv4 field
type IPv4Field struct {
	offset int
	size   int
}

// TODO convert IPv4Field to an interface and implement each field as a seperate struct. Reason for this is that
// some fields like Version, IHL, and flags don't align to 8 bits. These fields need to be masked and shifted
// to get a usable value for comparason.

var (
	IPv4VersionIHL = IPv4Field{
		offset: 0,
		size:   1,
	}
	IPv4TOS = IPv4Field{
		offset: IPv4VersionIHL.offset + IPv4VersionIHL.size,
		size:   1,
	}
	IPv4TotalLen = IPv4Field{
		offset: IPv4TOS.offset + IPv4TOS.size,
		size:   2,
	}
	IPv4ID = IPv4Field{
		offset: IPv4TotalLen.offset + IPv4TotalLen.size,
		size:   2,
	}
	IPv4FragmetOffset = IPv4Field{
		offset: IPv4ID.offset + IPv4ID.size,
		size:   2,
	}
	IPv4TTL = IPv4Field{
		offset: IPv4FragmetOffset.offset + IPv4FragmetOffset.size,
		size:   1,
	}
	IPv4Protocol = IPv4Field{
		offset: IPv4TTL.offset + IPv4TTL.size,
		size:   1,
	}
	IPv4Checksum = IPv4Field{
		offset: IPv4Protocol.offset + IPv4Protocol.size,
		size:   2,
	}
	IPv4SourceAddress = IPv4Field{
		offset: IPv4Checksum.offset + IPv4Checksum.size,
		size:   4,
	}
	IPv4DestinationAddress = IPv4Field{
		offset: IPv4SourceAddress.offset + IPv4SourceAddress.size,
		size:   4,
	}
)

var bytesToBPFSize = map[int]ebpf.Size{
	1: ebpf.BPF_B,
	2: ebpf.BPF_H,
	4: ebpf.BPF_W,
	8: ebpf.BPF_DW,
}

var _ Match = (*IPv4FieldMatch)(nil)

// IPv4FieldMatch can match a field in a IPv4 header.
// Like 'ipv4.src == "127.0.0.1"' or 'ipv4.len >= 50'
type IPv4FieldMatch struct {
	Field IPv4Field
	Op    LogicOp
	Value int
}

func (ifm *IPv4FieldMatch) Invert() Match {
	return &IPv4FieldMatch{
		Field: ifm.Field,
		Op:    ifm.Op.Invert(),
		Value: ifm.Value,
	}
}

func (ifm *IPv4FieldMatch) AssembleMatch(counter IDCounter, nextRuleLabel, actionLabel string) ([]string, error) {
	asm := []string{
		"# IPv4 field match",
		// Copy R6 to R1 in case R1 has been reused (R6 is always *xdp_md)
		"	r1 = r6",
		// Load the 'cached' header location of the IPv4 header
		fmt.Sprintf("	r0 = *(u64 *)(r10%+d)", headerLocationVariables[FWLibGetIPv4Header]),
		// If the cached value is not -2, use the cached value and skip the call
		"	if r0 != -2 goto +2",
		// Call FWLibGetIPv4Header
		"	call " + FWLibGetIPv4Header.String(),
		// Cache the result from FWLibGetIPv4Header
		fmt.Sprintf("	*(u64 *)(r10%+d) = r0", headerLocationVariables[FWLibGetIPv4Header]),
		// Jump to next rule/after action if return < 0
		// if return == -1, there is no IPv4 header, no other negative number is expected
		"	if r0 s< 0 goto " + nextRuleLabel,
		// r2 = xdp_md.data
		"	r2 = *(u32 *)(r6 + 0)",
		// R0 is just the offset of the IPv4 header, to get a pointer we need to
		// add the xdp_md.data to the offset.
		"	r0 += r2",
		// Load xdp_md->data_end into R1
		"	r1 = *(u32 *)(r6 + 4)",
		// Copy R0 to R2 so we can use R2 for bounds checking
		"	r2 = r0",
		//
		fmt.Sprintf("	r2 += %d", int32(ifm.Field.offset)+int32(ifm.Field.size)+1),
		// if xdp_md.data + offsetof(iphdr->{field}) + sizeof(iphdr->{field}) > xdp_md.data_end
		"	if r2 > r1 goto " + nextRuleLabel,
		// Invert the op, since we want to jump to the next rule if the condition
		// doesn't match.
	}

	// Invert the op. The 'action' code comes after the match, so we want to jump over the
	// the action to the next rule to get the same result.
	opInst := ifm.Op.Invert().Assembly(strconv.Itoa(ifm.Value), nextRuleLabel)

	asm = append(asm, []string{
		// Load the IPv4 field into R1
		fmt.Sprintf("	r1 = *(%s *)(r0 + %d)", bytesToBPFSize[ifm.Field.size], int16(ifm.Field.offset)),
		// Compare against the static value
		"	" + opInst,
		"# End IPv4 field match",
	}...)

	return asm, nil
}

// getIPv4Header returns the offset from xdp_md.data to the start of the IPv4 header, or -1 if there is no IPv4 header.
func getIPv4Header() []string {
	// Arguments
	// r1 = xdp_md
	return []string{
		// TODO move L2 parsing to seperate lib function. Let the main program pass the first frame pointer
		//  via r2 so lib functions can lookup offsets. Add L2 offset caching.
		FWLibGetIPv4Header.String() + ":",
		"	r0 = -1                         # Set default return value to -1",
		"	r2 = *(u32 *) (r1 + 4)          # r2 = xdp_md.data_end",
		"	r1 = *(u32 *) (r1 + 0)          # r1 = xdp_md.data",
		"	r5 = 14                         # r5 = sizeof(ethhdr)",
		"	r3 = r1                         # r3 = packet bounds checking",
		"	r3 += r5                        # r3 = xdp_md.data + sizeof(ethhdr)",
		"	if r3 > r2 goto get_ipv4_hdr_exit   # if xdp_md.data + sizeof(ethhdr) > xdp_md.data_end",
		"	r4 = *(u16 *) (r1 + 12)         # r4 = ethhdr.h_proto",
		// TODO add 802.1ad and QinQ double tagging support
		fmt.Sprintf("	if r4 != %d goto get_ipv4_hdr_iph  # if ethhdr.h_proto != 0x8100 (802.1Q Virtual LAN)", ebpf.HtonU16(0x8100)),
		"	r5 += 4                         # r5 = sizeof(ethhdr) + sizeof(vlan_hdr)",
		"	r3 += 4                         # r3 = xdp_md.data + sizeof(ethhdr) + sizeof(vlan_hdr)",
		" 	if r3 > r2 goto get_ipv4_hdr_exit   # if xdp_md.data + sizeof(ethhdr) + sizeof(vlan_hdr) > xdp_md.data_end",
		"	r4 = *(u16 *) (r1 + 16)         # r4 = vlan_hdr.h_vlan_encapsulated_proto",
		"get_ipv4_hdr_iph:",
		fmt.Sprintf("	if r4 != %d goto get_ipv4_hdr_exit   # if r4 != 0x0800 (IPv4)", ebpf.HtonU16(0x0800)),
		"	r0 = r5",
		"get_ipv4_hdr_exit:",
		"	exit",
	}
}
