package main

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

// IPv4Field descibes the properties of a IPv4 field
type IPv4Field struct {
	offset int
	size   int
}

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

func (ifm *IPv4FieldMatch) CompileMatch() (*UnlinkedObject, error) {
	obj := &UnlinkedObject{}
	obj.instructions = append(obj.instructions, []ebpf.Instruction{
		// Copy R6 to R1 in case R1 has been reused (R6 is always *xdp_md)
		&ebpf.Mov64Register{
			Dest: ebpf.BPF_REG_1,
			Src:  ebpf.BPF_REG_6,
		},
		// Load the 'cached' header location of the IPv4 header
		&ebpf.LoadMemory{
			Dest:   ebpf.BPF_REG_0,
			Src:    ebpf.BPF_REG_10,
			Offset: headerLocationVariables[FWLibGetIPv4Header],
			Size:   ebpf.BPF_DW,
		},
		// If the cached value is not -2, use the cached value and skip the call
		&ebpf.JumpNotEqual{
			Dest:   ebpf.BPF_REG_0,
			Offset: 2,
			Value:  -2,
		},
		// Call FWLibGetIPv4Header
		&ebpf.CallBPF{
			Offset: 0, // Offset is 0 since the actual address will be set by the linker
		},
	}...)
	// Add link for the call instruction
	obj.links = append(obj.links, ObjectLink{
		Type:      LTFunction,
		InstIndex: len(obj.instructions) - 1,
		Index:     int(FWLibGetIPv4Header),
	})
	obj.instructions = append(obj.instructions,
		// Cache the result from FWLibGetIPv4Header
		&ebpf.StoreMemoryRegister{
			Dest:   ebpf.BPF_REG_10,
			Src:    ebpf.BPF_REG_0,
			Offset: headerLocationVariables[FWLibGetIPv4Header],
			Size:   ebpf.BPF_DW,
		},
		// Jump to next rule/after action if return < 0
		// if return == -1, there is no IPv4 header, no other negative number is expected
		&ebpf.JumpSignedSmallerThan{
			Dest:  ebpf.BPF_REG_0,
			Value: 0,
			// Offset not specified
		},
	)
	// Add link for the call instruction
	obj.links = append(obj.links, ObjectLink{
		Type:      LTNextRule,
		InstIndex: len(obj.instructions) - 1,
	})
	obj.instructions = append(obj.instructions,
		// r2 = xdp_md.data
		&ebpf.LoadMemory{
			Dest:   ebpf.BPF_REG_2,
			Src:    ebpf.BPF_REG_6,
			Offset: 0,
			Size:   ebpf.BPF_W,
		},
		// R0 is just the offset of the IPv4 header, to get a pointer we need to
		// add the xdp_md.data to the offset.
		&ebpf.Add64Register{
			Dest: ebpf.BPF_REG_0,
			Src:  ebpf.BPF_REG_2,
		},
		// Load xdp_md->data_end into R1
		&ebpf.LoadMemory{
			Dest:   ebpf.BPF_REG_1,
			Src:    ebpf.BPF_REG_6,
			Offset: 4,
			Size:   ebpf.BPF_W,
		},
		// Copy R0 to R2 so we can use R2 for bounds checking
		&ebpf.Mov64Register{
			Dest: ebpf.BPF_REG_2,
			Src:  ebpf.BPF_REG_0,
		},
		//
		&ebpf.Add64{
			Dest:  ebpf.BPF_REG_2,
			Value: int32(ifm.Field.offset) + int32(ifm.Field.size) + 1,
		},
		// if xdp_md.data + offsetof(iphdr->{field}) + sizeof(iphdr->{field}) > xdp_md.data_end
		&ebpf.JumpGreaterThanRegister{
			Dest: ebpf.BPF_REG_2,
			Src:  ebpf.BPF_REG_1,
			// Offset not specified
		},
	)

	// Add link for to start of next rule to Jump instruction
	obj.links = append(obj.links, ObjectLink{
		Type:      LTNextRule,
		InstIndex: len(obj.instructions) - 1,
	})

	// Invert the op, since we want to jump to the next rule if the condition
	// doesn't match.
	opInst := ifm.Op.Invert().Instruction()
	if valuer, ok := opInst.(ebpf.Valuer); ok {
		// TODO truncate value to size of field?
		valuer.SetValue(int32(ifm.Value))
	}

	obj.instructions = append(obj.instructions, []ebpf.Instruction{
		// Load the IPv4 field into R1
		&ebpf.LoadMemory{
			Dest:   ebpf.BPF_REG_1,
			Src:    ebpf.BPF_REG_0,
			Offset: int16(ifm.Field.offset),
			Size:   bytesToBPFSize[ifm.Field.size],
		},
		opInst,
	}...)

	// Add link for to start of next rule to Jump instruction
	obj.links = append(obj.links, ObjectLink{
		Type:      LTNextRule,
		InstIndex: len(obj.instructions) - 1,
	})

	return obj, nil
}

func getIPv4Header() UnlinkedObject {
	return UnlinkedObject{
		// TODO cache offset in stack
		instructions: []ebpf.Instruction{
			// Set default return value to -1
			&ebpf.Mov64{
				Dest:  ebpf.BPF_REG_0,
				Value: -1,
			},
			// r2 = xdp_md.data_end
			// r2 = *(uint32 *) (r1 + 4)
			&ebpf.LoadMemory{
				Size:   ebpf.BPF_W,
				Dest:   ebpf.BPF_REG_2,
				Src:    ebpf.BPF_REG_1,
				Offset: 0x04,
			},
			// r1 = xdp_md.data
			// R1 = *(uint32 *) (R1 + 0)
			&ebpf.LoadMemory{
				Size: ebpf.BPF_W,
				Dest: ebpf.BPF_REG_1,
				Src:  ebpf.BPF_REG_1,
			},
			// r5 = sizeof(ethhdr)
			// r5 = 14
			&ebpf.Mov64{
				Dest:  ebpf.BPF_REG_5,
				Value: 14,
			},
			// r3 = packet bounds checking
			// r3 = r1
			&ebpf.Mov64Register{
				Dest: ebpf.BPF_REG_3,
				Src:  ebpf.BPF_REG_1,
			},
			// r3 = xdp_md.data + sizeof(ethhdr)
			// r3 += r5
			&ebpf.Add64Register{
				Dest: ebpf.BPF_REG_3,
				Src:  ebpf.BPF_REG_5,
			},
			// if xdp_md.data + sizeof(ethhdr) > xdp_md.data_end
			// if r3 > r2: goto exit
			&ebpf.JumpGreaterThanRegister{
				Dest:   ebpf.BPF_REG_3,
				Src:    ebpf.BPF_REG_2,
				Offset: 8, // goto exit
			},
			// r4 = ethhdr.h_proto
			// r4 = *(uint16 *) (r1 + 12)
			&ebpf.LoadMemory{
				Dest:   ebpf.BPF_REG_4,
				Src:    ebpf.BPF_REG_1,
				Offset: 12,
				Size:   ebpf.BPF_H,
			},
			// TODO add 802.1ad and QinQ double tagging support
			// if ethhdr.h_proto != 0x8100 (802.1Q Virtual LAN)
			// if r4 != 0x8100: goto iph
			&ebpf.JumpNotEqual32{
				Dest:   ebpf.BPF_REG_4,
				Value:  int32(ebpf.HtonU16(0x8100)),
				Offset: 4, // goto iph
			},
			// r5 = sizeof(ethhdr) + sizeof(vlan_hdr)
			// 	r5 += 4
			&ebpf.Add64{
				Dest:  ebpf.BPF_REG_5,
				Value: 4,
			},
			// r3 = xdp_md.data + sizeof(ethhdr) + sizeof(vlan_hdr)
			// 	r3 += 4
			&ebpf.Add64{
				Dest:  ebpf.BPF_REG_3,
				Value: 4,
			},
			// if xdp_md.data + sizeof(ethhdr) + sizeof(vlan_hdr) > xdp_md.data_end
			// 	if r3 > r2: goto exit
			&ebpf.JumpGreaterThanRegister{
				Dest:   ebpf.BPF_REG_3,
				Src:    ebpf.BPF_REG_2,
				Offset: 3,
			},
			// r4 = vlan_hdr.h_vlan_encapsulated_proto
			// 	r4 = *(uint16 *) (r1 + 16)
			&ebpf.LoadMemory{
				Dest:   ebpf.BPF_REG_4,
				Src:    ebpf.BPF_REG_1,
				Offset: 16,
				Size:   ebpf.BPF_H,
			},
			// iph:
			// if r4 != 0x0800 (IPv4)
			// 	if r4 != 0x0800: goto exit
			&ebpf.JumpNotEqual{
				Dest:   ebpf.BPF_REG_4,
				Offset: 1,
				Value:  int32(ebpf.HtonU16(0x0800)),
			},
			// 	r0 = r5
			&ebpf.Mov64Register{
				Dest: ebpf.BPF_REG_0,
				Src:  ebpf.BPF_REG_5,
			},
			// exit:
			// 	exit
			&ebpf.Exit{},
		},
	}
}
