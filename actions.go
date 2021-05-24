package main

import "github.com/dylandreimerink/gobpfld/ebpf"

type Action interface {
	CompileAction() (*UnlinkedObject, error)
}

var _ Action = (*Drop)(nil)

type Drop struct{}

func (b *Drop) CompileAction() (*UnlinkedObject, error) {
	return &UnlinkedObject{
		instructions: []ebpf.Instruction{
			&ebpf.Mov64{
				Dest:  ebpf.BPF_REG_0,
				Value: ebpf.XDP_DROP,
			},
			&ebpf.Exit{},
		},
	}, nil
}

var _ Action = (*Pass)(nil)

type Pass struct{}

func (b *Pass) CompileAction() (*UnlinkedObject, error) {
	return &UnlinkedObject{
		instructions: []ebpf.Instruction{
			&ebpf.Mov64{
				Dest:  ebpf.BPF_REG_0,
				Value: ebpf.XDP_PASS,
			},
			&ebpf.Exit{},
		},
	}, nil
}

// TODO add 'block' action which sends a ICMP/ICMPv6 destination port unreachable
