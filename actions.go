package main

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

type Action interface {
	AssembleAction() ([]string, error)
}

var _ Action = (*Drop)(nil)

type Drop struct{}

func (b *Drop) AssembleAction() ([]string, error) {
	return []string{
		fmt.Sprintf("	r0 = %d", ebpf.XDP_DROP),
		"	exit",
	}, nil
}

var _ Action = (*Pass)(nil)

type Pass struct{}

func (b *Pass) AssembleAction() ([]string, error) {
	return []string{
		fmt.Sprintf("	r0 = %d", ebpf.XDP_PASS),
		"	exit",
	}, nil
}

// TODO add 'block' action which sends a ICMP/ICMPv6 destination port unreachable
