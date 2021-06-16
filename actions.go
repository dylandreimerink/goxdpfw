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

func (a *Drop) AssembleAction() ([]string, error) {
	return []string{
		fmt.Sprintf("	r0 = %d", ebpf.XDP_DROP),
		"	exit",
	}, nil
}

var _ Action = (*Pass)(nil)

type Pass struct{}

func (a *Pass) AssembleAction() ([]string, error) {
	return []string{
		fmt.Sprintf("	r0 = %d", ebpf.XDP_PASS),
		"	exit",
	}, nil
}

var _ Action = (*testReturn)(nil)

// testReturn returns an arbirary value, it is used during unit testing to give every rule a seperate
// medurable action.
type testReturn struct {
	value int32
}

func (a *testReturn) AssembleAction() ([]string, error) {
	return []string{
		fmt.Sprintf("	r0 = %d", a.value),
		"	exit",
	}, nil
}

// TODO add 'block' action which sends a ICMP/ICMPv6 destination port unreachable
