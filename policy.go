package main

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

type Policy struct {
	Rules         []Rule
	DefaultAction Action
}

// Every rule needs to have offsets of headers relative to the start of the frame in order to match the correct
// fields. Since the code of a rule must assume it can be in any position in the policy, the code always has to
// do layer decoding. This is processing instensive, so to lessen that effect we define a few "global" variables
// which hold the result of layer decoding step.
var headerLocationVariables = map[FWLibFunc]int16{
	FWLibGetIPv4Header: -8,
}

func (p *Policy) Compile() ([]ebpf.Instruction, error) {
	policyObject := UnlinkedObject{
		instructions: []ebpf.Instruction{
			// Save xdp_md in R6 which we reserve, so rules don't have to worry about losing xdp_md
			&ebpf.Mov64Register{
				Dest: ebpf.BPF_REG_6,
				Src:  ebpf.BPF_REG_1,
			},
		},
	}

	// Initialize all header location stack variables to -2 to indicate they have not yet been set.
	// -1 is reserved for doesn't exist
	//
	// We need to do this using a register since the verifier doesn't seem to track the value of
	// the memory when we assign it via a constant.
	policyObject.instructions = append(policyObject.instructions,
		&ebpf.Mov64{
			Dest:  ebpf.BPF_REG_2,
			Value: -2,
		},
	)
	for _, address := range headerLocationVariables {
		policyObject.instructions = append(policyObject.instructions,
			&ebpf.StoreMemoryRegister{
				Dest:   ebpf.BPF_REG_10,
				Src:    ebpf.BPF_REG_2,
				Offset: address,
				Size:   ebpf.BPF_DW,
			},
		)
	}

	// TODO add (optionally disableable) ARP and NDP exceptions
	//  these are nessesery since the firewall operates at L2 level.
	//  When the default action is drop, the host will not be able to communicate
	//  at the link level.

	for i, rule := range p.Rules {
		rObj, err := rule.Compile()
		if err != nil {
			return nil, fmt.Errorf("rule '%d': %w", i, err)
		}

		// Combine the existing policy object with the rule object
		policyObject = CombineObjects(policyObject, *rObj)
	}

	defActObj, err := p.DefaultAction.CompileAction()
	if err != nil {
		return nil, fmt.Errorf("default action: %w", err)
	}
	policyObject = CombineObjects(policyObject, *defActObj)

	// TODO only add helper code when actually in use since the verifier error on unreachable code

	libFuncOffsets := make([]int32, len(fwLibFuncToObj))
	for i, libFunc := range fwLibFuncToObj {
		libFuncOffsets[i] = int32(len(policyObject.instructions))
		policyObject = CombineObjects(policyObject, libFunc)
	}

	for _, link := range policyObject.links {
		switch link.Type {
		case LTFunction:
			if call, ok := policyObject.instructions[link.InstIndex].(*ebpf.CallBPF); ok {
				// The minus one is to compensate for the inherent pc+1 of eBPF programs
				call.Offset = libFuncOffsets[link.Index] - int32(link.InstIndex) - 1
			}
		}
	}

	return policyObject.instructions, nil
}

// UnlinkedObject is a piece of 'unlinked' eBPF code that has references to code outside of the object.
// jumps to other functions or bpf-to-bpf functions are not yet set. The links contain a list of locations
// in the code which must be linked and to what.
type UnlinkedObject struct {
	instructions []ebpf.Instruction
	links        []ObjectLink
}

// CombineObjects combines two unlinked object into one
func CombineObjects(a, b UnlinkedObject) UnlinkedObject {
	aLen := len(a.instructions)
	newObj := UnlinkedObject{
		instructions: append(a.instructions, b.instructions...),
		links:        make([]ObjectLink, 0, len(a.links)+len(b.links)),
	}

	newObj.links = append(newObj.links, a.links...)

	for _, link := range b.links {
		link.InstIndex += aLen
		newObj.links = append(newObj.links, link)
	}

	return newObj
}

// ObjectLink describes which instruction should be linked to what other code
type ObjectLink struct {
	Type      LinkType
	InstIndex int
	Index     int
}

// LinkType describes what kind of link is decribed
type LinkType int

const (
	// LTFunction is a link to the address of a BPF-to-BPF function
	LTFunction LinkType = iota
	LTAction
	LTNextRule
)

// Rule represents a single rule in the firewall policy
type Rule struct {
	Name   string
	Match  Match
	Action Action
}

func (r *Rule) Compile() (*UnlinkedObject, error) {
	mObj, err := r.Match.CompileMatch()
	if err != nil {
		return nil, fmt.Errorf("gen match: %w", err)
	}

	aObj, err := r.Action.CompileAction()
	if err != nil {
		return nil, fmt.Errorf("gen action: %w", err)
	}

	*mObj = CombineObjects(*mObj, *aObj)

	// Process the next rule links here
	newLinks := make([]ObjectLink, 0, len(mObj.links))
	for _, link := range mObj.links {
		// If the link is a next rule link
		if link.Type == LTNextRule {
			// Set the jump target of the indicated instruction to the relative difference
			// between the end of the rule and the instruction index
			inst := mObj.instructions[link.InstIndex]
			if jumper, ok := inst.(ebpf.Jumper); ok {
				// The minus one is to compensate for the implicit pc+1 of eBPF programs
				jumper.SetJumpTarget(int16(len(mObj.instructions) - link.InstIndex - 1))
			}

			continue
		}

		// If the link is a next action link
		if link.Type == LTAction {
			// Set the jump target of the indicated instruction to the relative difference
			// between the start of the action and the instruction index
			inst := mObj.instructions[link.InstIndex]
			if jumper, ok := inst.(ebpf.Jumper); ok {
				// The minus one is to compensate for the implicit pc+1 of eBPF programs
				jumper.SetJumpTarget(int16(len(mObj.instructions) - len(aObj.instructions) - link.InstIndex - 1))
			}

			continue
		}

		newLinks = append(newLinks, link)
	}
	mObj.links = newLinks

	return mObj, nil
}

// A Match is any logical expression that can match produce a boolean match from a packet/frame
type Match interface {
	CompileMatch() (*UnlinkedObject, error)
	Invert() Match
}

type LogicOp int

const (
	OpEquals LogicOp = iota
	OpNotEquals
	OpGreaterThan
	OpGreaterThanEquals
	OpSmallerThan
	OpSmallerThanEquals
)

// Instruction returns the eBPF instruction without specific fields which corresponds to the operation enum
func (op LogicOp) Instruction() ebpf.Instruction {
	switch op {
	case OpEquals:
		return &ebpf.JumpEqual{
			Dest: ebpf.BPF_REG_1,
		}
	case OpNotEquals:
		return &ebpf.JumpNotEqual{
			Dest: ebpf.BPF_REG_1,
		}
	case OpGreaterThan:
		return &ebpf.JumpGreaterThan{
			Dest: ebpf.BPF_REG_1,
		}
	case OpGreaterThanEquals:
		return &ebpf.JumpGreaterThanEqual{
			Dest: ebpf.BPF_REG_1,
		}
	case OpSmallerThan:
		return &ebpf.JumpSmallerThan{
			Dest: ebpf.BPF_REG_1,
		}
	case OpSmallerThanEquals:
		return &ebpf.JumpSmallerThanEqual{
			Dest: ebpf.BPF_REG_1,
		}
	}

	return nil
}

// Invert inverts returns the logical op which produces the inverted result of the original op
func (op LogicOp) Invert() LogicOp {
	switch op {
	case OpEquals:
		return OpNotEquals
	case OpNotEquals:
		return OpEquals
	case OpGreaterThan:
		return OpSmallerThanEquals
	case OpGreaterThanEquals:
		return OpSmallerThan
	case OpSmallerThan:
		return OpGreaterThanEquals
	case OpSmallerThanEquals:
		return OpGreaterThan
	}

	return -1
}
