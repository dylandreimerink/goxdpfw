package main

import (
	"fmt"
	"strings"

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
	FWLibGetTCPHeader:  -16,
}

func (p *Policy) Compile() ([]ebpf.Instruction, error) {
	assembly, err := p.Assemble()
	if err != nil {
		return nil, err
	}

	return ebpf.AssemblyToInstructions("dynamic-policy", strings.NewReader(assembly))
}

func (p *Policy) Assemble() (string, error) {
	var counter IDCounter

	policyAssembly := []string{
		"# Policy",
		// Save xdp_md in R6 which we reserve, so rules don't have to worry about losing xdp_md
		"\tr6 = r1",
	}

	// Initialize all header location stack variables to -2 to indicate they have not yet been set.
	// -1 is reserved for doesn't exist
	//
	// We need to do this using a register since the verifier doesn't seem to track the value of
	// the memory when we assign it via a constant.
	policyAssembly = append(policyAssembly, "\tr2 = -2")
	for _, address := range headerLocationVariables {
		policyAssembly = append(policyAssembly, fmt.Sprintf("\t*(u64 *)(r10%+d) = r2", address))
	}

	// TODO add (optionally disableable) ARP and NDP exceptions
	//  these are nessesery since the firewall operates at L2 level.
	//  When the default action is drop, the host will not be able to communicate
	//  at the link level.

	for i, rule := range p.Rules {
		ruleAsm, err := rule.Assemble(counter)
		if err != nil {
			return "", fmt.Errorf("rule '%d': %w", i, err)
		}

		// Combine the existing policy object with the rule object
		policyAssembly = append(policyAssembly, ruleAsm...)
	}

	policyAssembly = append(policyAssembly, "# Policy default action")

	defActAsm, err := p.DefaultAction.AssembleAction()
	if err != nil {
		return "", fmt.Errorf("default action: %w", err)
	}
	policyAssembly = append(policyAssembly, defActAsm...)

	// TODO only add helper code when actually in use since the verifier error on unreachable code

	for _, libFunc := range fwLibFuncToObj {
		policyAssembly = append(policyAssembly, libFunc...)
	}

	return strings.Join(policyAssembly, "\n") + "\n", nil
}

type IDCounter struct {
	id int
}

func (id *IDCounter) Next() int {
	id.id += 1
	return id.id - 1
}

// Rule represents a single rule in the firewall policy
type Rule struct {
	Name   string
	Match  Match
	Action Action
}

func (r *Rule) Assemble(counter IDCounter) ([]string, error) {
	ruleID := counter.Next()
	ruleEndLabel := fmt.Sprintf("rule_end_%d", ruleID)
	actionLabel := fmt.Sprintf("rule_action_%d", ruleID)

	ruleAsm := []string{
		"# Rule",
	}

	matchAsm, err := r.Match.AssembleMatch(counter, ruleEndLabel, actionLabel)
	if err != nil {
		return nil, fmt.Errorf("gen match: %w", err)
	}

	ruleAsm = append(ruleAsm, matchAsm...)
	ruleAsm = append(ruleAsm, actionLabel+":")

	actionAsm, err := r.Action.AssembleAction()
	if err != nil {
		return nil, fmt.Errorf("gen action: %w", err)
	}

	ruleAsm = append(ruleAsm, actionAsm...)
	ruleAsm = append(ruleAsm, ruleEndLabel+":")

	return ruleAsm, nil
}

// A Match is any logical expression that can match produce a boolean match from a packet/frame
type Match interface {
	AssembleMatch(counter IDCounter, ruleEndLabel, actionLabel string) ([]string, error)
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
func (op LogicOp) Assembly(cmp string, target string) string {
	switch op {
	case OpEquals:
		return "if r1 == " + cmp + " goto " + target
	case OpNotEquals:
		return "if r1 != " + cmp + " goto " + target
	case OpGreaterThan:
		return "if r1 > " + cmp + " goto " + target
	case OpGreaterThanEquals:
		return "if r1 >= " + cmp + " goto " + target
	case OpSmallerThan:
		return "if r1 < " + cmp + " goto " + target
	case OpSmallerThanEquals:
		return "if r1 <= " + cmp + " goto " + target
	}

	return ""
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
