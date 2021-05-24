package main

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Match = (*OrMatch)(nil)

type OrMatch struct {
	SubMatch []Match
}

func (om *OrMatch) CompileMatch() (*UnlinkedObject, error) {
	andObj := &UnlinkedObject{}

	for i, match := range om.SubMatch {
		matchObj, err := match.CompileMatch()
		if err != nil {
			return nil, fmt.Errorf("sub-match %d: %w", i, err)
		}

		*andObj = CombineObjects(*andObj, *matchObj)
		// If part of an 'or' is true, we should jump to the action, not fallthrough to the next part.
		// But only if this is not the last part, since the action comes directly after the next part.
		if i != len(om.SubMatch)-1 {
			andObj.instructions = append(andObj.instructions, &ebpf.Jump{})
			andObj.links = append(andObj.links, ObjectLink{
				Type:      LTAction,
				InstIndex: len(andObj.instructions) - 1,
			})
		}

		// If part of an 'or' is false, we should jump to the next case not the next rule
		// unless there is no next case.
		if i != len(om.SubMatch)-1 {
			newLinks := make([]ObjectLink, 0, len(andObj.links))
			for _, link := range andObj.links {
				// If the link is a next rule link
				if link.Type == LTNextRule {
					// Set the jump target of the indicated instruction to the relative difference
					// between the end of the rule and the instruction index
					inst := andObj.instructions[link.InstIndex]
					if jumper, ok := inst.(ebpf.Jumper); ok {
						// The minus one is to compensate for the implicit pc+1 of eBPF programs
						jumper.SetJumpTarget(int16(len(andObj.instructions) - link.InstIndex - 1))
					}

					continue
				}

				newLinks = append(newLinks, link)
			}
			andObj.links = newLinks
		}
	}

	return andObj, nil
}

func (om *OrMatch) Invert() Match {
	// De Morgan 1: ¬(P ∨ Q) ⇔ (¬P ∧ ¬Q)
	and := &AndMatch{
		SubMatch: make([]Match, len(om.SubMatch)),
	}
	for i, match := range om.SubMatch {
		and.SubMatch[i] = match.Invert()
	}

	return and
}
