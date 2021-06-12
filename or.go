package main

import (
	"fmt"
	"strings"
)

var _ Match = (*OrMatch)(nil)

type OrMatch struct {
	SubMatch []Match
}

func (om *OrMatch) AssembleMatch(counter IDCounter, ruleEndLabel, actionLabel string) ([]string, error) {
	orAsm := []string{
		"# Or",
	}

	for i, match := range om.SubMatch {
		matchAsm, err := match.AssembleMatch(counter, ruleEndLabel, actionLabel)
		if err != nil {
			return nil, fmt.Errorf("sub-match %d: %w", i, err)
		}

		orAsm = append(orAsm, matchAsm...)
		// If part of an 'or' is true, we should jump to the action, not fallthrough to the next part.
		// But only if this is not the last part, since the action comes directly after the next part.
		if i != len(om.SubMatch)-1 {
			orAsm = append(orAsm, "\tgoto "+actionLabel)
		}

		nextMatchLabel := fmt.Sprintf("next_match_%d", counter.Next())
		orAsm = append(orAsm, nextMatchLabel+":")

		// If part of an 'or' is false, we should jump to the next case not the next rule
		// unless there is no next case.
		if i != len(om.SubMatch)-1 {
			for i, asm := range orAsm {
				orAsm[i] = strings.Replace(asm, "goto "+ruleEndLabel, "goto "+nextMatchLabel, -1)
			}
		}
	}

	orAsm = append(orAsm, "# End or")

	return orAsm, nil
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
