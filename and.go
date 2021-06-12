package main

import (
	"fmt"
)

var _ Match = (*AndMatch)(nil)

type AndMatch struct {
	SubMatch []Match
}

func (am *AndMatch) AssembleMatch(counter IDCounter, ruleEndLabel, actionLabel string) ([]string, error) {
	andAsm := []string{
		"# And",
	}

	for i, match := range am.SubMatch {
		matchAsm, err := match.AssembleMatch(counter, ruleEndLabel, actionLabel)
		if err != nil {
			return nil, fmt.Errorf("sub-match %d: %w", i, err)
		}

		andAsm = append(andAsm, matchAsm...)
	}

	andAsm = append(andAsm, "# End and")

	return andAsm, nil
}

func (am *AndMatch) Invert() Match {
	// De Morgan 2: ¬(P ∧ Q) ⇔ (¬P ∨ ¬Q)
	or := &OrMatch{
		SubMatch: make([]Match, len(am.SubMatch)),
	}
	for i, match := range am.SubMatch {
		or.SubMatch[i] = match.Invert()
	}

	return or
}
