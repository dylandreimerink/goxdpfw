package main

import (
	"fmt"
)

var _ Match = (*AndMatch)(nil)

type AndMatch struct {
	SubMatch []Match
}

func (am *AndMatch) CompileMatch() (*UnlinkedObject, error) {
	andObj := &UnlinkedObject{}

	for i, match := range am.SubMatch {
		matchObj, err := match.CompileMatch()
		if err != nil {
			return nil, fmt.Errorf("sub-match %d: %w", i, err)
		}

		*andObj = CombineObjects(*andObj, *matchObj)
	}

	return andObj, nil
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
