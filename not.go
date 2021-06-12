package main

var _ Match = (*NotMatch)(nil)

type NotMatch struct {
	SubMatch Match
}

func (not *NotMatch) AssembleMatch(counter IDCounter, ruleEndLabel, actionLabel string) ([]string, error) {
	return not.SubMatch.Invert().AssembleMatch(counter, ruleEndLabel, actionLabel)
}

func (not *NotMatch) Invert() Match {
	// ¬(¬P) ⇔ P
	return not.SubMatch
}
