package main

var _ Match = (*NotMatch)(nil)

type NotMatch struct {
	SubMatch Match
}

func (not *NotMatch) CompileMatch() (*UnlinkedObject, error) {
	return not.SubMatch.Invert().CompileMatch()
}

func (not *NotMatch) Invert() Match {
	// ¬(¬P) ⇔ P
	return not.SubMatch
}
