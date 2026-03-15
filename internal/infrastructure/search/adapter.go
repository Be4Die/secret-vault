package search

// FuzzySearcher wraps the Score function to implement the Searcher interface.
type FuzzySearcher struct{}

func NewFuzzySearcher() *FuzzySearcher {
	return &FuzzySearcher{}
}

func (s *FuzzySearcher) Score(query, text string) float64 {
	return Score(query, text)
}
