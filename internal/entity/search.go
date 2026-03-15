package entity

// SearchResult represents a single search result with relevance score.
type SearchResult struct {
	SecretID   string
	SecretType SecretType
	Title      string
	Subtitle   string
	Score      float64
}
