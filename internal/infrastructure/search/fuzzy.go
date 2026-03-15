package search

import (
	"strings"
	"unicode"
)

// Score returns similarity score between query and text (0.0 to 1.0).
// Uses bigram similarity combined with subsequence matching.
func Score(query, text string) float64 {
	query = normalize(query)
	text = normalize(text)

	if query == "" || text == "" {
		return 0
	}

	if text == query {
		return 1.0
	}

	if strings.Contains(text, query) {
		return 0.95
	}

	bigramScore := bigramSimilarity(query, text)
	subseqScore := subsequenceScore(query, text)

	score := bigramScore*0.6 + subseqScore*0.4

	if strings.HasPrefix(text, query) {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

func normalize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if !unicode.IsSpace(r) && !unicode.IsPunct(r) {
			b.WriteRune(r)
		} else if unicode.IsSpace(r) {
			b.WriteRune(' ')
		}
	}
	return strings.TrimSpace(b.String())
}

func bigrams(s string) map[string]int {
	bg := make(map[string]int)
	runes := []rune(s)
	for i := 0; i < len(runes)-1; i++ {
		pair := string(runes[i : i+2])
		bg[pair]++
	}
	return bg
}

func bigramSimilarity(a, b string) float64 {
	bg1 := bigrams(a)
	bg2 := bigrams(b)

	if len(bg1) == 0 || len(bg2) == 0 {
		return 0
	}

	var intersection int
	for pair, count1 := range bg1 {
		if count2, ok := bg2[pair]; ok {
			if count1 < count2 {
				intersection += count1
			} else {
				intersection += count2
			}
		}
	}

	total := len([]rune(a)) - 1 + len([]rune(b)) - 1
	if total == 0 {
		return 0
	}

	return 2.0 * float64(intersection) / float64(total)
}

func subsequenceScore(query, text string) float64 {
	qRunes := []rune(query)
	tRunes := []rune(text)

	qi := 0
	for ti := 0; ti < len(tRunes) && qi < len(qRunes); ti++ {
		if tRunes[ti] == qRunes[qi] {
			qi++
		}
	}

	if len(qRunes) == 0 {
		return 0
	}

	return float64(qi) / float64(len(qRunes))
}
