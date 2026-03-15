package search_test

import (
	"testing"

	"secret-vault/internal/infrastructure/search"
)

func TestScore_ExactMatch(t *testing.T) {
	score := search.Score("github", "github")
	if score != 1.0 {
		t.Errorf("exact match should score 1.0, got %f", score)
	}
}

func TestScore_ExactMatchCaseInsensitive(t *testing.T) {
	score := search.Score("GitHub", "GITHUB")
	if score != 1.0 {
		t.Errorf("case-insensitive exact match should score 1.0, got %f", score)
	}
}

func TestScore_Contains(t *testing.T) {
	score := search.Score("hub", "github")
	if score < 0.9 {
		t.Errorf("substring match should score >= 0.9, got %f", score)
	}
}

func TestScore_Prefix(t *testing.T) {
	score := search.Score("git", "github")
	if score < 0.9 {
		t.Errorf("prefix match should score >= 0.9, got %f", score)
	}
}

func TestScore_EmptyQuery(t *testing.T) {
	score := search.Score("", "github")
	if score != 0 {
		t.Errorf("empty query should score 0, got %f", score)
	}
}

func TestScore_EmptyText(t *testing.T) {
	score := search.Score("github", "")
	if score != 0 {
		t.Errorf("empty text should score 0, got %f", score)
	}
}

func TestScore_BothEmpty(t *testing.T) {
	score := search.Score("", "")
	if score != 0 {
		t.Errorf("both empty should score 0, got %f", score)
	}
}

func TestScore_NoMatch(t *testing.T) {
	score := search.Score("zzzzz", "github")
	if score > 0.3 {
		t.Errorf("no match should score low, got %f", score)
	}
}

func TestScore_FuzzyMatch(t *testing.T) {
	score := search.Score("gthb", "github")
	if score < 0.3 {
		t.Errorf("fuzzy match should score > 0.3, got %f", score)
	}
}

func TestScore_SimilarStrings(t *testing.T) {
	score := search.Score("gitlab", "github")
	if score < 0.3 {
		t.Errorf("similar strings should have reasonable score, got %f", score)
	}
}

func TestScore_MaxCappedAtOne(t *testing.T) {
	score := search.Score("a", "a")
	if score > 1.0 {
		t.Errorf("score should never exceed 1.0, got %f", score)
	}
}

func TestScore_Unicode(t *testing.T) {
	score := search.Score("пароль", "мой пароль")
	if score < 0.5 {
		t.Errorf("unicode substring should score well, got %f", score)
	}
}

func TestScore_WithPunctuation(t *testing.T) {
	score := search.Score("github", "github.com")
	if score < 0.5 {
		t.Errorf("with punctuation stripped should still match, got %f", score)
	}
}

func TestScore_Ordering(t *testing.T) {
	exact := search.Score("github", "github")
	contains := search.Score("git", "github")
	fuzzy := search.Score("gthb", "github")
	none := search.Score("zzzzz", "github")

	if exact <= contains {
		t.Errorf("exact (%f) should beat contains (%f)", exact, contains)
	}
	if contains <= fuzzy {
		t.Errorf("contains (%f) should beat fuzzy (%f)", contains, fuzzy)
	}
	if fuzzy <= none {
		t.Errorf("fuzzy (%f) should beat no match (%f)", fuzzy, none)
	}
}
