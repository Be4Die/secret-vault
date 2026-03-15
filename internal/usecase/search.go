package usecase

import (
	"context"
	"fmt"
	"sort"

	"secret-vault/internal/entity"
)

const (
	minSearchScore   = 0.3
	maxSearchResults = 50
	searchableFields = 3 // title, login/token, url
)

// Searcher performs fuzzy matching on text.
type Searcher interface {
	Score(query, text string) float64
}

type SearchUseCase struct {
	secrets   SecretRepository
	encryptor Encryptor
	searcher  Searcher
}

func NewSearchUseCase(
	secrets SecretRepository,
	encryptor Encryptor,
	searcher Searcher,
) *SearchUseCase {
	return &SearchUseCase{
		secrets:   secrets,
		encryptor: encryptor,
		searcher:  searcher,
	}
}

// SearchCredentials searches only credentials for a user.
func (uc *SearchUseCase) SearchCredentials(ctx context.Context, userID string, key []byte, query string) ([]CredentialView, error) {
	secrets, err := uc.secrets.ListByUserAndType(ctx, userID, entity.SecretTypeCredential)
	if err != nil {
		return nil, fmt.Errorf("listing credentials: %w", err)
	}

	type scored struct {
		view  CredentialView
		score float64
	}

	var results []scored
	for _, s := range secrets {
		payload, err := uc.decryptCredential(s.EncryptedPayload, key)
		if err != nil {
			continue
		}

		score := uc.scoreCredential(query, payload)
		if score >= minSearchScore {
			results = append(results, scored{
				view: CredentialView{
					ID:        s.ID,
					Payload:   payload,
					CreatedAt: s.CreatedAt,
					UpdatedAt: s.UpdatedAt,
				},
				score: score,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	if len(results) > maxSearchResults {
		results = results[:maxSearchResults]
	}

	views := make([]CredentialView, len(results))
	for i, r := range results {
		views[i] = r.view
	}

	return views, nil
}

// SearchTokens searches only tokens for a user.
func (uc *SearchUseCase) SearchTokens(ctx context.Context, userID string, key []byte, query string) ([]TokenView, error) {
	secrets, err := uc.secrets.ListByUserAndType(ctx, userID, entity.SecretTypeToken)
	if err != nil {
		return nil, fmt.Errorf("listing tokens: %w", err)
	}

	type scored struct {
		view  TokenView
		score float64
	}

	var results []scored
	for _, s := range secrets {
		payload, err := uc.decryptToken(s.EncryptedPayload, key)
		if err != nil {
			continue
		}

		score := uc.scoreToken(query, payload)
		if score >= minSearchScore {
			results = append(results, scored{
				view: TokenView{
					ID:        s.ID,
					Payload:   payload,
					CreatedAt: s.CreatedAt,
					UpdatedAt: s.UpdatedAt,
				},
				score: score,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	if len(results) > maxSearchResults {
		results = results[:maxSearchResults]
	}

	views := make([]TokenView, len(results))
	for i, r := range results {
		views[i] = r.view
	}

	return views, nil
}

// SearchGlobal searches across all secret types for a user.
func (uc *SearchUseCase) SearchGlobal(ctx context.Context, userID string, key []byte, query string) ([]entity.SearchResult, error) {
	var results []entity.SearchResult

	creds, err := uc.SearchCredentials(ctx, userID, key, query)
	if err != nil {
		return nil, fmt.Errorf("searching credentials: %w", err)
	}
	for _, c := range creds {
		score := uc.scoreCredential(query, c.Payload)
		results = append(results, entity.SearchResult{
			SecretID:   c.ID,
			SecretType: entity.SecretTypeCredential,
			Title:      c.Payload.Title,
			Subtitle:   c.Payload.Login,
			Score:      score,
		})
	}

	tokens, err := uc.SearchTokens(ctx, userID, key, query)
	if err != nil {
		return nil, fmt.Errorf("searching tokens: %w", err)
	}
	for _, t := range tokens {
		score := uc.scoreToken(query, t.Payload)
		results = append(results, entity.SearchResult{
			SecretID:   t.ID,
			SecretType: entity.SecretTypeToken,
			Title:      t.Payload.Title,
			Subtitle:   maskToken(t.Payload.Token),
			Score:      score,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > maxSearchResults {
		results = results[:maxSearchResults]
	}

	return results, nil
}

func (uc *SearchUseCase) scoreCredential(query string, p entity.CredentialPayload) float64 {
	best := 0.0
	for _, field := range []string{p.Title, p.Login, p.URL} {
		if s := uc.searcher.Score(query, field); s > best {
			best = s
		}
	}
	return best
}

func (uc *SearchUseCase) scoreToken(query string, p entity.TokenPayload) float64 {
	best := 0.0
	for _, field := range []string{p.Title, p.URL} {
		if s := uc.searcher.Score(query, field); s > best {
			best = s
		}
	}
	return best
}

func (uc *SearchUseCase) decryptCredential(ciphertext, key []byte) (entity.CredentialPayload, error) {
	data, err := uc.encryptor.Decrypt(ciphertext, key)
	if err != nil {
		return entity.CredentialPayload{}, err
	}

	var payload entity.CredentialPayload
	if err := jsonUnmarshal(data, &payload); err != nil {
		return entity.CredentialPayload{}, err
	}

	return payload, nil
}

func (uc *SearchUseCase) decryptToken(ciphertext, key []byte) (entity.TokenPayload, error) {
	data, err := uc.encryptor.Decrypt(ciphertext, key)
	if err != nil {
		return entity.TokenPayload{}, err
	}

	var payload entity.TokenPayload
	if err := jsonUnmarshal(data, &payload); err != nil {
		return entity.TokenPayload{}, err
	}

	return payload, nil
}

func maskToken(token string) string {
	if len(token) <= 8 {
		return "••••••••"
	}
	return token[:4] + "••••" + token[len(token)-4:]
}
