//go:build integration

package integration_test

import (
	"testing"

	"secret-vault/internal/entity"
)

func TestSearch_Credentials(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	credentials := []entity.CredentialPayload{
		{Title: "GitHub", Login: "alice@github.com", Password: "pass1", URL: "https://github.com"},
		{Title: "GitLab", Login: "alice@gitlab.com", Password: "pass2", URL: "https://gitlab.com"},
		{Title: "AWS Console", Login: "admin", Password: "pass3", URL: "https://aws.amazon.com"},
		{Title: "Stripe Dashboard", Login: "alice", Password: "pass4", URL: "https://stripe.com"},
	}

	for _, c := range credentials {
		if _, err := env.credentialUC.Create(ctx, user.ID, key, c); err != nil {
			t.Fatalf("create credential %q: %v", c.Title, err)
		}
	}

	// Search "git" should find GitHub and GitLab
	results, err := env.searchUC.SearchCredentials(ctx, user.ID, key, "git")
	if err != nil {
		t.Fatalf("search 'git': %v", err)
	}
	if len(results) < 2 {
		t.Errorf("expected at least 2 results for 'git', got %d", len(results))
	}

	// Search "aws" should find AWS Console
	results, err = env.searchUC.SearchCredentials(ctx, user.ID, key, "aws")
	if err != nil {
		t.Fatalf("search 'aws': %v", err)
	}
	if len(results) < 1 {
		t.Errorf("expected at least 1 result for 'aws', got %d", len(results))
	}

	// Search gibberish should find nothing
	results, err = env.searchUC.SearchCredentials(ctx, user.ID, key, "zzzzxxx")
	if err != nil {
		t.Fatalf("search gibberish: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for gibberish, got %d", len(results))
	}
}

func TestSearch_Tokens(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	tokens := []entity.TokenPayload{
		{Title: "Stripe API Key", Token: "sk_live_xxx", URL: "https://stripe.com"},
		{Title: "OpenAI Key", Token: "sk-proj-xxx", URL: "https://openai.com"},
		{Title: "SSH Server", Token: "ssh-rsa AAAA"},
	}

	for _, tk := range tokens {
		if _, err := env.tokenUC.Create(ctx, user.ID, key, tk); err != nil {
			t.Fatalf("create token %q: %v", tk.Title, err)
		}
	}

	results, err := env.searchUC.SearchTokens(ctx, user.ID, key, "stripe")
	if err != nil {
		t.Fatalf("search 'stripe': %v", err)
	}
	if len(results) < 1 {
		t.Errorf("expected at least 1 result for 'stripe', got %d", len(results))
	}
}

func TestSearch_Global(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	_, key, _ := registerTestUser(t, env, "alice")
	user, _ := env.userRepo.GetByUsername(ctx, "alice")

	_, _ = env.credentialUC.Create(ctx, user.ID, key, entity.CredentialPayload{
		Title: "GitHub", Login: "alice", Password: "pass",
	})
	_, _ = env.tokenUC.Create(ctx, user.ID, key, entity.TokenPayload{
		Title: "GitHub Token", Token: "ghp_xxxxxxxxxxxx",
	})

	results, err := env.searchUC.SearchGlobal(ctx, user.ID, key, "github")
	if err != nil {
		t.Fatalf("global search: %v", err)
	}
	if len(results) < 2 {
		t.Errorf("expected at least 2 results (credential + token), got %d", len(results))
	}

	// Verify both types found
	hasCredential := false
	hasToken := false
	for _, r := range results {
		switch r.SecretType {
		case entity.SecretTypeCredential:
			hasCredential = true
		case entity.SecretTypeToken:
			hasToken = true
		}
	}
	if !hasCredential {
		t.Error("expected credential in global search results")
	}
	if !hasToken {
		t.Error("expected token in global search results")
	}
}

func TestSearch_IsolationBetweenUsers(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()

	_, keyAlice, _ := registerTestUser(t, env, "alice")
	_, keyBob, _ := registerTestUser(t, env, "bobuser")

	alice, _ := env.userRepo.GetByUsername(ctx, "alice")
	bob, _ := env.userRepo.GetByUsername(ctx, "bobuser")

	_, _ = env.credentialUC.Create(ctx, alice.ID, keyAlice, entity.CredentialPayload{
		Title: "Alice Secret Service", Login: "alice", Password: "pass",
	})

	results, err := env.searchUC.SearchCredentials(ctx, bob.ID, keyBob, "alice")
	if err != nil {
		t.Fatalf("search as bob: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("bob should not see alice's secrets, got %d results", len(results))
	}
}
