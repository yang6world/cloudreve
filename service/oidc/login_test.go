package oidc

import (
	"net/url"
	"testing"
)

func TestLocalRedirect(t *testing.T) {
	valid := map[string]string{
		"":                       "/home",
		"/home":                  "/home",
		"/session/authorize?a=1": "/session/authorize?a=1",
	}
	for input, expected := range valid {
		actual, err := localRedirect(input)
		if err != nil || actual != expected {
			t.Fatalf("local redirect %q: got %q, %v", input, actual, err)
		}
	}

	invalid := []string{
		"https://evil.example",
		"//evil.example/path",
		"/%2f%2fevil.example/path",
		"/%5c%5cevil.example/path",
		"home",
		"\\\\evil.example\\path",
	}
	for _, input := range invalid {
		if _, err := localRedirect(input); err == nil {
			t.Fatalf("external redirect accepted: %q", input)
		}
	}
}

func TestIdentitySettingKey(t *testing.T) {
	first := identitySettingKey("https://idp.example.com", "subject")
	if first != identitySettingKey("https://idp.example.com", "subject") {
		t.Fatal("identity key is not stable")
	}
	if first == identitySettingKey("https://idp.example.com", "other") || first == identitySettingKey("https://other.example.com", "subject") {
		t.Fatal("identity key does not separate issuer and subject")
	}
	if len(first) != len(identityPrefix)+64 {
		t.Fatalf("unexpected identity key length: %d", len(first))
	}
}

func TestSetURLFragment(t *testing.T) {
	target, err := url.Parse("https://cloud.example.com/session/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	setURLFragment(target, url.Values{
		"ticket":   {"ticket-value"},
		"redirect": {"/session/authorize?client_id=test&scope=openid profile"},
	})
	expected := "https://cloud.example.com/session/oidc/callback#redirect=%2Fsession%2Fauthorize%3Fclient_id%3Dtest%26scope%3Dopenid+profile&ticket=ticket-value"
	if actual := target.String(); actual != expected {
		t.Fatalf("unexpected callback URL: %s", actual)
	}
}

func TestValidateClaims(t *testing.T) {
	verified := true
	unverified := false
	config := &Config{RequireVerifiedEmail: true}

	if err := validateClaims(config, &claims{Subject: "subject", Email: "user@example.com", EmailVerified: &verified}); err != nil {
		t.Fatalf("verified claims rejected: %v", err)
	}
	for _, identity := range []*claims{
		{Email: "user@example.com", EmailVerified: &verified},
		{Subject: "subject", EmailVerified: &verified},
		{Subject: "subject", Email: "user@example.com"},
		{Subject: "subject", Email: "user@example.com", EmailVerified: &unverified},
	} {
		if err := validateClaims(config, identity); err == nil {
			t.Fatalf("invalid claims accepted: %#v", identity)
		}
	}

	config.RequireVerifiedEmail = false
	if err := validateClaims(config, &claims{Subject: "subject", Email: "user@example.com"}); err != nil {
		t.Fatalf("optional email verification was enforced: %v", err)
	}
}

func TestMergeClaims(t *testing.T) {
	verified := true
	identity := &claims{Subject: "subject"}
	additional := &claims{
		Subject:           "subject",
		Email:             "user@example.com",
		EmailVerified:     &verified,
		Name:              "Example User",
		PreferredUsername: "example",
		Picture:           "https://idp.example.com/avatar.png",
	}
	if err := mergeClaims(identity, additional); err != nil {
		t.Fatal(err)
	}
	if identity.Email != additional.Email || identity.EmailVerified == nil || !*identity.EmailVerified || identity.Name != additional.Name {
		t.Fatalf("claims were not merged: %#v", identity)
	}

	if err := mergeClaims(identity, &claims{Subject: "other"}); err == nil {
		t.Fatal("mismatched subject was accepted")
	}
	if err := mergeClaims(identity, &claims{Subject: "subject", Email: "other@example.com"}); err == nil {
		t.Fatal("mismatched email was accepted")
	}
}
