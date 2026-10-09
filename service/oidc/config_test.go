package oidc

import (
	"reflect"
	"testing"
)

func TestConfigFromValues(t *testing.T) {
	config := configFromValues(map[string]string{
		SettingEnabled:     "true",
		SettingIssuer:      " https://idp.example.com/ ",
		SettingClientID:    " client ",
		SettingScopes:      "profile,email",
		SettingDisplayName: " Example SSO ",
		SettingOnlyLogin:   "yes",
	})

	if !config.Enabled || !config.OnlyLogin || !config.RequireVerifiedEmail {
		t.Fatal("expected enabled, OIDC-only, verified-email defaults")
	}
	if config.Issuer != "https://idp.example.com/" || config.ClientID != "client" || config.DisplayName != "Example SSO" {
		t.Fatalf("settings were not normalized: %#v", config)
	}
	if !reflect.DeepEqual(config.Scopes, []string{"openid", "profile", "email"}) {
		t.Fatalf("unexpected scopes: %#v", config.Scopes)
	}
}

func TestValidateConfig(t *testing.T) {
	valid := &Config{Enabled: true, Issuer: "https://idp.example.com", ClientID: "client", ClientSecret: "secret"}
	if err := validateConfig(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	invalidIssuers := []string{
		"http://idp.example.com",
		"//idp.example.com",
		"javascript:alert(1)",
		"https://user@idp.example.com",
		"https://idp.example.com?tenant=one",
		"https://idp.example.com#issuer",
	}
	for _, issuer := range invalidIssuers {
		config := *valid
		config.Issuer = issuer
		if err := validateConfig(&config); err == nil {
			t.Fatalf("invalid issuer accepted: %q", issuer)
		}
	}

	local := *valid
	local.Issuer = "http://localhost:8080/realms/test"
	if err := validateConfig(&local); err != nil {
		t.Fatalf("local development issuer rejected: %v", err)
	}
}

func TestPublicConfigOnlyLoginRequiresEnabled(t *testing.T) {
	public := (&Config{OnlyLogin: true}).Public()
	if public.OnlyLogin {
		t.Fatal("disabled OIDC must not force redirect")
	}
}
