package oidc

import (
	"context"
	"strings"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
)

const (
	MaskedClientSecret          = "********"
	SettingEnabled              = "oidc_enabled"
	SettingIssuer               = "oidc_issuer"
	SettingClientID             = "oidc_client_id"
	SettingClientSecret         = "oidc_client_secret"
	SettingScopes               = "oidc_scopes"
	SettingDisplayName          = "oidc_display_name"
	SettingLogo                 = "oidc_logo"
	SettingOnlyLogin            = "oidc_only_login"
	SettingRequireVerifiedEmail = "oidc_require_verified_email"
)

var settingKeys = []string{
	SettingEnabled,
	SettingIssuer,
	SettingClientID,
	SettingClientSecret,
	SettingScopes,
	SettingDisplayName,
	SettingLogo,
	SettingOnlyLogin,
	SettingRequireVerifiedEmail,
}

type Config struct {
	Enabled              bool
	Issuer               string
	ClientID             string
	ClientSecret         string
	Scopes               []string
	DisplayName          string
	Logo                 string
	OnlyLogin            bool
	RequireVerifiedEmail bool
}

type PublicConfig struct {
	Enabled     bool   `json:"enabled"`
	DisplayName string `json:"display_name,omitempty"`
	Logo        string `json:"logo,omitempty"`
	OnlyLogin   bool   `json:"only_login,omitempty"`
}

func configFromValues(values map[string]string) *Config {
	scopes := strings.Fields(strings.ReplaceAll(value(values, SettingScopes, "openid profile email"), ",", " "))
	if !contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}

	return &Config{
		Enabled:              boolValue(values[SettingEnabled]),
		Issuer:               strings.TrimSpace(values[SettingIssuer]),
		ClientID:             strings.TrimSpace(values[SettingClientID]),
		ClientSecret:         values[SettingClientSecret],
		Scopes:               scopes,
		DisplayName:          strings.TrimSpace(value(values, SettingDisplayName, "OpenID Connect")),
		Logo:                 strings.TrimSpace(values[SettingLogo]),
		OnlyLogin:            boolValue(values[SettingOnlyLogin]),
		RequireVerifiedEmail: value(values, SettingRequireVerifiedEmail, "1") != "0",
	}
}

func LoadConfig(ctx context.Context, dep dependency.Dep) (*Config, error) {
	values, err := dep.SettingClient().Gets(ctx, settingKeys)
	if err != nil {
		return nil, err
	}

	return configFromValues(values), nil
}

// PrepareSettings validates and normalizes OIDC admin setting updates.
func PrepareSettings(ctx context.Context, dep dependency.Dep, updates map[string]string) error {
	values, err := dep.SettingClient().Gets(ctx, settingKeys)
	if err != nil {
		return err
	}

	if secret, ok := updates[SettingClientSecret]; ok && (secret == "" || secret == MaskedClientSecret) {
		updates[SettingClientSecret] = values[SettingClientSecret]
	}
	for key, val := range updates {
		values[key] = val
	}

	config := configFromValues(values)
	if config.Enabled {
		if err := validateConfig(config); err != nil {
			return err
		}
	}

	if _, ok := updates[SettingIssuer]; ok {
		updates[SettingIssuer] = config.Issuer
	}
	if _, ok := updates[SettingClientID]; ok {
		updates[SettingClientID] = config.ClientID
	}
	if _, ok := updates[SettingScopes]; ok {
		updates[SettingScopes] = strings.Join(config.Scopes, " ")
	}
	if _, ok := updates[SettingDisplayName]; ok {
		updates[SettingDisplayName] = config.DisplayName
	}
	if _, ok := updates[SettingLogo]; ok {
		updates[SettingLogo] = config.Logo
	}
	return nil
}

func (c *Config) Public() *PublicConfig {
	return &PublicConfig{
		Enabled:     c.Enabled,
		DisplayName: c.DisplayName,
		Logo:        c.Logo,
		OnlyLogin:   c.Enabled && c.OnlyLogin,
	}
}

func value(values map[string]string, key, fallback string) string {
	if v, ok := values[key]; ok && v != "" {
		return v
	}
	return fallback
}

func boolValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
