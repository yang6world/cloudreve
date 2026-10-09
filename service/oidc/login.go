package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entsetting "github.com/cloudreve/Cloudreve/v4/ent/setting"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const (
	stateKeyPrefix  = "oidc_login_state_"
	ticketKeyPrefix = "oidc_login_ticket_"
	identityPrefix  = "ext_oidc_identity_"
	stateTTL        = 10 * time.Minute
	ticketTTL       = 90 * time.Second
)

type loginState struct {
	Nonce        string
	PKCEVerifier string
	Redirect     string
}

type claims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
}

type ExchangeService struct {
	Ticket string `json:"ticket" binding:"required"`
}

type ExchangeParameterCtx struct{}

func init() {
	gob.Register(loginState{})
}

func Start(c *gin.Context) (string, error) {
	dep := dependency.FromContext(c)
	config, err := LoadConfig(c, dep)
	if err != nil {
		return "", serializer.NewError(serializer.CodeInternalSetting, "Failed to load OIDC settings", err)
	}
	if err := validateConfig(config); err != nil {
		return "", err
	}

	redirect, err := localRedirect(c.Query("redirect"))
	if err != nil {
		return "", serializer.NewError(serializer.CodeParamErr, "Invalid redirect URL", err)
	}

	_, oauthConfig, err := providerConfig(c, dep, config)
	if err != nil {
		return "", err
	}

	state := util.RandStringRunesCrypto(48)
	nonce := util.RandStringRunesCrypto(48)
	verifier := oauth2.GenerateVerifier()
	if err := dep.KV().Set(stateKeyPrefix+state, loginState{
		Nonce:        nonce,
		PKCEVerifier: verifier,
		Redirect:     redirect,
	}, int(stateTTL.Seconds())); err != nil {
		return "", serializer.NewError(serializer.CodeInternalSetting, "Failed to create OIDC login session", err)
	}

	return oauthConfig.AuthCodeURL(
		state,
		coreoidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	), nil
}

func Callback(c *gin.Context) string {
	dep := dependency.FromContext(c)
	frontend := dep.SettingProvider().SiteURL(c).ResolveReference(&url.URL{Path: "/session/oidc/callback"})
	query := frontend.Query()

	fail := func(message string, err error) string {
		dep.Logger().Warning("OIDC sign-in failed: %s: %v", message, err)
		query.Set("error", "1")
		frontend.RawQuery = query.Encode()
		return frontend.String()
	}

	stateID := c.Query("state")
	if stateID == "" {
		return fail("OIDC login session is invalid", errors.New("missing state"))
	}
	stored, ok := dep.KV().Take(stateKeyPrefix + stateID)
	if !ok {
		return fail("OIDC login session has expired", errors.New("state not found"))
	}
	state, ok := stored.(loginState)
	if !ok {
		return fail("Invalid OIDC login session", errors.New("invalid state type"))
	}
	if providerError := c.Query("error"); providerError != "" {
		return fail("Identity provider rejected the sign-in request", errors.New(providerError))
	}

	config, err := LoadConfig(c, dep)
	if err != nil {
		return fail("Failed to load OIDC settings", err)
	}
	requestCtx := coreoidc.ClientContext(c, &http.Client{Timeout: 15 * time.Second})
	provider, oauthConfig, err := providerConfig(requestCtx, dep, config)
	if err != nil {
		return fail("Failed to initialize OIDC provider", err)
	}

	token, err := oauthConfig.Exchange(requestCtx, c.Query("code"), oauth2.VerifierOption(state.PKCEVerifier))
	if err != nil {
		return fail("Failed to exchange OIDC authorization code", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return fail("OIDC provider did not return an ID token", errors.New("missing id_token"))
	}
	idToken, err := provider.Verifier(&coreoidc.Config{ClientID: config.ClientID}).Verify(requestCtx, rawIDToken)
	if err != nil {
		return fail("OIDC ID token validation failed", err)
	}
	if idToken.Nonce != state.Nonce {
		return fail("OIDC nonce validation failed", errors.New("nonce mismatch"))
	}

	var identity claims
	if err := idToken.Claims(&identity); err != nil {
		return fail("Failed to read OIDC claims", err)
	}
	if identity.Email == "" || (config.RequireVerifiedEmail && identity.EmailVerified == nil) {
		userInfo, err := provider.UserInfo(requestCtx, oauth2.StaticTokenSource(token))
		if err != nil {
			return fail("Failed to read OIDC UserInfo", err)
		}
		if userInfo.Subject != identity.Subject {
			return fail("OIDC UserInfo subject validation failed", errors.New("subject mismatch"))
		}
		var additionalClaims claims
		if err := userInfo.Claims(&additionalClaims); err != nil {
			return fail("Failed to read OIDC UserInfo claims", err)
		}
		if err := mergeClaims(&identity, &additionalClaims); err != nil {
			return fail("OIDC UserInfo validation failed", err)
		}
	}
	user, err := resolveUser(c, dep, config, idToken.Issuer, &identity)
	if err != nil {
		return fail("Failed to sign in with OIDC", err)
	}

	ticket := util.RandStringRunesCrypto(64)
	if err := dep.KV().Set(ticketKeyPrefix+ticket, user.ID, int(ticketTTL.Seconds())); err != nil {
		return fail("Failed to create OIDC login ticket", err)
	}
	fragment := url.Values{}
	fragment.Set("ticket", ticket)
	if state.Redirect != "" {
		fragment.Set("redirect", state.Redirect)
	}
	setURLFragment(frontend, fragment)
	return frontend.String()
}

func setURLFragment(target *url.URL, values url.Values) {
	target.RawFragment = values.Encode()
	target.Fragment, _ = url.PathUnescape(target.RawFragment)
}

func (s *ExchangeService) Exchange(c *gin.Context) (*usersvc.BuiltinLoginResponse, error) {
	dep := dependency.FromContext(c)
	key := ticketKeyPrefix + s.Ticket
	stored, ok := dep.KV().Take(key)
	if !ok {
		return nil, serializer.NewError(serializer.CodeLoginSessionNotExist, "OIDC login ticket is invalid or expired", nil)
	}
	uid, ok := stored.(int)
	if !ok {
		return nil, serializer.NewError(serializer.CodeCredentialInvalid, "Invalid OIDC login ticket", nil)
	}

	ctx := context.WithValue(c, inventory.LoadUserGroup{}, true)
	u, err := dep.UserClient().GetActiveByID(ctx, uid)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeUserNotFound, "OIDC user is not available", err)
	}
	token, err := dep.TokenAuth().Issue(c, &auth.IssueTokenArgs{User: u})
	if err != nil {
		return nil, serializer.NewError(serializer.CodeEncryptError, "Failed to issue token pair", err)
	}
	return &usersvc.BuiltinLoginResponse{User: usersvc.BuildUser(u, dep.HashIDEncoder()), Token: *token}, nil
}

func providerConfig(ctx context.Context, dep dependency.Dep, config *Config) (*coreoidc.Provider, *oauth2.Config, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	provider, err := coreoidc.NewProvider(coreoidc.ClientContext(ctx, client), config.Issuer)
	if err != nil {
		return nil, nil, serializer.NewError(serializer.CodeInternalSetting, "Failed to discover OIDC provider", err)
	}
	callback := dep.SettingProvider().SiteURL(ctx).ResolveReference(&url.URL{Path: constants.APIPrefix + "/session/oidc/callback"})
	return provider, &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  callback.String(),
		Scopes:       config.Scopes,
	}, nil
}

func validateConfig(config *Config) error {
	if !config.Enabled {
		return serializer.NewError(serializer.CodeFeatureNotEnabled, "OIDC login is disabled", nil)
	}
	if config.Issuer == "" || config.ClientID == "" || config.ClientSecret == "" {
		return serializer.NewError(serializer.CodeInternalSetting, "OIDC issuer, client ID and client secret are required", nil)
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer == nil {
		return serializer.NewError(serializer.CodeInternalSetting, "OIDC issuer must be an absolute HTTPS URL", err)
	}
	localIssuer := issuer.Hostname() == "localhost" || issuer.Hostname() == "127.0.0.1" || issuer.Hostname() == "::1"
	if issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" ||
		(issuer.Scheme != "https" && !(issuer.Scheme == "http" && localIssuer)) {
		return serializer.NewError(serializer.CodeInternalSetting, "OIDC issuer must be an absolute HTTPS URL", err)
	}
	return nil
}

func localRedirect(raw string) (string, error) {
	if raw == "" {
		return "/home", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") ||
		strings.HasPrefix(parsed.Path, "//") || strings.Contains(parsed.Path, "\\") {
		return "", errors.New("redirect must be a local absolute path")
	}
	return parsed.String(), nil
}

func resolveUser(ctx context.Context, dep dependency.Dep, config *Config, issuer string, identity *claims) (*ent.User, error) {
	if err := validateClaims(config, identity); err != nil {
		return nil, err
	}

	userClient := dep.UserClient()
	loadGroupCtx := context.WithValue(ctx, inventory.LoadUserGroup{}, true)
	identityKey := identitySettingKey(issuer, identity.Subject)
	if binding, err := dep.SettingClient().Get(ctx, identityKey); err == nil {
		uid, parseErr := strconv.Atoi(binding)
		if parseErr == nil {
			u, getErr := userClient.GetByID(loadGroupCtx, uid)
			if getErr == nil {
				return activeUser(u)
			}
		}
		_, _ = dep.DBClient().Setting.Delete().Where(entsetting.Name(identityKey)).Exec(ctx)
	}

	email := strings.ToLower(strings.TrimSpace(identity.Email))
	u, err := userClient.GetByEmail(loadGroupCtx, email)
	if err != nil {
		nick := strings.TrimSpace(identity.Name)
		if nick == "" {
			nick = strings.TrimSpace(identity.PreferredUsername)
		}
		u, err = userClient.Create(ctx, &inventory.NewUserArgs{
			Email:   email,
			Nick:    nick,
			Status:  entuser.StatusActive,
			GroupID: dep.SettingProvider().DefaultGroup(ctx),
			Avatar:  identity.Picture,
		})
		if err != nil {
			createErr := err
			u, err = userClient.GetByEmail(loadGroupCtx, email)
			if err != nil {
				return nil, fmt.Errorf("failed to create OIDC user: %w", createErr)
			}
		}
	}
	if u == nil {
		return nil, errors.New("failed to resolve OIDC user")
	}
	if _, err := activeUser(u); err != nil {
		return nil, err
	}

	if err := dep.DBClient().Setting.Create().
		SetName(identityKey).
		SetValue(strconv.Itoa(u.ID)).
		OnConflict(entsql.ConflictColumns(entsetting.FieldName)).
		UpdateValue().
		Exec(ctx); err != nil {
		return nil, fmt.Errorf("failed to save OIDC identity binding: %w", err)
	}
	return userClient.GetActiveByID(loadGroupCtx, u.ID)
}

func validateClaims(config *Config, identity *claims) error {
	if identity.Subject == "" || strings.TrimSpace(identity.Email) == "" {
		return errors.New("OIDC subject and email claims are required")
	}
	if config.RequireVerifiedEmail && (identity.EmailVerified == nil || !*identity.EmailVerified) {
		return errors.New("OIDC provider did not verify the email address")
	}
	return nil
}

func mergeClaims(identity, additional *claims) error {
	if additional.Subject != "" && additional.Subject != identity.Subject {
		return errors.New("subject mismatch")
	}
	if identity.Email != "" && additional.Email != "" && !strings.EqualFold(identity.Email, additional.Email) {
		return errors.New("email mismatch")
	}
	if identity.Email == "" {
		identity.Email = additional.Email
	}
	if identity.EmailVerified == nil {
		identity.EmailVerified = additional.EmailVerified
	}
	if identity.Name == "" {
		identity.Name = additional.Name
	}
	if identity.PreferredUsername == "" {
		identity.PreferredUsername = additional.PreferredUsername
	}
	if identity.Picture == "" {
		identity.Picture = additional.Picture
	}
	return nil
}

func activeUser(u *ent.User) (*ent.User, error) {
	switch u.Status {
	case entuser.StatusActive:
		return u, nil
	case entuser.StatusInactive:
		return nil, errors.New("Cloudreve account is inactive")
	default:
		return nil, errors.New("Cloudreve account is blocked")
	}
}

func identitySettingKey(issuer, subject string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return identityPrefix + hex.EncodeToString(digest[:])
}
