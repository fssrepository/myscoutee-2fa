package mfa

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const oidcCookie = "myscoutee_2fa_oidc_flow"

func (s *Server) localKeycloakLogoutURL() string {
	if s.config.OIDCIssuer != "http://localhost:18084/realms/myscoutee-2fa-lab" || s.config.OIDCClientID != "myscoutee-2fa-lab" || s.config.RPOrigin != "http://localhost:18083" {
		return ""
	}
	return s.config.RPOrigin + "/lab/oidc/logout"
}

func (s *Server) keycloakEndSessionURL(idToken string) string {
	logout, _ := url.Parse(s.config.OIDCIssuer + "/protocol/openid-connect/logout")
	query := logout.Query()
	query.Set("client_id", s.config.OIDCClientID)
	query.Set("id_token_hint", idToken)
	query.Set("post_logout_redirect_uri", s.config.RPOrigin+"/")
	logout.RawQuery = query.Encode()
	return logout.String()
}

type oidcFlow struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Purpose  string `json:"purpose,omitempty"`
	Expires  int64  `json:"expires"`
}

type oidcBackchannel struct {
	transport      http.RoundTripper
	publicOrigin   string
	internalOrigin string
}

func (t oidcBackchannel) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.internalOrigin == "" || r.URL.Scheme+"://"+r.URL.Host != t.publicOrigin {
		return t.transport.RoundTrip(r)
	}
	copy := r.Clone(r.Context())
	u := *r.URL
	target, _ := url.Parse(t.internalOrigin)
	u.Scheme, u.Host = target.Scheme, target.Host
	copy.URL = &u
	copy.Host = ""
	return t.transport.RoundTrip(copy)
}

func (s *Server) oidcClient() *http.Client {
	issuer, _ := url.Parse(s.config.OIDCIssuer)
	return &http.Client{
		Timeout:       8 * time.Second,
		Transport:     oidcBackchannel{transport: http.DefaultTransport, publicOrigin: issuer.Scheme + "://" + issuer.Host, internalOrigin: s.config.OIDCBackchannelOrigin},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (s *Server) oidcSetup(ctx context.Context) (*oidc.Provider, oauth2.Config, context.Context, error) {
	client := s.oidcClient()
	ctx = oidc.ClientContext(ctx, client)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	provider, err := oidc.NewProvider(ctx, s.config.OIDCIssuer)
	if err != nil {
		return nil, oauth2.Config{}, ctx, err
	}
	return provider, oauth2.Config{
		ClientID:     s.config.OIDCClientID,
		ClientSecret: s.config.OIDCClientSecret,
		RedirectURL:  s.config.OIDCRedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
	}, ctx, nil
}

func (s *Server) setOIDCCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: value, Path: "/lab/oidc", MaxAge: maxAge, HttpOnly: true, Secure: strings.HasPrefix(s.config.RPOrigin, "https://"), SameSite: http.SameSiteLaxMode})
}

func (s *Server) startOIDC(w http.ResponseWriter, r *http.Request) {
	s.startOIDCFlow(w, r, "signin")
}

func (s *Server) startOIDCLogout(w http.ResponseWriter, r *http.Request) {
	if s.localKeycloakLogoutURL() == "" {
		problem(w, 404, "not found")
		return
	}
	s.startOIDCFlow(w, r, "logout")
}

func (s *Server) startOIDCFlow(w http.ResponseWriter, r *http.Request, purpose string) {
	_, config, _, err := s.oidcSetup(r.Context())
	if err != nil {
		problem(w, 503, "identity provider unavailable")
		return
	}
	state, err := randomID(24)
	if err != nil {
		problem(w, 500, "identity flow failed")
		return
	}
	nonce, err := randomID(24)
	if err != nil {
		problem(w, 500, "identity flow failed")
		return
	}
	flow := oidcFlow{State: state, Nonce: nonce, Verifier: oauth2.GenerateVerifier(), Purpose: purpose, Expires: time.Now().Add(5 * time.Minute).Unix()}
	raw, err := json.Marshal(flow)
	if err != nil {
		problem(w, 500, "identity flow failed")
		return
	}
	sealed, err := s.Store.seal(raw)
	if err != nil {
		problem(w, 500, "identity flow failed")
		return
	}
	s.setOIDCCookie(w, base64.RawURLEncoding.EncodeToString(sealed), 300)
	w.Header().Set("Cache-Control", "no-store")
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(flow.Verifier), oauth2.SetAuthURLParam("nonce", nonce)}
	if purpose == "logout" {
		options = append(options, oauth2.SetAuthURLParam("prompt", "none"))
	}
	http.Redirect(w, r, config.AuthCodeURL(state, options...), http.StatusFound)
}

var oidcResult = template.Must(template.New("result").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OIDC result · MyScoutee 2FA Lab</title><link rel="stylesheet" href="/assets/demo.css"></head><body><main class="app-shell"><article class="method-card"><p class="eyebrow">Identity protocols</p><h1>OIDC sign-in succeeded</h1><p>The Go service verified the provider's ID token signature, issuer, audience, expiry, and nonce.</p><dl><dt>Issuer</dt><dd><code>{{.Issuer}}</code></dd><dt>Subject</dt><dd><code>{{.Subject}}</code></dd><dt>Username</dt><dd>{{.Username}}</dd><dt>Email</dt><dd>{{.Email}}</dd></dl><p>This is an identity demonstration. It does not create a MyScoutee session or make a 2FA decision.</p><a class="button" href="/">Back to the lab</a></article></main></body></html>`))

func (s *Server) finishOIDC(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(oidcCookie)
	s.setOIDCCookie(w, "", -1)
	if err != nil {
		problem(w, 400, "identity flow missing or expired")
		return
	}
	sealed, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		problem(w, 400, "identity flow invalid")
		return
	}
	raw, err := s.Store.open(sealed)
	if err != nil {
		problem(w, 400, "identity flow invalid")
		return
	}
	var flow oidcFlow
	if json.Unmarshal(raw, &flow) != nil || time.Now().Unix() > flow.Expires || flow.State == "" || subtle.ConstantTimeCompare([]byte(flow.State), []byte(r.URL.Query().Get("state"))) != 1 {
		problem(w, 400, "identity flow invalid")
		return
	}
	if flow.Purpose != "signin" && flow.Purpose != "logout" {
		problem(w, 400, "identity flow invalid")
		return
	}
	if flow.Purpose == "logout" && (r.URL.Query().Get("error") == "login_required" || r.URL.Query().Get("error") == "interaction_required") {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" || len(code) > 4096 {
		problem(w, 400, "identity code missing")
		return
	}
	provider, config, ctx, err := s.oidcSetup(r.Context())
	if err != nil {
		problem(w, 503, "identity provider unavailable")
		return
	}
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		problem(w, 400, "identity exchange failed")
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		problem(w, 400, "identity token missing")
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: s.config.OIDCClientID}).Verify(ctx, rawID)
	if err != nil || subtle.ConstantTimeCompare([]byte(idTokenNonce(idToken)), []byte(flow.Nonce)) != 1 {
		problem(w, 400, "identity token invalid")
		return
	}
	var claims struct {
		Email    string `json:"email"`
		Username string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		problem(w, 400, "identity claims invalid")
		return
	}
	if flow.Purpose == "logout" {
		http.Redirect(w, r, s.keycloakEndSessionURL(rawID), http.StatusFound)
		return
	}
	s.setIdentityTrial(w, "oidc", true)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = oidcResult.Execute(w, struct{ Issuer, Subject, Username, Email string }{idToken.Issuer, idToken.Subject, claims.Username, claims.Email})
}

func idTokenNonce(token *oidc.IDToken) string {
	if token == nil {
		return ""
	}
	return token.Nonce
}
