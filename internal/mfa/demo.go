package mfa

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var web embed.FS

const demoCookieName = "myscoutee_2fa_demo"

func identityTrialCookieName(method string) string { return "myscoutee_2fa_" + method + "_trial" }

func (s *Server) setIdentityTrial(w http.ResponseWriter, method string, complete bool) {
	value, maxAge := "", -1
	if complete {
		value = base64.RawURLEncoding.EncodeToString(s.demoSignature("identity-trial:" + method))
		maxAge = 3600
	}
	http.SetCookie(w, &http.Cookie{Name: identityTrialCookieName(method), Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: strings.HasPrefix(s.config.RPOrigin, "https://"), SameSite: http.SameSiteLaxMode})
}

func (s *Server) identityTrialStatus(r *http.Request, method string, enabled bool) string {
	if !enabled {
		return "Unavailable"
	}
	cookie, err := r.Cookie(identityTrialCookieName(method))
	if err != nil {
		return "Not tried"
	}
	want := s.demoSignature("identity-trial:" + method)
	got, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err == nil && hmac.Equal(got, want) {
		return "Completed"
	}
	return "Not tried"
}

func (s *Server) demoHostMatches(r *http.Request) bool {
	origin, err := url.Parse(s.config.RPOrigin)
	return err == nil && r.Host == origin.Host
}

func (s *Server) demoSignature(payload string) []byte {
	mac := hmac.New(sha256.New, s.tokenHash[:])
	_, _ = mac.Write([]byte("demo-session:" + payload))
	return mac.Sum(nil)
}

func (s *Server) setDemoSession(w http.ResponseWriter) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	payload := strconv.FormatInt(s.now().Add(time.Hour).Unix(), 10) + ":" + base64.RawURLEncoding.EncodeToString(nonce)
	value := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(s.demoSignature(payload))
	http.SetCookie(w, &http.Cookie{Name: demoCookieName, Value: value, Path: "/v1", MaxAge: 3600, HttpOnly: true, Secure: strings.HasPrefix(s.config.RPOrigin, "https://"), SameSite: http.SameSiteStrictMode})
	return nil
}

func (s *Server) validDemoSession(r *http.Request) bool {
	if !s.config.DemoEnabled || !s.demoHostMatches(r) {
		return false
	}
	cookie, err := r.Cookie(demoCookieName)
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, s.demoSignature(string(raw))) {
		return false
	}
	fields := strings.Split(string(raw), ":")
	if len(fields) != 2 {
		return false
	}
	expires, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || expires < s.now().Unix() {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(fields[1])
	return err == nil && len(nonce) == 16
}

func (s *Server) serveDemo(w http.ResponseWriter, r *http.Request) {
	if !s.demoHostMatches(r) {
		problem(w, http.StatusForbidden, "demo origin denied")
		return
	}
	if err := s.setDemoSession(w); err != nil {
		problem(w, http.StatusInternalServerError, "demo session unavailable")
		return
	}
	b, _ := web.ReadFile("web/index.html")
	oidcSection := []byte(`<article class="method-card"><div class="card-title"><span class="method-icon">OIDC</span><div><h3>OpenID Connect</h3><p>Authorization code with PKCE, state, and nonce.</p></div></div><p>Sign in with the local Keycloak test account. The result shows the verified provider identity.</p><a class="button" href="/lab/oidc/start">Try OIDC sign-in</a></article>`)
	if s.config.OIDCIssuer == "" {
		oidcSection = []byte(`<article class="method-card muted-card"><h3>OpenID Connect</h3><p>Start the optional Keycloak identity stack to enable this test.</p></article>`)
	}
	b = bytes.Replace(b, []byte("<!-- OIDC_LAB -->"), oidcSection, 1)
	samlSection := []byte(`<article class="method-card"><div class="card-title"><span class="method-icon">SAML</span><div><h3>SAML 2.0</h3><p>Signed assertion from the local Keycloak identity provider.</p></div></div><p>Sign in with the local Keycloak test account and inspect the validated identity.</p><div class="actions"><a class="button" href="/lab/saml/result">Try SAML sign-in</a><a class="button orange" href="/lab/saml/metadata" download="myscoutee-2fa-sp-metadata.xml">Download SP metadata XML</a></div><div class="metadata-help"><h4>Service Provider (SP) metadata</h4><p>Import the downloaded XML into another SAML identity provider if it requests an SP metadata file. The bundled Keycloak is already configured, so no upload is needed for this test.</p></div></article>`)
	if s.saml == nil {
		samlSection = []byte(`<article class="method-card muted-card"><h3>SAML 2.0</h3><p>Start the optional Keycloak identity stack to enable this test.</p></article>`)
	}
	b = bytes.Replace(b, []byte("<!-- SAML_LAB -->"), samlSection, 1)
	b = bytes.Replace(b, []byte("<!-- OIDC_STATUS -->"), []byte(s.identityTrialStatus(r, "oidc", s.config.OIDCIssuer != "")), 1)
	b = bytes.Replace(b, []byte("<!-- SAML_STATUS -->"), []byte(s.identityTrialStatus(r, "saml", s.saml != nil)), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func serveAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/assets/demo.js":
		b, _ := web.ReadFile("web/demo.js")
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(b)
	case "/assets/demo.css":
		b, _ := web.ReadFile("web/demo.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(b)
	case "/assets/logo.png":
		b, _ := web.ReadFile("web/logo.png")
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}
