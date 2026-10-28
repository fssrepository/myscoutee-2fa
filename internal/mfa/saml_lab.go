package mfa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/crewjam/saml/samlsp"
)

type samlLab struct {
	mu         sync.Mutex
	middleware *samlsp.Middleware
}

type hostOnlyTracker struct{ samlsp.CookieRequestTracker }

func (t hostOnlyTracker) StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error {
	_, err := r.Cookie(t.NamePrefix + index)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: t.NamePrefix + index, Value: "", Path: t.ServiceProvider.AcsURL.Path, MaxAge: -1, HttpOnly: true, Secure: t.ServiceProvider.AcsURL.Scheme == "https", SameSite: t.SameSite})
	return nil
}

func (s *Server) samlMiddleware(r *http.Request) (*samlsp.Middleware, error) {
	s.saml.mu.Lock()
	defer s.saml.mu.Unlock()
	if s.saml.middleware != nil {
		return s.saml.middleware, nil
	}
	metadataURL, err := url.Parse(s.config.SAMLIDPMetadataURL)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	metadata, err := samlsp.FetchMetadata(r.Context(), client, *metadataURL)
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	certificateTemplate := &x509.Certificate{
		SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(s.config.RPOrigin + "/lab/")
	if err != nil {
		return nil, err
	}
	middleware, err := samlsp.New(samlsp.Options{
		URL: *base, Key: key, Certificate: cert, IDPMetadata: metadata,
		DefaultRedirectURI: "/lab/saml/result", CookieSameSite: http.SameSiteLaxMode,
	})
	if err != nil {
		return nil, err
	}
	session, ok := middleware.Session.(samlsp.CookieSessionProvider)
	if !ok {
		return nil, errors.New("unexpected SAML session provider")
	}
	session.Domain = ""
	session.Name = "myscoutee_2fa_saml_session"
	session.Path = "/lab/saml"
	middleware.Session = session
	tracker, ok := middleware.RequestTracker.(samlsp.CookieRequestTracker)
	if !ok {
		return nil, errors.New("unexpected SAML request tracker")
	}
	middleware.RequestTracker = hostOnlyTracker{tracker}
	middleware.OnError = func(w http.ResponseWriter, _ *http.Request, _ error) { problem(w, 400, "SAML response invalid") }
	s.saml.middleware = middleware
	return middleware, nil
}

var samlResult = template.Must(template.New("result").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SAML result · MyScoutee 2FA Lab</title><link rel="stylesheet" href="/assets/demo.css"></head><body><main class="app-shell"><article class="method-card"><p class="eyebrow">Identity protocols</p><h1>SAML sign-in succeeded</h1><p>The Go service provider verified the signed response from the identity provider and matched the earlier request.</p><dl><dt>Subject</dt><dd><code>{{.Subject}}</code></dd><dt>Email attribute</dt><dd>{{.Email}}</dd></dl><p>This is an identity demonstration. It does not create a MyScoutee session or make a 2FA decision.</p><a class="button" href="/">Back to the lab</a></article></main></body></html>`))

func (s *Server) handleSAML(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/lab/saml/metadata", "/lab/saml/result":
		if r.Method != http.MethodGet {
			problem(w, 405, "method not allowed")
			return
		}
	case "/lab/saml/acs":
		if r.Method != http.MethodPost {
			problem(w, 405, "method not allowed")
			return
		}
	default:
		problem(w, 404, "not found")
		return
	}
	middleware, err := s.samlMiddleware(r)
	if err != nil {
		problem(w, 503, "identity provider unavailable")
		return
	}
	if r.URL.Path == "/lab/saml/metadata" {
		w.Header().Set("Content-Disposition", `attachment; filename="myscoutee-2fa-sp-metadata.xml"`)
		w.Header().Set("Cache-Control", "no-store")
	}
	if r.URL.Path != "/lab/saml/result" {
		middleware.ServeHTTP(w, r)
		return
	}
	middleware.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var subject, email string
		if claims, ok := samlsp.SessionFromContext(r.Context()).(samlsp.JWTSessionClaims); ok {
			subject = claims.Subject
			email = claims.Attributes.Get("email")
		}
		s.setIdentityTrial(w, "saml", true)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = samlResult.Execute(w, struct{ Subject, Email string }{subject, email})
	})).ServeHTTP(w, r)
}
