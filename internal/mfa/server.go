package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

type Config struct {
	Token, RPID, RPOrigin, RPName                                                      string
	DemoEnabled                                                                        bool
	OIDCIssuer, OIDCClientID, OIDCClientSecret, OIDCRedirectURL, OIDCBackchannelOrigin string
	SAMLIDPMetadataURL                                                                 string
}
type Server struct {
	Store     *Store
	config    Config
	webauthn  *webauthn.WebAuthn
	tokenHash [32]byte
	now       func() time.Time
	saml      *samlLab
}

var userIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:@-]{1,128}$`)
var codePattern = regexp.MustCompile(`^[0-9]{6}$`)

func NewServer(store *Store, c Config) (*Server, error) {
	if len(c.Token) < 32 {
		return nil, errors.New("MFA_API_TOKEN must have at least 32 characters")
	}
	if c.RPID == "" || c.RPOrigin == "" {
		return nil, errors.New("MFA_RP_ID and MFA_RP_ORIGIN are required")
	}
	if c.RPName == "" {
		c.RPName = "MyScoutee"
	}
	if c.OIDCIssuer != "" || c.OIDCClientID != "" || c.OIDCRedirectURL != "" || c.OIDCBackchannelOrigin != "" {
		issuer, issuerErr := url.Parse(c.OIDCIssuer)
		backchannel, backchannelErr := url.Parse(c.OIDCBackchannelOrigin)
		if !c.DemoEnabled || c.OIDCIssuer == "" || c.OIDCClientID == "" || issuerErr != nil || issuer.Host == "" || (issuer.Scheme != "https" && !(issuer.Scheme == "http" && (issuer.Hostname() == "localhost" || issuer.Hostname() == "127.0.0.1"))) || c.OIDCRedirectURL != strings.TrimRight(c.RPOrigin, "/")+"/lab/oidc/callback" {
			return nil, errors.New("OIDC lab requires demo mode, a valid issuer and client ID, and the RP-origin callback URL")
		}
		if c.OIDCBackchannelOrigin != "" && (backchannelErr != nil || backchannel.Host == "" || (backchannel.Scheme != "https" && backchannel.Scheme != "http") || backchannel.Path != "" || backchannel.RawQuery != "") {
			return nil, errors.New("MFA_OIDC_BACKCHANNEL_ORIGIN must be an HTTP(S) origin")
		}
	}
	if c.SAMLIDPMetadataURL != "" {
		metadata, err := url.Parse(c.SAMLIDPMetadataURL)
		if !c.DemoEnabled || err != nil || metadata.Host == "" || (metadata.Scheme != "https" && metadata.Scheme != "http") {
			return nil, errors.New("SAML lab requires demo mode and an HTTP(S) IdP metadata URL")
		}
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: c.RPID, RPOrigins: []string{c.RPOrigin}, RPDisplayName: c.RPName, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}})
	if err != nil {
		return nil, err
	}
	server := &Server{Store: store, config: c, webauthn: wa, tokenHash: sha256.Sum256([]byte(c.Token)), now: time.Now}
	if c.SAMLIDPMetadataURL != "" {
		server.saml = &samlLab{}
	}
	return server, nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func decode(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values")
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'")
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if s.config.DemoEnabled && r.Method == http.MethodGet && r.URL.Path == "/" {
		s.serveDemo(w, r)
		return
	}
	if s.config.DemoEnabled && strings.HasPrefix(r.URL.Path, "/assets/") && r.Method == http.MethodGet {
		serveAsset(w, r)
		return
	}
	if s.config.DemoEnabled && s.config.OIDCIssuer != "" && s.config.OIDCClientID != "" && r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/lab/oidc/start":
			s.startOIDC(w, r)
			return
		case "/lab/oidc/logout":
			s.startOIDCLogout(w, r)
			return
		case "/lab/oidc/callback":
			s.finishOIDC(w, r)
			return
		}
	}
	if s.saml != nil && strings.HasPrefix(r.URL.Path, "/lab/saml/") {
		s.handleSAML(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		problem(w, 404, "not found")
		return
	}
	authorization := r.Header.Get("Authorization")
	authorized := false
	demoAuthorized := false
	if authorization != "" {
		bearer := strings.TrimPrefix(authorization, "Bearer ")
		incoming := sha256.Sum256([]byte(bearer))
		authorized = strings.HasPrefix(authorization, "Bearer ") && bearer != "" && subtle.ConstantTimeCompare(incoming[:], s.tokenHash[:]) == 1
	} else {
		demoAuthorized = s.validDemoSession(r)
		authorized = demoAuthorized
	}
	if !authorized {
		problem(w, 401, "unauthorized")
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != s.config.RPOrigin {
		problem(w, 403, "origin denied")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "users" || !userIDPattern.MatchString(parts[2]) {
		problem(w, 404, "not found")
		return
	}
	uid := parts[2]
	if demoAuthorized && uid != "demo" {
		problem(w, 403, "demo user only")
		return
	}
	action := strings.Join(parts[3:], "/")
	switch {
	case r.Method == "GET" && action == "factors":
		s.factors(w, r, uid)
	case r.Method == "DELETE" && action == "lab-reset" && uid == "demo":
		s.resetDemoUser(w, r, uid)
	case r.Method == "POST" && action == "totp/enrollment":
		s.startTOTP(w, r, uid)
	case r.Method == "POST" && action == "totp/confirm":
		s.confirmTOTP(w, r, uid)
	case r.Method == "POST" && action == "hotp/enrollment":
		s.startHOTP(w, r, uid)
	case r.Method == "POST" && action == "hotp/confirm":
		s.confirmHOTP(w, r, uid)
	case r.Method == "POST" && action == "verify":
		s.verify(w, r, uid)
	case r.Method == "POST" && action == "recovery-codes/rotate":
		s.rotateCodes(w, r, uid)
	case r.Method == "POST" && action == "passkeys/register/begin":
		s.beginPasskey(w, r, uid, "register")
	case r.Method == "POST" && action == "passkeys/register/finish":
		s.finishPasskey(w, r, uid, "register")
	case r.Method == "POST" && action == "passkeys/authenticate/begin":
		s.beginPasskey(w, r, uid, "authenticate")
	case r.Method == "POST" && action == "passkeys/authenticate/finish":
		s.finishPasskey(w, r, uid, "authenticate")
	case r.Method == "DELETE" && strings.HasPrefix(action, "passkeys/"):
		s.deletePasskey(w, r, uid, strings.TrimPrefix(action, "passkeys/"))
	default:
		problem(w, 404, "not found")
	}
}
func (s *Server) resetDemoUser(w http.ResponseWriter, r *http.Request, uid string) {
	if !s.validDemoSession(r) {
		problem(w, 403, "demo session required")
		return
	}
	tx, err := s.Store.db.BeginTx(r.Context(), nil)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `DELETE FROM users WHERE id=?`, uid); err != nil {
		problem(w, 500, "storage error")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `DELETE FROM attempts WHERE user_id=?`, uid); err != nil {
		problem(w, 500, "storage error")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "storage error")
		return
	}
	s.setOIDCCookie(w, "", -1)
	http.SetCookie(w, &http.Cookie{Name: "myscoutee_2fa_saml_session", Value: "", Path: "/lab/saml", MaxAge: -1, HttpOnly: true})
	s.setIdentityTrial(w, "oidc", false)
	s.setIdentityTrial(w, "saml", false)
	writeJSON(w, 200, map[string]any{"deleted": true, "logout_url": s.localKeycloakLogoutURL()})
}
func (s *Server) factors(w http.ResponseWriter, r *http.Request, uid string) {
	var active bool
	var hotpActive bool
	var count int
	err := s.Store.db.QueryRowContext(r.Context(), `SELECT totp_secret IS NOT NULL FROM users WHERE id=?`, uid).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, 200, map[string]any{"totp": false, "hotp": false, "passkeys": []any{}, "recovery_codes_remaining": 0})
		return
	}
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	if err = s.Store.db.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM hotp WHERE user_id=? AND secret IS NOT NULL)`, uid).Scan(&hotpActive); err != nil {
		problem(w, 500, "storage error")
		return
	}
	rows, err := s.Store.db.QueryContext(r.Context(), `SELECT id,created_at FROM credentials WHERE user_id=? ORDER BY created_at`, uid)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	defer rows.Close()
	keys := []map[string]any{}
	for rows.Next() {
		var id string
		var ts int64
		if rows.Scan(&id, &ts) != nil {
			problem(w, 500, "storage error")
			return
		}
		keys = append(keys, map[string]any{"id": id, "created_at": time.Unix(ts, 0).UTC().Format(time.RFC3339)})
	}
	if rows.Err() != nil {
		problem(w, 500, "storage error")
		return
	}
	count, err = s.Store.remainingCodes(r.Context(), uid)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	writeJSON(w, 200, map[string]any{"totp": active, "hotp": hotpActive, "passkeys": keys, "recovery_codes_remaining": count})
}
func (s *Server) startTOTP(w http.ResponseWriter, r *http.Request, uid string) {
	if _, err := s.Store.ensureUser(r.Context(), uid); err != nil {
		problem(w, 500, "storage error")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.config.RPName, AccountName: uid, SecretSize: 20, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		problem(w, 500, "enrollment failed")
		return
	}
	sealed, err := s.Store.seal([]byte(key.Secret()))
	if err != nil {
		problem(w, 500, "enrollment failed")
		return
	}
	if _, err = s.Store.db.ExecContext(r.Context(), `UPDATE users SET pending_secret=?,pending_at=? WHERE id=?`, sealed, time.Now().Unix(), uid); err != nil {
		problem(w, 500, "storage error")
		return
	}
	writeProvisioning(w, key)
}
func writeProvisioning(w http.ResponseWriter, key *otp.Key) {
	img, err := key.Image(200, 200)
	if err != nil {
		problem(w, 500, "QR generation failed")
		return
	}
	var out bytes.Buffer
	if err = png.Encode(&out, img); err != nil {
		problem(w, 500, "QR generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"secret": key.Secret(), "otpauth_url": key.URL(), "qr_png_data_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(out.Bytes()), "expires_in_seconds": 600})
}
func (s *Server) startHOTP(w http.ResponseWriter, r *http.Request, uid string) {
	if _, err := s.Store.ensureUser(r.Context(), uid); err != nil {
		problem(w, 500, "storage error")
		return
	}
	key, err := hotp.Generate(hotp.GenerateOpts{Issuer: s.config.RPName, AccountName: uid, SecretSize: 20, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		problem(w, 500, "enrollment failed")
		return
	}
	// The library omits the HOTP counter, but authenticator provisioning requires it.
	key, err = otp.NewKeyFromURL(key.URL() + "&counter=0")
	if err != nil {
		problem(w, 500, "enrollment failed")
		return
	}
	sealed, err := s.Store.seal([]byte(key.Secret()))
	if err != nil {
		problem(w, 500, "enrollment failed")
		return
	}
	_, err = s.Store.db.ExecContext(r.Context(), `INSERT INTO hotp(user_id,pending_secret,pending_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET pending_secret=excluded.pending_secret,pending_at=excluded.pending_at`, uid, sealed, time.Now().Unix())
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	writeProvisioning(w, key)
}
func (s *Server) confirmHOTP(w http.ResponseWriter, r *http.Request, uid string) {
	var body struct {
		Code string `json:"code"`
	}
	if decode(r, &body) != nil || !codePattern.MatchString(body.Code) {
		problem(w, 400, "six-digit code required")
		return
	}
	allowed, err := s.allowAttempt(r.Context(), uid)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	if !allowed {
		problem(w, 429, "too many attempts; retry in one minute")
		return
	}
	tx, err := s.Store.db.BeginTx(r.Context(), nil)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	defer tx.Rollback()
	var sealed []byte
	var at int64
	err = tx.QueryRowContext(r.Context(), `SELECT pending_secret,pending_at FROM hotp WHERE user_id=?`, uid).Scan(&sealed, &at)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(w, 500, "storage error")
		return
	}
	if errors.Is(err, sql.ErrNoRows) || len(sealed) == 0 || time.Now().Unix()-at > 600 {
		problem(w, 400, "no active enrollment")
		return
	}
	secret, err := s.Store.open(sealed)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	// An app may display or advance a few counter values while enrollment is open.
	// Use the same bounded look-ahead as normal HOTP verification.
	acceptedCounter := int64(-1)
	for candidate := int64(0); candidate < 10; candidate++ {
		if hotp.Validate(body.Code, uint64(candidate), string(secret)) {
			acceptedCounter = candidate
			break
		}
	}
	if acceptedCounter < 0 {
		problem(w, 400, "invalid code")
		return
	}
	codes, err := newRecoveryCodes()
	if err != nil {
		problem(w, 500, "code generation failed")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE hotp SET secret=pending_secret,pending_secret=NULL,pending_at=0,counter=? WHERE user_id=?`, acceptedCounter+1, uid); err != nil {
		problem(w, 500, "storage error")
		return
	}
	if err = replaceCodes(r.Context(), tx, uid, codes); err != nil {
		problem(w, 500, "storage error")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "storage error")
		return
	}
	_, _ = s.Store.db.ExecContext(r.Context(), `DELETE FROM attempts WHERE user_id=?`, uid)
	writeJSON(w, 200, map[string]any{"enabled": true, "recovery_codes": codes})
}
func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request, uid string) {
	var body struct {
		Code string `json:"code"`
	}
	if decode(r, &body) != nil || !codePattern.MatchString(body.Code) {
		problem(w, 400, "six-digit code required")
		return
	}
	allowed, err := s.allowAttempt(r.Context(), uid)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	if !allowed {
		problem(w, 429, "too many attempts; retry in one minute")
		return
	}
	tx, err := s.Store.db.BeginTx(r.Context(), nil)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	defer tx.Rollback()
	var sealed []byte
	var at int64
	err = tx.QueryRowContext(r.Context(), `SELECT pending_secret,pending_at FROM users WHERE id=?`, uid).Scan(&sealed, &at)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(w, 500, "storage error")
		return
	}
	if errors.Is(err, sql.ErrNoRows) || len(sealed) == 0 || time.Now().Unix()-at > 600 {
		problem(w, 400, "no active enrollment")
		return
	}
	secret, err := s.Store.open(sealed)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	step, ok := matchTOTP(body.Code, string(secret), -1, s.now())
	if !ok {
		problem(w, 400, "invalid code")
		return
	}
	codes, err := newRecoveryCodes()
	if err != nil {
		problem(w, 500, "code generation failed")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE users SET totp_secret=pending_secret,pending_secret=NULL,pending_at=0,last_step=? WHERE id=?`, step, uid); err != nil {
		problem(w, 500, "storage error")
		return
	}
	if err = replaceCodes(r.Context(), tx, uid, codes); err != nil {
		problem(w, 500, "storage error")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "storage error")
		return
	}
	_, _ = s.Store.db.ExecContext(r.Context(), `DELETE FROM attempts WHERE user_id=?`, uid)
	writeJSON(w, 200, map[string]any{"enabled": true, "recovery_codes": codes})
}
func matchTOTP(code, secret string, last int64, now time.Time) (int64, bool) {
	current := now.Unix() / 30
	for _, step := range []int64{current, current - 1, current + 1} {
		if step <= last || step < 0 {
			continue
		}
		candidate, err := totp.GenerateCode(secret, time.Unix(step*30, 0))
		if err == nil && subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
func (s *Server) verify(w http.ResponseWriter, r *http.Request, uid string) {
	var body struct {
		Method string `json:"method"`
		Code   string `json:"code"`
	}
	if decode(r, &body) != nil {
		problem(w, 400, "invalid JSON")
		return
	}
	if body.Method != "totp" && body.Method != "hotp" && body.Method != "recovery_code" {
		problem(w, 400, "unknown method")
		return
	}
	if (body.Method == "totp" || body.Method == "hotp") && !codePattern.MatchString(body.Code) {
		problem(w, 400, "six-digit code required")
		return
	}
	if body.Method == "recovery_code" {
		body.Code = normalizeRecovery(body.Code)
		if len(body.Code) != 32 {
			problem(w, 400, "invalid recovery code")
			return
		}
	}
	allowed, err := s.allowAttempt(r.Context(), uid)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	if !allowed {
		problem(w, 429, "too many attempts; retry in one minute")
		return
	}
	valid := false
	if body.Method == "totp" {
		valid, err = s.verifyTOTP(r.Context(), uid, body.Code)
	} else if body.Method == "hotp" {
		valid, err = s.verifyHOTP(r.Context(), uid, body.Code)
	} else {
		valid, err = s.verifyRecovery(r.Context(), uid, body.Code)
	}
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	if valid {
		_, _ = s.Store.db.ExecContext(r.Context(), `DELETE FROM attempts WHERE user_id=?`, uid)
	}
	writeJSON(w, 200, map[string]bool{"valid": valid})
}
func (s *Server) verifyHOTP(ctx context.Context, uid, code string) (bool, error) {
	tx, err := s.Store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var sealed []byte
	var counter int64
	err = tx.QueryRowContext(ctx, `SELECT secret,counter FROM hotp WHERE user_id=?`, uid).Scan(&sealed, &counter)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(sealed) == 0 {
		return false, nil
	}
	secret, err := s.Store.open(sealed)
	if err != nil {
		return false, err
	}
	// A small look-ahead allows an authenticator to advance without contacting the service.
	for next := counter; next < counter+10; next++ {
		if !hotp.Validate(code, uint64(next), string(secret)) {
			continue
		}
		result, err := tx.ExecContext(ctx, `UPDATE hotp SET counter=? WHERE user_id=? AND counter=?`, next+1, uid, counter)
		if err != nil {
			return false, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return false, err
		}
		if n != 1 {
			return false, nil
		}
		return true, tx.Commit()
	}
	return false, nil
}
func (s *Server) allowAttempt(ctx context.Context, uid string) (bool, error) {
	now := time.Now().Unix()
	tx, err := s.Store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var start int64
	var count int
	err = tx.QueryRowContext(ctx, `SELECT started_at,count FROM attempts WHERE user_id=?`, uid).Scan(&start, &count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if now-start >= 60 {
		start = now
		count = 0
	}
	if count >= 5 {
		return false, nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO attempts(user_id,started_at,count) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET started_at=excluded.started_at,count=excluded.count`, uid, start, count+1)
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}
func (s *Server) verifyTOTP(ctx context.Context, uid, code string) (bool, error) {
	tx, err := s.Store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var sealed []byte
	var last int64
	err = tx.QueryRowContext(ctx, `SELECT totp_secret,last_step FROM users WHERE id=?`, uid).Scan(&sealed, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(sealed) == 0 {
		return false, nil
	}
	secret, err := s.Store.open(sealed)
	if err != nil {
		return false, err
	}
	step, ok := matchTOTP(code, string(secret), last, s.now())
	if !ok {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET last_step=? WHERE id=? AND last_step<?`, step, uid, step)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, nil
	}
	return true, tx.Commit()
}
func (s *Server) verifyRecovery(ctx context.Context, uid, code string) (bool, error) {
	result, err := s.Store.db.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=? AND hash=?`, uid, codeHash(code))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}
func normalizeRecovery(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", ""))
}
func newRecoveryCodes() ([]string, error) {
	codes := make([]string, 10)
	for i := range codes {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		hex := fmt.Sprintf("%X", raw)
		codes[i] = hex[:8] + "-" + hex[8:16] + "-" + hex[16:24] + "-" + hex[24:]
	}
	return codes, nil
}
func replaceCodes(ctx context.Context, tx *sql.Tx, uid string, codes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, uid); err != nil {
		return err
	}
	for _, c := range codes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(user_id,hash) VALUES(?,?)`, uid, codeHash(normalizeRecovery(c))); err != nil {
			return err
		}
	}
	return nil
}
func (s *Server) rotateCodes(w http.ResponseWriter, r *http.Request, uid string) {
	codes, err := newRecoveryCodes()
	if err != nil {
		problem(w, 500, "code generation failed")
		return
	}
	tx, err := s.Store.db.BeginTx(r.Context(), nil)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	defer tx.Rollback()
	var active bool
	var hotpActive bool
	var passkeys int
	err = tx.QueryRowContext(r.Context(), `SELECT totp_secret IS NOT NULL,(SELECT EXISTS(SELECT 1 FROM hotp WHERE user_id=? AND secret IS NOT NULL)),(SELECT COUNT(*) FROM credentials WHERE user_id=?) FROM users WHERE id=?`, uid, uid, uid).Scan(&active, &hotpActive, &passkeys)
	if errors.Is(err, sql.ErrNoRows) {
		problem(w, 404, "user not found")
		return
	}
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	if !active && !hotpActive && passkeys == 0 {
		problem(w, 400, "enable a factor first")
		return
	}
	if err = replaceCodes(r.Context(), tx, uid, codes); err != nil {
		problem(w, 500, "storage error")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "storage error")
		return
	}
	writeJSON(w, 200, map[string]any{"recovery_codes": codes})
}
func (s *Server) beginPasskey(w http.ResponseWriter, r *http.Request, uid, kind string) {
	var u user
	var err error
	if kind == "register" {
		u, err = s.Store.ensureUser(r.Context(), uid)
	} else {
		u, err = s.Store.loadUser(r.Context(), uid)
	}
	if err != nil {
		problem(w, 404, "user not found")
		return
	}
	if kind == "authenticate" && len(u.Credentials) == 0 {
		problem(w, 400, "no passkey registered")
		return
	}
	var options any
	var session *webauthn.SessionData
	if kind == "register" {
		options, session, err = s.webauthn.BeginRegistration(u)
	} else {
		options, session, err = s.webauthn.BeginLogin(u)
	}
	if err != nil {
		problem(w, 500, "ceremony failed")
		return
	}
	id, err := randomID(24)
	if err != nil {
		problem(w, 500, "ceremony failed")
		return
	}
	if err = s.Store.saveCeremony(r.Context(), id, uid, kind, session); err != nil {
		problem(w, 500, "storage error")
		return
	}
	writeJSON(w, 200, map[string]any{"ceremony_id": id, "options": options})
}
func (s *Server) finishPasskey(w http.ResponseWriter, r *http.Request, uid, kind string) {
	id := r.Header.Get("X-Ceremony-ID")
	if id == "" {
		problem(w, 400, "X-Ceremony-ID required")
		return
	}
	session, err := s.Store.takeCeremony(r.Context(), id, uid, kind)
	if err != nil {
		problem(w, 400, "ceremony missing or expired")
		return
	}
	u, err := s.Store.loadUser(r.Context(), uid)
	if err != nil {
		problem(w, 404, "user not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var credential *webauthn.Credential
	if kind == "register" {
		credential, err = s.webauthn.FinishRegistration(u, session, r)
	} else {
		credential, err = s.webauthn.FinishLogin(u, session, r)
	}
	if err != nil {
		problem(w, 400, "invalid passkey response")
		return
	}
	if credential.Authenticator.CloneWarning {
		problem(w, 403, "passkey counter anomaly")
		return
	}
	if err = s.Store.saveCredential(r.Context(), uid, credential, kind == "register"); err != nil {
		problem(w, 500, "storage error")
		return
	}
	writeJSON(w, 200, map[string]any{"valid": true, "credential_id": base64.RawURLEncoding.EncodeToString(credential.ID)})
}
func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request, uid, id string) {
	if id == "" || strings.Contains(id, "/") {
		problem(w, 404, "not found")
		return
	}
	tx, err := s.Store.db.BeginTx(r.Context(), nil)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), `DELETE FROM credentials WHERE id=? AND user_id=?`, id, uid)
	if err != nil {
		problem(w, 500, "storage error")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		problem(w, 404, "passkey not found")
		return
	}
	var active bool
	var hotpActive bool
	var remaining int
	if err = tx.QueryRowContext(r.Context(), `SELECT totp_secret IS NOT NULL,(SELECT EXISTS(SELECT 1 FROM hotp WHERE user_id=? AND secret IS NOT NULL)),(SELECT COUNT(*) FROM credentials WHERE user_id=?) FROM users WHERE id=?`, uid, uid, uid).Scan(&active, &hotpActive, &remaining); err != nil {
		problem(w, 500, "storage error")
		return
	}
	if !active && !hotpActive && remaining == 0 {
		if _, err = tx.ExecContext(r.Context(), `DELETE FROM recovery_codes WHERE user_id=?`, uid); err != nil {
			problem(w, 500, "storage error")
			return
		}
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "storage error")
		return
	}
	writeJSON(w, 200, map[string]bool{"deleted": true})
}
