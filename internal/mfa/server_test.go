package mfa

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

func newTestServer(t *testing.T) (*Server, string, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mfa.db")
	store, err := OpenStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	server, err := NewServer(store, Config{Token: strings.Repeat("t", 40), RPID: "localhost", RPOrigin: "http://localhost:18083", RPName: "Test", DemoEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return server, path, key
}
func call(t *testing.T, s *Server, method, path string, body any, auth bool, ceremony string) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if auth {
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 40))
	}
	if ceremony != "" {
		req.Header.Set("X-Ceremony-ID", ceremony)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var data map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatalf("%s: %s: %v", path, rec.Body.String(), err)
	}
	return rec.Code, data
}
func requireStatus(t *testing.T, want, got int, data map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("status %d, want %d: %#v", got, want, data)
	}
}
func TestTOTPAndRecoveryLifecycle(t *testing.T) {
	s, path, key := newTestServer(t)
	baseTime := time.Now()
	s.now = func() time.Time { return baseTime }
	code, data := call(t, s, "POST", "/v1/users/alice/totp/enrollment", nil, false, "")
	requireStatus(t, 401, code, data)
	code, data = call(t, s, "POST", "/v1/users/alice/totp/enrollment", nil, true, "")
	requireStatus(t, 200, code, data)
	secret := data["secret"].(string)
	if !strings.HasPrefix(data["otpauth_url"].(string), "otpauth://totp/") || !strings.HasPrefix(data["qr_png_data_url"].(string), "data:image/png;base64,") {
		t.Fatal("missing authenticator provisioning data")
	}
	otp, err := totp.GenerateCode(secret, baseTime)
	if err != nil {
		t.Fatal(err)
	}
	code, data = call(t, s, "POST", "/v1/users/alice/totp/confirm", map[string]string{"code": otp}, true, "")
	requireStatus(t, 200, code, data)
	codes := data["recovery_codes"].([]any)
	if len(codes) != 10 {
		t.Fatal("expected ten recovery codes")
	}
	code, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "totp", "code": otp}, true, "")
	requireStatus(t, 200, code, data)
	if data["valid"] != false {
		t.Fatal("enrollment code was replayed")
	}
	s.now = func() time.Time { return baseTime.Add(30 * time.Second) }
	nextCode, err := totp.GenerateCode(secret, s.now())
	if err != nil {
		t.Fatal(err)
	}
	code, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "totp", "code": nextCode}, true, "")
	requireStatus(t, 200, code, data)
	if data["valid"] != true {
		t.Fatal("next TOTP step was rejected")
	}
	code, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "totp", "code": nextCode}, true, "")
	requireStatus(t, 200, code, data)
	if data["valid"] != false {
		t.Fatal("TOTP code was replayed")
	}
	recovery := codes[0].(string)
	code, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "recovery_code", "code": recovery}, true, "")
	requireStatus(t, 200, code, data)
	if data["valid"] != true {
		t.Fatal("recovery code failed")
	}
	code, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "recovery_code", "code": recovery}, true, "")
	requireStatus(t, 200, code, data)
	if data["valid"] != false {
		t.Fatal("recovery code replayed")
	}
	code, data = call(t, s, "POST", "/v1/users/alice/recovery-codes/rotate", nil, true, "")
	requireStatus(t, 200, code, data)
	newCode := data["recovery_codes"].([]any)[0].(string)
	s.Store.Close()
	store, err := OpenStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	s.Store = store
	defer store.Close()
	code, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "recovery_code", "code": codes[1].(string)}, true, "")
	requireStatus(t, 200, code, data)
	if data["valid"] != false {
		t.Fatal("rotated code still valid")
	}
	code, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "recovery_code", "code": newCode}, true, "")
	requireStatus(t, 200, code, data)
	if data["valid"] != true {
		t.Fatal("new code did not survive reopen")
	}
}
func TestHOTPEnrollmentResyncAndPersistence(t *testing.T) {
	s, path, key := newTestServer(t)
	status, data := call(t, s, "POST", "/v1/users/alice/hotp/enrollment", nil, true, "")
	requireStatus(t, 200, status, data)
	secret := data["secret"].(string)
	if !strings.HasPrefix(data["otpauth_url"].(string), "otpauth://hotp/") || !strings.Contains(data["otpauth_url"].(string), "counter=0") {
		t.Fatal("missing HOTP counter in provisioning URL")
	}
	first, err := hotp.GenerateCode(secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	wrong := ""
	for n := 0; n < 1_000_000; n++ {
		candidateCode := fmt.Sprintf("%06d", n)
		matches := false
		for candidate := uint64(0); candidate < 10; candidate++ {
			if hotp.Validate(candidateCode, candidate, secret) {
				matches = true
				break
			}
		}
		if !matches {
			wrong = candidateCode
			break
		}
	}
	status, data = call(t, s, "POST", "/v1/users/alice/hotp/confirm", map[string]string{"code": wrong}, true, "")
	requireStatus(t, 400, status, data)
	status, data = call(t, s, "POST", "/v1/users/alice/hotp/confirm", map[string]string{"code": first}, true, "")
	requireStatus(t, 200, status, data)
	if len(data["recovery_codes"].([]any)) != 10 {
		t.Fatal("missing recovery codes")
	}
	status, data = call(t, s, "GET", "/v1/users/alice/factors", nil, true, "")
	requireStatus(t, 200, status, data)
	if data["hotp"] != true {
		t.Fatal("HOTP not listed")
	}
	status, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "hotp", "code": first}, true, "")
	requireStatus(t, 200, status, data)
	if data["valid"] != false {
		t.Fatal("enrollment code replayed")
	}
	// The authenticator advanced to counter 3 while offline.
	next, err := hotp.GenerateCode(secret, 3)
	if err != nil {
		t.Fatal(err)
	}
	status, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "hotp", "code": next}, true, "")
	requireStatus(t, 200, status, data)
	if data["valid"] != true {
		t.Fatal("look-ahead code rejected")
	}
	s.Store.Close()
	store, err := OpenStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	s.Store = store
	defer store.Close()
	status, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "hotp", "code": next}, true, "")
	requireStatus(t, 200, status, data)
	if data["valid"] != false {
		t.Fatal("HOTP replayed after restart")
	}
	after, err := hotp.GenerateCode(secret, 4)
	if err != nil {
		t.Fatal(err)
	}
	status, data = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "hotp", "code": after}, true, "")
	requireStatus(t, 200, status, data)
	if data["valid"] != true {
		t.Fatal("next HOTP code rejected after restart")
	}
}
func TestHOTPEnrollmentAcceptsAdvancedAppCounter(t *testing.T) {
	s, _, _ := newTestServer(t)
	status, data := call(t, s, "POST", "/v1/users/advanced/hotp/enrollment", nil, true, "")
	requireStatus(t, 200, status, data)
	secret := data["secret"].(string)
	activation, err := hotp.GenerateCode(secret, 2)
	if err != nil {
		t.Fatal(err)
	}
	status, data = call(t, s, "POST", "/v1/users/advanced/hotp/confirm", map[string]string{"code": activation}, true, "")
	requireStatus(t, 200, status, data)
	for _, counter := range []uint64{0, 1, 2} {
		used, err := hotp.GenerateCode(secret, counter)
		if err != nil {
			t.Fatal(err)
		}
		status, data = call(t, s, "POST", "/v1/users/advanced/verify", map[string]string{"method": "hotp", "code": used}, true, "")
		requireStatus(t, 200, status, data)
		if data["valid"] != false {
			t.Fatalf("counter %d accepted after enrollment at counter 2", counter)
		}
	}
	next, err := hotp.GenerateCode(secret, 3)
	if err != nil {
		t.Fatal(err)
	}
	status, data = call(t, s, "POST", "/v1/users/advanced/verify", map[string]string{"method": "hotp", "code": next}, true, "")
	requireStatus(t, 200, status, data)
	if data["valid"] != true {
		t.Fatal("next counter rejected after advanced enrollment")
	}
}
func TestPasskeyCeremonyIsOneUse(t *testing.T) {
	s, _, _ := newTestServer(t)
	code, data := call(t, s, "POST", "/v1/users/alice/passkeys/register/begin", nil, true, "")
	requireStatus(t, 200, code, data)
	if data["options"] == nil {
		t.Fatal("missing browser options")
	}
	id := data["ceremony_id"].(string)
	code, data = call(t, s, "POST", "/v1/users/alice/passkeys/register/finish", map[string]string{"bad": "credential"}, true, id)
	requireStatus(t, 400, code, data)
	code, data = call(t, s, "POST", "/v1/users/alice/passkeys/register/finish", map[string]string{"bad": "credential"}, true, id)
	requireStatus(t, 400, code, data)
	if data["error"] != "ceremony missing or expired" {
		t.Fatal("ceremony reused")
	}
	code, data = call(t, s, "POST", "/v1/users/alice/passkeys/authenticate/begin", nil, true, "")
	requireStatus(t, 400, code, data)
	code, data = call(t, s, "POST", "/v1/users/alice/recovery-codes/rotate", nil, true, "")
	requireStatus(t, 400, code, data)
}
func TestVerificationRateLimitAndOrigin(t *testing.T) {
	s, _, _ := newTestServer(t)
	code, data := call(t, s, "POST", "/v1/users/a/totp/enrollment", nil, true, "")
	requireStatus(t, 200, code, data)
	for i := 0; i < 5; i++ {
		code, data = call(t, s, "POST", "/v1/users/a/verify", map[string]string{"method": "totp", "code": "000000"}, true, "")
		requireStatus(t, 200, code, data)
	}
	code, data = call(t, s, "POST", "/v1/users/a/verify", map[string]string{"method": "totp", "code": "000000"}, true, "")
	requireStatus(t, 429, code, data)
	req := httptest.NewRequest("GET", "/v1/users/a/factors", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 40))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("foreign origin status %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("health status %d", rec.Code)
	}
}

func TestWrongEncryptionKeyRejected(t *testing.T) {
	s, path, _ := newTestServer(t)
	s.Store.Close()
	wrong := make([]byte, 32)
	if _, err := rand.Read(wrong); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path, wrong)
	if err == nil {
		store.Close()
		t.Fatal("database accepted a different encryption key")
	}
}

func TestIdentityLabRequiresDemoAndSafeIssuer(t *testing.T) {
	s, _, _ := newTestServer(t)
	base := Config{Token: strings.Repeat("t", 40), RPID: "localhost", RPOrigin: "http://localhost:18083", RPName: "Test", OIDCIssuer: "http://localhost:18084/realms/test", OIDCClientID: "test", OIDCRedirectURL: "http://localhost:18083/lab/oidc/callback"}
	if _, err := NewServer(s.Store, base); err == nil {
		t.Fatal("identity lab enabled outside demo mode")
	}
	base.DemoEnabled = true
	base.OIDCIssuer = "http://example.com/realms/test"
	if _, err := NewServer(s.Store, base); err == nil {
		t.Fatal("remote plain-HTTP issuer accepted")
	}
	base.OIDCIssuer = "http://localhost:18084/realms/test"
	if _, err := NewServer(s.Store, base); err != nil {
		t.Fatal(err)
	}
}

func TestDemoSessionUnlocksOnlyTheLocalDemo(t *testing.T) {
	s, _, _ := newTestServer(t)
	page := httptest.NewRecorder()
	s.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "http://localhost:18083/", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Show setup QR code") || strings.Count(page.Body.String(), `role="tablist"`) != 3 || !strings.Contains(page.Body.String(), `aria-controls="panel-totp"`) || !strings.Contains(page.Body.String(), `aria-controls="panel-hotp"`) || !strings.Contains(page.Body.String(), `aria-controls="panel-oidc"`) || !strings.Contains(page.Body.String(), `aria-controls="panel-saml"`) || !strings.Contains(page.Body.String(), "Start with TOTP") || !strings.Contains(page.Body.String(), "HOTP needs an app that explicitly supports it") || !strings.Contains(page.Body.String(), `<dialog id="enrollment"`) || !strings.Contains(page.Body.String(), `<dialog id="hotp-enrollment"`) || !strings.Contains(page.Body.String(), `<dialog id="recovery-dialog"`) || !strings.Contains(page.Body.String(), `<dialog id="reset-dialog"`) || !strings.Contains(page.Body.String(), `aria-label="Reset demo user">Reset</button>`) || !strings.Contains(page.Body.String(), `<strong id="status-oidc">Unavailable</strong>`) || !strings.Contains(page.Body.String(), `<strong id="status-saml">Unavailable</strong>`) || strings.Contains(page.Body.String(), "Refresh status") || strings.Count(page.Body.String(), `class="dialog-close"`) != 4 || strings.Count(page.Body.String(), "Generate new QR code") != 2 || strings.Contains(page.Body.String(), s.config.Token) {
		t.Fatal("demo page did not provide the English tabbed setup without exposing the service token")
	}
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "img-src 'self' data:") {
		t.Fatal("content security policy blocks the local logo or QR image")
	}
	logo := httptest.NewRecorder()
	s.ServeHTTP(logo, httptest.NewRequest(http.MethodGet, "http://localhost:18083/assets/logo.png", nil))
	if logo.Code != http.StatusOK || logo.Header().Get("Content-Type") != "image/png" || logo.Body.Len() == 0 {
		t.Fatal("demo logo asset is unavailable")
	}
	if logo.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("demo assets should refresh without stale browser caching")
	}
	cookies := page.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != demoCookieName || cookies[0].Path != "/v1" || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected demo cookie: %#v", cookies)
	}
	request := func(host, origin, authorization string, withCookie bool) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/v1/users/alice/factors", nil)
		if withCookie {
			req.AddCookie(cookies[0])
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := request("localhost:18083", "", "", false); got != 401 {
		t.Fatalf("tokenless API request: %d", got)
	}
	if got := request("localhost:18083", "http://localhost:18083", "", true); got != 403 {
		t.Fatalf("demo cookie accessed another user: %d", got)
	}
	if got := request("localhost:18083", "http://localhost:18083", "Bearer "+strings.Repeat("t", 40), false); got != 200 {
		t.Fatalf("same-origin demo request: %d", got)
	}
	if got := request("localhost:18083", "", "Bearer wrong", true); got != 401 {
		t.Fatalf("invalid bearer was replaced by demo cookie: %d", got)
	}
	if got := request("other.example:18083", "", "", true); got != 401 {
		t.Fatalf("foreign host accepted demo cookie: %d", got)
	}
	if got := request("localhost:18083", "https://other.example", "", true); got != 403 {
		t.Fatalf("foreign origin accepted demo cookie: %d", got)
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if got := request("localhost:18083", "", "", true); got != 401 {
		t.Fatalf("expired demo cookie: %d", got)
	}
	s.config.DemoEnabled = false
	if got := request("localhost:18083", "", "", true); got != 401 {
		t.Fatalf("production mode accepted demo cookie: %d", got)
	}
}

func TestResetDemoUser(t *testing.T) {
	s, _, _ := newTestServer(t)
	for _, id := range []string{"demo", "other"} {
		if _, err := s.Store.ensureUser(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Store.db.Exec(`UPDATE users SET totp_secret=?,pending_secret=?,pending_at=1,last_step=4 WHERE id='demo'`, []byte("active"), []byte("pending")); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`INSERT INTO hotp(user_id,secret,counter) VALUES('demo',X'01',3)`,
		`INSERT INTO credentials(id,user_id,value,created_at) VALUES('passkey','demo',X'01',1)`,
		`INSERT INTO recovery_codes(user_id,hash) VALUES('demo',X'01')`,
		`INSERT INTO ceremonies(id,user_id,kind,data,expires_at) VALUES('ceremony','demo','register',X'01',1)`,
		`INSERT INTO attempts(user_id,started_at,count) VALUES('demo',1,2)`,
	} {
		if _, err := s.Store.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	page := httptest.NewRecorder()
	s.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "http://localhost:18083/", nil))
	cookie := page.Result().Cookies()[0]
	request := func(path, origin string, withCookie, withBearer bool) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodDelete, "http://localhost:18083"+path, nil)
		if withCookie {
			req.AddCookie(cookie)
		}
		if withBearer {
			req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 40))
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code
	}
	path := "/v1/users/demo/lab-reset"
	if got := request(path, "", false, false); got != 401 {
		t.Fatalf("anonymous reset status %d", got)
	}
	if got := request(path, "", false, true); got != 403 {
		t.Fatalf("bearer-only reset status %d", got)
	}
	if got := request("/v1/users/other/lab-reset", "", true, false); got != 403 {
		t.Fatalf("another user reset status %d", got)
	}
	if got := request(path, "https://other.example", true, false); got != 403 {
		t.Fatalf("foreign-origin reset status %d", got)
	}
	if got := request(path, "http://localhost:18083", true, false); got != 200 {
		t.Fatalf("demo reset status %d", got)
	}
	s.config.OIDCIssuer = "http://localhost:18084/realms/myscoutee-2fa-lab"
	s.config.OIDCClientID = "myscoutee-2fa-lab"
	repeat := httptest.NewRequest(http.MethodDelete, "http://localhost:18083"+path, nil)
	repeat.AddCookie(cookie)
	repeat.Header.Set("Origin", "http://localhost:18083")
	repeatResult := httptest.NewRecorder()
	s.ServeHTTP(repeatResult, repeat)
	var resetResult struct {
		Deleted   bool   `json:"deleted"`
		LogoutURL string `json:"logout_url"`
	}
	if repeatResult.Code != 200 || json.Unmarshal(repeatResult.Body.Bytes(), &resetResult) != nil || !resetResult.Deleted {
		t.Fatalf("repeat reset did not return local Keycloak logout: %d %s", repeatResult.Code, repeatResult.Body.String())
	}
	if resetResult.LogoutURL != "http://localhost:18083/lab/oidc/logout" {
		t.Fatalf("invalid local logout start URL: %q", resetResult.LogoutURL)
	}
	for _, name := range []string{oidcCookie, "myscoutee_2fa_saml_session", identityTrialCookieName("oidc"), identityTrialCookieName("saml")} {
		found := false
		for _, cleared := range repeatResult.Result().Cookies() {
			if cleared.Name == name && cleared.MaxAge < 0 {
				found = true
			}
		}
		if !found {
			t.Fatalf("reset did not clear %s", name)
		}
	}
	for _, table := range []string{"users", "hotp", "credentials", "recovery_codes", "ceremonies", "attempts"} {
		column := "user_id"
		if table == "users" {
			column = "id"
		}
		var count int
		if err := s.Store.db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE ` + column + `='demo'`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s still has demo data: %d, %v", table, count, err)
		}
	}
	var others int
	if err := s.Store.db.QueryRow(`SELECT COUNT(*) FROM users WHERE id='other'`).Scan(&others); err != nil || others != 1 {
		t.Fatalf("another user was changed: %d, %v", others, err)
	}
	code, data := call(t, s, http.MethodGet, "/v1/users/demo/factors", nil, true, "")
	requireStatus(t, 200, code, data)
	if data["totp"] != false || data["hotp"] != false || len(data["passkeys"].([]any)) != 0 || data["recovery_codes_remaining"] != float64(0) {
		t.Fatalf("reset demo status is not empty: %#v", data)
	}
	code, data = call(t, s, http.MethodPost, "/v1/users/demo/totp/enrollment", nil, true, "")
	requireStatus(t, 200, code, data)
}

func TestIdentityTrialIndicatorsRequireServerCookie(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.config.OIDCIssuer = "http://localhost:18084/realms/myscoutee-2fa-lab"
	s.saml = &samlLab{}
	issued := httptest.NewRecorder()
	s.setIdentityTrial(issued, "oidc", true)
	request := httptest.NewRequest(http.MethodGet, "http://localhost:18083/", nil)
	request.AddCookie(issued.Result().Cookies()[0])
	request.AddCookie(&http.Cookie{Name: identityTrialCookieName("saml"), Value: "forged"})
	page := httptest.NewRecorder()
	s.ServeHTTP(page, request)
	if !strings.Contains(page.Body.String(), `<strong id="status-oidc">Completed</strong>`) || !strings.Contains(page.Body.String(), `<strong id="status-saml">Not tried</strong>`) {
		t.Fatal("identity trial indicators did not reflect only a completed provider result")
	}
}

func TestLocalKeycloakLogoutWithoutSecondConfirmation(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.config.OIDCIssuer = "http://localhost:18084/realms/myscoutee-2fa-lab"
	s.config.OIDCClientID = "myscoutee-2fa-lab"
	if got := s.localKeycloakLogoutURL(); got != "http://localhost:18083/lab/oidc/logout" {
		t.Fatalf("unexpected logout start: %q", got)
	}
	logout, err := url.Parse(s.keycloakEndSessionURL("verified-id-token"))
	if err != nil || logout.Host != "localhost:18084" || logout.Path != "/realms/myscoutee-2fa-lab/protocol/openid-connect/logout" || logout.Query().Get("client_id") != "myscoutee-2fa-lab" || logout.Query().Get("id_token_hint") != "verified-id-token" || logout.Query().Get("post_logout_redirect_uri") != "http://localhost:18083/" {
		t.Fatalf("invalid Keycloak logout URL: %v", err)
	}
	flow, err := json.Marshal(oidcFlow{State: "expected-state", Nonce: "nonce", Verifier: "verifier", Purpose: "logout", Expires: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Store.seal(flow)
	if err != nil {
		t.Fatal(err)
	}
	request := func(state string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://localhost:18083/lab/oidc/callback?error=login_required&state="+state, nil)
		req.AddCookie(&http.Cookie{Name: oidcCookie, Value: base64.RawURLEncoding.EncodeToString(sealed)})
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}
	if rec := request("wrong-state"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid logout state accepted: %d", rec.Code)
	}
	if rec := request("expected-state"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("logout without a Keycloak session did not return to lab: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
