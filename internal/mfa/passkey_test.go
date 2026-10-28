package mfa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func encoded(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func credentialRequest(t *testing.T, s *Server, path, id string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 40))
	req.Header.Set("X-Ceremony-ID", id)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return rec.Code, result
}
func clientData(t *testing.T, kind, challenge string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": "http://localhost:18083"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestWebAuthnRegistrationAndAuthentication(t *testing.T) {
	s, path, encryptionKey := newTestServer(t)
	code, begin := call(t, s, "POST", "/v1/users/alice/passkeys/register/begin", nil, true, "")
	requireStatus(t, 200, code, begin)
	options := begin["options"].(map[string]any)["publicKey"].(map[string]any)
	selection := options["authenticatorSelection"].(map[string]any)
	if selection["residentKey"] != "required" || selection["userVerification"] != "required" {
		t.Fatal("passkey requirements were not requested")
	}
	challenge := options["challenge"].(string)
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := key.PublicKey.X.FillBytes(make([]byte, 32)), key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte("localhost"))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x45, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(credentialID)))
	authData = append(authData, length...)
	authData = append(authData, credentialID...)
	authData = append(authData, cose...)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		t.Fatal(err)
	}
	creation := map[string]any{"id": encoded(credentialID), "rawId": encoded(credentialID), "type": "public-key", "response": map[string]any{"clientDataJSON": encoded(clientData(t, "webauthn.create", challenge)), "attestationObject": encoded(attestation), "transports": []string{"internal"}}}
	code, result := credentialRequest(t, s, "/v1/users/alice/passkeys/register/finish", begin["ceremony_id"].(string), creation)
	requireStatus(t, 200, code, result)
	if result["valid"] != true {
		t.Fatal("passkey registration failed")
	}
	if err := s.Store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s.Store = reopened
	code, begin = call(t, s, "POST", "/v1/users/alice/passkeys/authenticate/begin", nil, true, "")
	requireStatus(t, 200, code, begin)
	options = begin["options"].(map[string]any)["publicKey"].(map[string]any)
	challenge = options["challenge"].(string)
	assertionData := append([]byte{}, rpHash[:]...)
	assertionData = append(assertionData, 0x05, 0, 0, 0, 1)
	client := clientData(t, "webauthn.get", challenge)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte{}, assertionData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	assertion := map[string]any{"id": encoded(credentialID), "rawId": encoded(credentialID), "type": "public-key", "response": map[string]any{"clientDataJSON": encoded(client), "authenticatorData": encoded(assertionData), "signature": encoded(signature), "userHandle": nil}}
	code, result = credentialRequest(t, s, "/v1/users/alice/passkeys/authenticate/finish", begin["ceremony_id"].(string), assertion)
	requireStatus(t, 200, code, result)
	if result["valid"] != true {
		t.Fatal("valid passkey assertion failed")
	}
	code, result = credentialRequest(t, s, "/v1/users/alice/passkeys/authenticate/finish", begin["ceremony_id"].(string), assertion)
	requireStatus(t, http.StatusBadRequest, code, result)
	code, begin = call(t, s, "POST", "/v1/users/alice/passkeys/authenticate/begin", nil, true, "")
	requireStatus(t, 200, code, begin)
	// The old signed challenge must not be accepted by a new ceremony.
	code, result = credentialRequest(t, s, "/v1/users/alice/passkeys/authenticate/finish", begin["ceremony_id"].(string), assertion)
	requireStatus(t, http.StatusBadRequest, code, result)
	code, result = call(t, s, "POST", "/v1/users/alice/recovery-codes/rotate", nil, true, "")
	requireStatus(t, 200, code, result)
	recovery := result["recovery_codes"].([]any)[0].(string)
	code, result = call(t, s, "DELETE", "/v1/users/alice/passkeys/"+encoded(credentialID), nil, true, "")
	requireStatus(t, 200, code, result)
	code, result = call(t, s, "POST", "/v1/users/alice/verify", map[string]string{"method": "recovery_code", "code": recovery}, true, "")
	requireStatus(t, 200, code, result)
	if result["valid"] != false {
		t.Fatal("recovery code remained after last factor removal")
	}
}
