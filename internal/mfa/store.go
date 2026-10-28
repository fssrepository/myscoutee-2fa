package mfa

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	aead cipher.AEAD
}

type user struct {
	ID          string
	Handle      []byte
	Credentials []webauthn.Credential
}

func (u user) WebAuthnID() []byte                         { return u.Handle }
func (u user) WebAuthnName() string                       { return u.ID }
func (u user) WebAuthnDisplayName() string                { return u.ID }
func (u user) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func OpenStore(path string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("MFA_ENCRYPTION_KEY must decode to exactly 32 bytes")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	file.Close()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, aead: aead}
	for _, q := range []string{
		`PRAGMA foreign_keys=ON`, `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, handle BLOB NOT NULL UNIQUE, totp_secret BLOB, pending_secret BLOB, pending_at INTEGER NOT NULL DEFAULT 0, last_step INTEGER NOT NULL DEFAULT -1)`,
		`CREATE TABLE IF NOT EXISTS hotp (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, secret BLOB, pending_secret BLOB, pending_at INTEGER NOT NULL DEFAULT 0, counter INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, value BLOB NOT NULL, created_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS recovery_codes (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, hash BLOB NOT NULL, PRIMARY KEY(user_id,hash))`,
		`CREATE TABLE IF NOT EXISTS ceremonies (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL, data BLOB NOT NULL, expires_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS attempts (user_id TEXT PRIMARY KEY, started_at INTEGER NOT NULL, count INTEGER NOT NULL)`,
	} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	var sentinel []byte
	err = db.QueryRow(`SELECT v FROM meta WHERE k='key_check'`).Scan(&sentinel)
	if errors.Is(err, sql.ErrNoRows) {
		sentinel, err = s.seal([]byte("myscoutee-2fa"))
		if err == nil {
			_, err = db.Exec(`INSERT INTO meta(k,v) VALUES('key_check',?)`, sentinel)
		}
	} else if err == nil {
		var plain []byte
		plain, err = s.open(sentinel)
		if err == nil && string(plain) != "myscoutee-2fa" {
			err = errors.New("encryption key does not match database")
		}
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("database encryption check: %w", err)
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, nil), nil
}
func (s *Store) open(value []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(value) < n {
		return nil, errors.New("invalid ciphertext")
	}
	return s.aead.Open(nil, value[:n], value[n:], nil)
}
func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (s *Store) ensureUser(ctx context.Context, id string) (user, error) {
	h := make([]byte, 32)
	if _, err := rand.Read(h); err != nil {
		return user{}, err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO users(id,handle) VALUES(?,?)`, id, h); err != nil {
		return user{}, err
	}
	return s.loadUser(ctx, id)
}
func (s *Store) loadUser(ctx context.Context, id string) (user, error) {
	u := user{ID: id}
	if err := s.db.QueryRowContext(ctx, `SELECT handle FROM users WHERE id=?`, id).Scan(&u.Handle); err != nil {
		return user{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT value FROM credentials WHERE user_id=? ORDER BY created_at`, id)
	if err != nil {
		return user{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		var c webauthn.Credential
		if err := rows.Scan(&b); err != nil {
			return user{}, err
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return user{}, err
		}
		u.Credentials = append(u.Credentials, c)
	}
	return u, rows.Err()
}
func (s *Store) saveCredential(ctx context.Context, id string, c *webauthn.Credential, registration bool) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	credentialID := base64.RawURLEncoding.EncodeToString(c.ID)
	if registration {
		_, err = s.db.ExecContext(ctx, `INSERT INTO credentials(id,user_id,value,created_at) VALUES(?,?,?,?)`, credentialID, id, b, time.Now().Unix())
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE credentials SET value=? WHERE id=? AND user_id=?`, b, credentialID, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("credential owner changed")
	}
	return nil
}
func (s *Store) saveCeremony(ctx context.Context, id, uid, kind string, session *webauthn.SessionData) error {
	b, err := json.Marshal(session)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO ceremonies(id,user_id,kind,data,expires_at) VALUES(?,?,?,?,?)`, id, uid, kind, b, time.Now().Add(5*time.Minute).Unix())
	return err
}
func (s *Store) takeCeremony(ctx context.Context, id, uid, kind string) (webauthn.SessionData, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return webauthn.SessionData{}, err
	}
	defer tx.Rollback()
	var b []byte
	var expiry int64
	if err = tx.QueryRowContext(ctx, `SELECT data,expires_at FROM ceremonies WHERE id=? AND user_id=? AND kind=?`, id, uid, kind).Scan(&b, &expiry); err != nil {
		return webauthn.SessionData{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM ceremonies WHERE id=?`, id); err != nil {
		return webauthn.SessionData{}, err
	}
	if err = tx.Commit(); err != nil {
		return webauthn.SessionData{}, err
	}
	if expiry < time.Now().Unix() {
		return webauthn.SessionData{}, errors.New("ceremony expired")
	}
	var session webauthn.SessionData
	err = json.Unmarshal(b, &session)
	return session, err
}
func (s *Store) remainingCodes(ctx context.Context, uid string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id=?`, uid).Scan(&n)
	return n, err
}
func codeHash(code string) []byte { h := sha256.Sum256([]byte(code)); return h[:] }
