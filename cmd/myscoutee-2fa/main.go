package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/fssrepository/myscoutee-2fa/internal/mfa"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		url := env("MFA_HEALTH_URL", "http://127.0.0.1:18083/healthz")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		resp.Body.Close()
		return
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("MFA_ENCRYPTION_KEY"))
	if err != nil {
		log.Fatal("MFA_ENCRYPTION_KEY must be base64")
	}
	store, err := mfa.OpenStore(env("MFA_DB_PATH", "data/mfa.db"), key)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	server, err := mfa.NewServer(store, mfa.Config{Token: os.Getenv("MFA_API_TOKEN"), RPID: env("MFA_RP_ID", "localhost"), RPOrigin: env("MFA_RP_ORIGIN", "http://localhost:18083"), RPName: env("MFA_RP_NAME", "MyScoutee"), DemoEnabled: os.Getenv("MFA_DEMO_ENABLED") == "true", OIDCIssuer: os.Getenv("MFA_OIDC_ISSUER"), OIDCClientID: os.Getenv("MFA_OIDC_CLIENT_ID"), OIDCClientSecret: os.Getenv("MFA_OIDC_CLIENT_SECRET"), OIDCRedirectURL: os.Getenv("MFA_OIDC_REDIRECT_URL"), OIDCBackchannelOrigin: os.Getenv("MFA_OIDC_BACKCHANNEL_ORIGIN"), SAMLIDPMetadataURL: os.Getenv("MFA_SAML_IDP_METADATA_URL")})
	if err != nil {
		log.Fatal(err)
	}
	addr := env("MFA_LISTEN_ADDR", "127.0.0.1:18083")
	srv := &http.Server{Addr: addr, Handler: server, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second}
	log.Print(fmt.Sprintf("myscoutee-2fa listening on %s", addr))
	log.Fatal(srv.ListenAndServe())
}
