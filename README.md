# MyScoutee 2FA

English technical guide: [MyScoutee 2FA PDF](guides/publication/manuals/MyScoutee_2FA_Technical_Guide_EN.pdf).
English test steps and current results: [2FA lab test plan](guides/testing/2fa-lab-test-plan.md).

Small standalone Go service for authenticator-app TOTP and HOTP, WebAuthn passkeys, and one-use recovery codes. It runs as one Docker container with a SQLite volume. An optional Keycloak container demonstrates OAuth 2.0/OIDC and SAML 2.0 identity flows. The trusted MyScoutee backend can later call the factor API through an internal network; MyScoutee login integration is not part of this repository.

## Run the local demo

1. Copy `.env.example` to `.env`.
2. Generate two **different** random values with `openssl rand -base64 32`. Set `MFA_API_TOKEN` and `MFA_ENCRYPTION_KEY` in `.env`. The encryption key must decode to exactly 32 bytes.
3. Run `docker compose up --build -d`.
4. Open <http://localhost:18083/>. The browser lab uses the fixed disposable `demo` user; factor status loads automatically. Follow the English-language tabs. The Authenticator app area has separate TOTP and HOTP tabs; QR setup opens in a dialog with a button to generate a fresh QR code. New recovery codes appear in a separate popup with a Copy codes button and are cleared from the page when it closes. The top-right **Reset** button deletes the demo user's factors and pending setup, clears completed identity-trial indicators, and signs out of local Keycloak when that stack is running. Reset uses a silent OIDC request and its verified ID token to avoid Keycloak's second confirmation. Reset does not erase passkeys stored on a device or in a password manager. The local demo establishes its own short-lived browser session; no service token needs to be entered in the page.

TOTP and HOTP enrollment return a QR image, manual secret, and `otpauth://` URL. Confirm a six-digit code to activate the factor. HOTP setup accepts counter 0 through 9 in case the app advanced before confirmation, then stores the next counter; normal HOTP verification also accepts the next ten counter values. Confirmation returns ten one-use recovery codes. Save them then: only hashes are stored, and they cannot be displayed again. Passkey-only accounts can create recovery codes after registering a passkey. Rotating codes invalidates all old codes; removing the last factor revokes them. A TOTP step and an HOTP counter can each be accepted only once. Five verification attempts per user within a minute are allowed before HTTP 429; a success clears the count.

TOTP changes with time, normally every 30 seconds. HOTP advances an app-side counter whenever a code is generated; the service advances its stored counter when it accepts a code. Both can use an authenticator app, but HOTP requires an entry explicitly marked HOTP or counter-based. A 30-second countdown indicates TOTP and will not work with the HOTP QR. [Aegis for Android](https://github.com/beemdevelopment/Aegis) is one app whose project documents HOTP support. For manual HOTP setup, use SHA-1, six digits and starting counter 0.

TOTP, HOTP and recovery-code entry fields are masked by default. The eye button at the end of each field shows or hides that field's value. The six-digit TOTP/HOTP fields accept only digits; recovery codes remain alphanumeric. Verification clears and remasks the entered value immediately after submission.

## Optional identity lab

Run `docker compose --env-file .env -f compose.yaml -f compose.identity.yaml up --build -d` to add local Keycloak. Wait until <http://localhost:18084/realms/myscoutee-2fa-lab/.well-known/openid-configuration> responds, then open <http://localhost:18083/>. The Identity protocols area has separate OpenID Connect and SAML tabs. Both sign-in buttons use the demo account `sandbox` with password `Sandbox-2FA-2026!`. This fixed credential is for the loopback-only lab. Set `KEYCLOAK_ADMIN_PASSWORD` in `.env` if you want to replace the local admin default.

The separate identity-trial tiles show **Completed** after this browser receives a verified OIDC or SAML result. They are lab indicators, not MyScoutee sessions or factors. Reset clears them and takes the browser through Keycloak sign-out. The local Keycloak realm permits the return to the lab after logout; external OIDC/SAML providers need their own logout configuration.

OIDC uses authorization code with PKCE, state and nonce; Go verifies the signed ID token, issuer and audience. SAML uses a Go service provider, Keycloak IdP metadata, a tracked request and a verified assertion. Both result pages show the external identity without creating a MyScoutee session or treating a provider result as a second-factor decision. `MFA_OIDC_*` and `MFA_SAML_IDP_METADATA_URL` can point the same demo adapters to an externally configured provider. Real Microsoft Entra ID and Duo tests require their tenant/application settings and credentials; the bundled lab does not impersonate those services.

The SAML tab downloads this lab's Service Provider (SP) metadata XML from `/lab/saml/metadata`. Import that XML when creating a SAML application in another identity provider; it tells the provider this lab's entity ID and assertion callback. Then configure that provider's metadata URL as `MFA_SAML_IDP_METADATA_URL` and its own test user. The bundled Keycloak realm is already configured, so no file upload is needed for its sign-in trial.

For a new Keycloak realm, open **Clients → Import client**, choose the downloaded XML file, review the imported SAML client and save it. Do not import it into the bundled lab realm: that realm already contains a client with the same entity ID. [Keycloak's SAML client import guide](https://www.keycloak.org/docs/26.8.1/server_admin/).

The Keycloak lab stores its realm inside the disposable development container. If you recreate that container, restart `mfa` as well so its cached SAML IdP signing metadata matches the new realm.

Passkey creation and verification use the browser's native WebAuthn API. A separate password manager is not required: the browser may offer a device credential store, phone, password manager, or FIDO2 security key. Open `http://localhost:18083/` in a regular browser window for this trial; the VS Code built-in browser may not show the native passkey prompt. Click **Add passkey** to start the browser or device prompt; the status card updates after registration. The page reports when it is preparing the request and waiting for the browser, then shows a result or browser error. **Cancel request** aborts a pending browser ceremony. Chrome may ask for a Google Password Manager PIN; that is the selected provider's unlock PIN, not a lab OTP or Google account password. If unknown, cancel and choose another available authenticator. The demo works on `localhost`; a remote browser origin needs HTTPS. The configured `MFA_RP_ID` must match the browser domain and `MFA_RP_ORIGIN` must match the complete origin, including the external HTTPS scheme and port. These values must remain stable after passkeys are registered.

## API

Trusted backend `/v1/` calls require `Authorization: Bearer <MFA_API_TOKEN>`. The caller supplies its **already authenticated and authorized** user ID in the path. This token grants access to every user, so it belongs to a trusted server, never to a production browser client. In `MFA_DEMO_ENABLED=true` mode, visiting the demo page issues a one-hour, HTTP-only, same-site cookie scoped to `/v1`; it works only on the configured demo host and only for the `demo` user. The lab reset endpoint additionally requires that demo cookie and cannot be called with a bearer token alone. Anyone able to reach the demo page can change that disposable user's factors, so keep the demo on loopback and disable it for integration. Browser calls with an `Origin` header must match `MFA_RP_ORIGIN`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/healthz` | Public health check |
| GET | `/v1/users/{id}/factors` | Enabled factors, passkey IDs, remaining recovery count |
| POST | `/v1/users/{id}/totp/enrollment` | Start ten-minute enrollment; returns secret, URL, QR data URL |
| POST | `/v1/users/{id}/totp/confirm` | `{ "code": "123456" }`; activates TOTP and returns ten recovery codes |
| POST | `/v1/users/{id}/hotp/enrollment` | Start ten-minute HOTP enrollment; returns secret, counter-zero URL, QR data URL |
| POST | `/v1/users/{id}/hotp/confirm` | `{ "code": "123456" }`; accepts counter 0-9, consumes through the matched counter and activates HOTP |
| POST | `/v1/users/{id}/verify` | `{ "method": "totp|hotp|recovery_code", "code": "..." }`; returns `{ "valid": true/false }` |
| POST | `/v1/users/{id}/recovery-codes/rotate` | Replace and display recovery codes once |
| POST | `/v1/users/{id}/passkeys/register/begin` | Return WebAuthn creation options and ceremony ID |
| POST | `/v1/users/{id}/passkeys/register/finish` | Send browser credential JSON and `X-Ceremony-ID` |
| POST | `/v1/users/{id}/passkeys/authenticate/begin` | Return WebAuthn assertion options and ceremony ID |
| POST | `/v1/users/{id}/passkeys/authenticate/finish` | Send browser assertion JSON and `X-Ceremony-ID` |
| DELETE | `/v1/users/{id}/passkeys/{credential-id}` | Remove one passkey |
| DELETE | `/v1/users/demo/lab-reset` | Demo cookie only; remove all `demo` factors and pending setup so the browser lab starts over |

Ceremonies expire after five minutes and are consumed once, even if verification fails. WebAuthn requires user verification. Passkey credentials and counters survive restarts. The Go factor service has no SMS, email, password store, built-in identity provider, or MyScoutee user session. The optional Keycloak container is a separate IdP for local protocol trials. An application's primary login and factor policy remain with the integrating backend.

## Deployment behind nginx

The container listens on port 18083. Keep it on a private Docker network and proxy an HTTPS origin to it; remove the local demo port mapping and set `MFA_DEMO_ENABLED=false` for an integrated deployment. Route calls from MyScoutee's authenticated backend with the bearer token. If browser WebAuthn options or responses pass through MyScoutee, expose them under the RP origin and preserve the complete JSON body and `X-Ceremony-ID` header. The browser must see the exact configured origin. Do not put the service token in frontend code.

`MFA_DB_PATH` defaults to `data/mfa.db`; the container uses `/data/mfa.db`. The AES-256-GCM key encrypts TOTP/HOTP secrets and pending enrollments. Back up the **database and encryption key together**. A mismatched key prevents startup rather than silently replacing enrolled factors. Rotate the API token by changing the environment value; replacing the encryption key requires a planned data migration or re-enrollment. The SQLite setup is intended for one service instance.

## Development checks

`go test ./...` and `go vet ./...` run with Go 1.26. The Docker image includes a self-contained health check. The service fails startup if the API token or encryption key is missing or invalid.
