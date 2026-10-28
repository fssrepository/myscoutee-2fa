# MyScoutee 2FA lab test plan

This plan tests the standalone sandbox as a future MyScoutee factor service. The
factor API trusts a backend-supplied user ID; it does not create a MyScoutee
login session. The browser demo uses only the disposable `demo` user. Never put a service token,
enrollment secret, or recovery code in a committed test record.

## Test order and evidence

| Phase | What we test | Required runtime | Result on 2026-10-28 |
| --- | --- | --- | --- |
| A | Go unit and in-process HTTP tests: TOTP, HOTP, recovery, WebAuthn, access controls and persistence | Go 1.26.2 | PASS |
| B | Static analysis | Go 1.26.2 | PASS |
| C0 | Live HTTP readiness, bearer-token access and browser-origin boundary | `mfa` container | PASS |
| C | Authenticator app and recovery flows through the demo page | One Go service or the `mfa` container, phone app | User reports TOTP, recovery and HOTP tested; individual HOTP replay and lookahead checks were not separately recorded |
| D | Browser passkey and optional physical security key | Demo page, browser authenticator | User reports the external Chrome passkey trial apparently worked; saved count and separate Verify result not yet recorded |
| E | Local OIDC and SAML round trips | `mfa` and Keycloak containers | User tried both protocols; exact callback results and logout repeat remain to be recorded |
| F | Microsoft Entra ID or Duo adapter trial | External test tenant and credentials | NOT RUN |
| G | MyScoutee login and step-up integration | MyScoutee integration code | NOT IMPLEMENTED |

The automatic tests use a temporary SQLite database and do not start a server.
They exercise the HTTP handlers in process. Phase D still needs a real browser
and authenticator because a synthetic WebAuthn signature does not prove device
prompt behavior. Phase E needs Keycloak; do not infer its current behavior from
the Go tests alone.

## Phase A and B: automatic checks

From the repository root:

On Linux x86-64, `tools/install-go-linux-amd64.sh` installs the Dockerfile's
Go version system-wide after a visible `sudo` prompt. It does not edit shell
profile files. Skip it when Go 1.26.2 is already installed.

```sh
go version
go test -count=1 ./...
go vet ./...
```

The tests assert the following contracts:

1. **TOTP:** unauthenticated enrollment is rejected; an enrollment produces a
   QR code and `otpauth://` URL; confirmation creates ten recovery codes; the
   confirmation code and an accepted later time step cannot be replayed.
2. **HOTP:** a wrong confirmation code is rejected; setup accepts counter zero
   through nine and consumes through the matched counter; an authenticator
   advanced while offline can resynchronize within the ten-counter lookahead;
   an accepted counter cannot be replayed after reopening the database.
3. **Recovery:** a code works once, rotation invalidates old codes, and a new
   code remains valid after reopening the database.
4. **WebAuthn:** registration requires a resident key and user verification;
   a signed assertion works after reopening the database; the ceremony and
   challenge cannot be replayed; removing the last factor revokes recovery
   codes.
5. **Boundaries:** failed verification is rate limited, an alien browser origin
   is rejected, the wrong encryption key is rejected, and identity adapters
   require the safe demo configuration.

Run record: on 2026-10-28, at repository revision `3e26f9c`,
`go test -count=1 ./...` passed (`internal/mfa`; `cmd/myscoutee-2fa` has no test
files), and `go vet ./...` passed. No Go server, Docker container, or KVM guest
was started for these checks.

Live HTTP record: the factor-only Docker stack was started on 2026-10-28.
`GET /healthz` returned 200; a tokenless factor read returned 401; the same
read with the local service token returned 200; and a foreign `Origin` returned
403. After the English tabbed UI update, opening the page issued a demo cookie;
the same-origin factor read worked without a service token; the separate TOTP/HOTP
tabs, both QR setup dialogs and their refresh buttons were present; the logo asset and TOTP enrollment QR
returned valid PNGs. The `mfa` container was healthy. No
Keycloak or KVM guest was started.

HOTP checkpoint on 2026-10-28: the user reported that a code entered in the
HOTP activation popup returned `invalid code`. The app type and whether it had
advanced its counter are not yet known, so this is an observed failure rather
than a confirmed app or server cause. Code review found that activation only
accepted counter 0 while normal verification already accepted a ten-counter
window. The handler now accepts setup counters 0-9 and stores the next counter;
the page explains how to recognize an HOTP entry. `go test -count=1 ./...`,
`go vet ./...`, and `node --check internal/mfa/web/demo.js` passed after the
change. The factor-only container was rebuilt and returned a healthy
`/healthz`; the served page and script contained the revised HOTP guidance.
No browser actions were run by the agent. At that checkpoint, a fresh manual
trial with an explicitly HOTP-capable app remained open.

Follow-up on 2026-10-28: the user reported HOTP tested after the revised
container was running and asked to continue with passkeys. This closes the
reported activation failure as a user-observed success; the C2 replay and
lookahead subchecks have not been reported individually. Passkey phase D is
the next manual checkpoint.

Passkey checkpoint on 2026-10-28: the user reported that no approval prompt
appeared in the VS Code built-in browser. The screenshot showed
`http://localhost:18083/`, test user `demo`, zero saved passkeys and later a
pending browser/device prompt state. The same URL in a regular Chrome window
did show a Google Password Manager PIN prompt. The user subsequently reported
that the trial apparently worked. This is a user-reported passkey result; the
saved Passkeys count and separate Verify passkey result have not been recorded.
The page now explains the browser choice and provider PIN, and can cancel a
pending WebAuthn ceremony. The user also reported that verification left a
sensitive code in its input; TOTP, HOTP and recovery verification now clear
and remask the submitted value.

Demo-user reset checkpoint on 2026-10-28: the browser lab now fixes the user ID
to `demo` and loads status automatically. The **Reset** confirmation
deletes that user's server-side factors, recovery codes, ceremonies and attempt
state. It also clears local identity-trial indicators and sends the browser to
Keycloak sign-out when the local identity stack is enabled; Keycloak may ask for
confirmation. Automated tests checked that no demo cookie or a bearer token alone
cannot call the reset, a demo cookie cannot access another user, the reset is
idempotent and another user's row remains. The running `demo` data was not
reset by the agent; manual use of the button remains with the user.

Identity checkpoint on 2026-10-28: the repository's identity Compose stack
started with the existing `mfa` volume. `GET /healthz` returned 200 and the
Keycloak realm's OIDC discovery document returned 200. The user tried the OIDC
and SAML browser flows and observed that the second flow reused the Keycloak
login. Callback details have not been recorded. No browser sign-in was
performed by the agent. The Keycloak `sandbox` identity is separate from the
fixed factor-lab `demo` user.

## How the named technologies map to this lab

[FIDO2](https://fidoalliance.org/specifications/) combines the browser-facing
WebAuthn API with CTAP between the browser or operating system and an
authenticator. This Go service is the WebAuthn relying party: it creates
registration and authentication challenges and validates the returned public
key credential. The browser handles CTAP and any USB, NFC, or Bluetooth link
to a FIDO2 key. A passkey is a WebAuthn credential; a YubiKey is one possible
physical authenticator. The automated test uses a synthetic credential, so a
real key or platform prompt remains a separate manual check.

TOTP and HOTP are the code protocols used by compatible authenticator apps;
Google Authenticator and Microsoft Authenticator are app choices, not separate
server integrations. Keycloak is the included identity provider for the OIDC
and SAML demonstrations. OAuth 2.0 authorization code with PKCE is used within
the OIDC demonstration; the lab does not act as a general OAuth authorization
server. Microsoft Entra ID and Duo require separate provider configuration and
live accounts. HSM key custody is not implemented.

## Prepare the manual lab

1. Copy `.env.example` to `.env`. Generate separate values for `MFA_API_TOKEN`
   and `MFA_ENCRYPTION_KEY` with `openssl rand -base64 32`; keep `.env` local.
2. Start the factor-only lab with `docker compose up --build -d`. Open
   <http://localhost:18083/>. The page creates a local demo session, so no
   service token or password is needed in the browser.
3. The browser page uses one fixed `demo` user. Its factor status loads automatically;
   there is no editable user ID or Refresh status button. To repeat a scenario
   from an empty state, click **Reset** and confirm **Delete demo data
   and start over**. This removes all of `demo`'s factors and recovery codes;
   do not use it while preserving test evidence. The quoted button labels below match the
   English tabs and controls shown by the page. Code fields are masked by
   default; use the eye button at the end of a field to check its value. The
   six-digit TOTP/HOTP fields filter non-digits, while recovery codes are
   alphanumeric. Verification clears and remasks each entered code.
4. Check `docker compose ps` and <http://localhost:18083/healthz>. Stop the
   factor-only lab after testing with `docker compose down`. Do not use `-v`
   unless deliberately discarding the disposable SQLite volume.

### C1. TOTP with an authenticator app

1. On the `demo` page, expect TOTP to show **Not set up** after a fresh start or reset.
2. On **Authenticator app → TOTP · Time-based**, click **Show setup QR code**. In the setup dialog, scan it with an authenticator app such
   as Google Authenticator or Microsoft Authenticator.
   **Generate new QR code** replaces the pending setup if you need to start again.
3. Enter its six-digit code and click **Activate TOTP**. The page selects the
   **Recovery codes** tab and opens a popup with ten codes. Use **Copy codes**
   and keep them only in a private temporary note for this test. Close the popup
   with the round X; the codes should no longer be visible on the page.
4. Return to **Authenticator app → TOTP · Time-based**, enter the confirmation code under **Current
   code**, and click **Verify code**. Expect a rejection because setup consumed
   that time step.
5. Wait for the next code, verify it once (accepted), then repeat the same code
   (rejected).

### C2. Recovery and rotation

1. After C1 and before resetting `demo`, open the **Recovery codes** tab. Submit one saved code
   under **Recovery code to test** and click **Verify recovery code**. Expect acceptance and
   one fewer remaining code.
2. Submit the same recovery code again. Expect rejection.
3. Click **Generate new codes** in the top right of the card. The popup explains
   that the old set will be invalidated. Click **Generate codes** inside it,
   then **Copy codes** and close it with the round X. Expect ten new codes and
   the prior unused codes to become invalid; the new set should disappear from
   the page after closing the popup.
4. Verify one new code once (accepted), then again (rejected). Space
   invalid attempts or wait a minute after five failures to avoid HTTP 429.

### C3. HOTP counter and resynchronization

1. Click **Reset** and confirm deletion, then use an app entry
   explicitly marked HOTP or counter-based, such as Aegis on Android. A
   30-second countdown indicates TOTP and cannot be used for this scenario.
   For manual setup use SHA-1, six digits and starting counter 0. On
   **Authenticator app → HOTP · Counter-based**, click **Show HOTP setup QR code**, scan it in the dialog, and
   click **Activate HOTP** with the app's current code. The service accepts up
   to nine skipped codes during setup.
2. Verify the activation code again. Expect a rejection.
3. Advance the authenticator three counters without submitting the earlier
   codes. Submit the current code and expect acceptance.
4. Submit that same code again and expect rejection. Do not exceed the ten
   counter lookahead in this scenario.

### D1. Browser passkey and optional YubiKey

1. Open the demo on `http://localhost:18083/` in a regular browser window,
   not the VS Code built-in browser. Use a browser with a platform
   authenticator, a phone passkey provider or a FIDO2 security key. If Chrome
   offers Google Password Manager and asks for its PIN, that is the provider's
   unlock PIN; do not enter a lab OTP or Google account password. If the PIN
   is unknown, cancel and choose another supported method rather than using
   account recovery for this lab. Reset `demo` first if a clean passkey-only
   trial is needed. Open the **Passkey** tab and click **Add passkey**. The
   browser may offer a phone or security key. The page should first report that it is
   preparing the request, then waiting for the browser or device prompt.
   Complete the browser's user-verification prompt. If no prompt appears,
   record the page's status or error message and the browser/device used.
2. Expect the status card to show one saved passkey automatically. Click **Verify passkey**
   and complete the prompt; expect success.
3. On **Recovery codes**, click **Generate new codes**, then **Generate codes**
   in the popup, and save one code temporarily. Close the popup, return to
   **Passkey** and click **Remove** on the only saved
   credential. Expect zero passkeys and the
   saved recovery code to fail.
4. If a physical YubiKey is available, reset `demo`, repeat and record
   the browser and key model. This tests the WebAuthn/FIDO2 path; there is no
   separate YubiKey protocol in this service.

### E1. Local OIDC and SAML identity flows

1. Stop the factor-only stack, then start the identity stack with
   `docker compose --env-file .env -f compose.yaml -f compose.identity.yaml up --build -d`.
2. Wait for <http://localhost:18084/realms/myscoutee-2fa-lab/.well-known/openid-configuration>
   and the factor service health check.
3. Open <http://localhost:18083/> and select **Identity protocols → OpenID
   Connect**. Use **Try OIDC sign-in**, sign in to Keycloak with the documented
   `sandbox` account, and confirm the result page shows the provider identity.
   Return to the lab and select **Identity protocols → SAML 2.0**. Use
   **Try SAML sign-in** and confirm the signed assertion result. The SAML tab's
   **Download SP metadata XML** gives you this lab's Service
   Provider metadata; Keycloak is preconfigured, so this trial requires no
   file upload.
4. Confirm neither result page claims to create a MyScoutee session or a 2FA
   decision. Record any callback error without copying tokens or assertions.
   On returning to the lab, the separate identity-trial tiles should read
   **Completed**. Click **Reset** and confirm deletion. The browser should return
   to the lab without a second Keycloak logout confirmation. Retry OIDC or SAML;
   Keycloak should ask for the `sandbox` password again.
5. Stop this stack with
   `docker compose --env-file .env -f compose.yaml -f compose.identity.yaml down`.
   A recreated Keycloak realm has a new SAML signing key; restart `mfa` with
   it before repeating SAML.

## External and integration boundaries

Microsoft Entra ID and Duo can only be tested after a real test tenant,
application registration, redirect URL, signing metadata, and test account are
available. Record each provider's issuer/metadata source and observed result,
without committing credentials. Keycloak is the included local protocol lab;
it does not claim to emulate Entra ID or Duo. HSM custody, SMS/email, and a
MyScoutee backend login integration are outside the implemented sandbox and
have no executable acceptance test here.

For MyScoutee integration, the future test must verify that the backend
authenticates the member before supplying its user ID, applies a step-up policy
to login and sensitive actions, keeps the service token server-side, and never
accepts a provider result as a factor decision by itself. These are design
checks until the integration exists.
