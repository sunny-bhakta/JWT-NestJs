# JWT NestJS Demo

A focused NestJS API that demonstrates how to issue and validate JSON Web Tokens (JWT) securely. It follows the checklist in `todo.md`, showing how to:

- Generate JWTs only after successful authentication
- Sign tokens with strong secrets (or drop-in RSA/ECDSA keys)
- Control token expiration through the `exp` claim
- Keep token payloads lean (only user id, email, roles)
- Validate token signatures and registered claims on every protected request
- Issue per-device refresh sessions so each browser/app keeps an isolated token family

## Prerequisites

- Node.js 18+
- npm (comes with Node)

## Quick start

```bash
npm install # install TypeORM/sqlite dependencies
copy .env.example .env   # then edit the secrets!
npm run start:dev

```

> On macOS/Linux use `cp .env.example .env` instead of `copy`.

The API listens on `http://localhost:3000` by default.

## Environment variables

| Key | Description |
| --- | --- |
| `PORT` | API port (defaults to 3000) |
| `JWT_ACCESS_SECRET` | Strong random string or base64 key used to sign tokens (fallback when no keyset is provided) |
| `JWT_ACCESS_EXPIRES_IN` | Access token lifetime (e.g., `15m`, `1h`) |
| `JWT_AUDIENCE` | Expected `aud` claim used by the JWT strategy |
| `JWT_ISSUER` | Expected `iss` claim used by the JWT strategy |
| `JWT_REFRESH_EXPIRES_IN` | Refresh token lifetime (default `7d`) |
| `JWT_REFRESH_MAX_LIFETIME` | Sliding session lifetime cap (default `30d`) |
| `JWT_KEYSET` | JSON array of signing keys (`[{"id":"key1","secret":"base64"}, ...]`) |
| `JWT_ACTIVE_KEY_ID` | Optional override that selects which key from the keyset is currently active |
| `HTTPS_KEY_PATH` | Path to the TLS private key (enables HTTPS when paired with `HTTPS_CERT_PATH`) |
| `HTTPS_CERT_PATH` | Path to the TLS certificate chain |
| `HTTPS_CA_PATH` | Optional path to a CA bundle if your certificate chain needs it |
| `AUTH_COOKIES_ENABLED` | `true` to send tokens as HttpOnly cookies in addition to the JSON body |
| `AUTH_COOKIE_DOMAIN` | Cookie domain (leave empty for localhost/dev) |
| `AUTH_COOKIE_PATH` | Cookie path (defaults to `/`) |
| `AUTH_COOKIE_SAME_SITE` | `lax`, `strict`, or `none` (use `none` for cross-site SPAs) |
| `AUTH_COOKIE_SECURE` | Force the `Secure` flag (`true` requires HTTPS) |
| `ACCESS_TOKEN_COOKIE_NAME` | Name for the access-token cookie |
| `REFRESH_TOKEN_COOKIE_NAME` | Name for the refresh-token cookie |
| `DB_PATH` | Path to the SQLite database file used for refresh sessions (default `data/app.db`) |

### Rotating access-token signing keys

Set `JWT_KEYSET` to a JSON array so you can keep multiple symmetric keys online at once:

```jsonc
JWT_KEYSET=[
  { "id": "key-2025-q4", "secret": "c2VjcmV0X2tleV8x", "primary": true },
  { "id": "key-2026-q1", "secret": "c2VjcmV0X2tleV8y" }
]
```

- The `secret` values can be plain strings or base64-encoded bytes (just make them long and random).
- Mark the upcoming key with `primary: true` or set `JWT_ACTIVE_KEY_ID=key-2026-q1` when you are ready to switch.
- Tokens issued before the rotation keep their `kid` header, so the `JwtStrategy` can still validate them using whatever key matches that ID.
- If `JWT_KEYSET` is omitted, the app falls back to the legacy `JWT_ACCESS_SECRET` value.

> Tip: treat `JWT_KEYSET` like any other credential—store it in your secret manager and automate rotations (e.g., cron job that updates the JSON and `JWT_ACTIVE_KEY_ID`).

### Serving the API over HTTPS

Provide certificate files and the server will automatically boot in HTTPS mode:

```bash
HTTPS_KEY_PATH=./certs/server.key
HTTPS_CERT_PATH=./certs/server.crt
npm run start:prod
```

For local testing you can create a self-signed pair:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout certs/server.key -out certs/server.crt -subj "/CN=localhost" -days 365
```

When HTTPS variables are omitted the app falls back to HTTP (suitable only for local development—always terminate TLS in production, either in Nest or a reverse proxy).

### Issuing tokens via HttpOnly cookies

Set `AUTH_COOKIES_ENABLED=true` to have `/auth/login` and `/auth/refresh` return the tokens both in the JSON payload *and* as HttpOnly cookies:

- Access token cookie defaults to `access_token`, refresh token to `refresh_token`.
- Cookies are `HttpOnly` and inherit the `Secure`, `SameSite`, `Domain`, and `Path` flags from the env vars above.
- On logout the cookies are cleared so browsers automatically drop the credentials.

This pattern keeps tokens away from `localStorage/sessionStorage`; browsers will automatically attach the cookies on HTTPS requests and block JavaScript from reading them, which mitigates XSS token theft. Combine this with CORS `credentials: true` (already enabled) and CSRF protections appropriate for your client architecture.

### Per-device refresh sessions

- Every login creates (or resumes) a refresh *session* identified by a `sessionId`. Each session tracks metadata such as `deviceId`, `deviceName`, IP, and user agent.
- Refresh tokens are bound to their session. Consuming a refresh token rotates it but keeps the session alive, so multiple devices can stay logged in simultaneously without stepping on one another.
- Each session gets a `familyId`, so you can correlate all refreshes that stem from the same authentication event and revoke the entire family when one token leaks.
- Sliding expiration keeps engaged users online: every refresh extends `expiresAt` up to a hard cap defined by `JWT_REFRESH_MAX_LIFETIME` (exposed as `maxExpiresAt`). Once the cap is reached the user must re-authenticate.
- Responses now include a `session` object (sessionId, familyId, expiresAt, maxExpiresAt, metadata) so clients can persist identifiers for telemetry or “manage devices” screens.
- Refresh sessions are stored in SQLite (`data/app.db` by default) via TypeORM, so restarts won’t erase device history and multiple API instances can share the same file (or point `DB_PATH` elsewhere).
- Use `GET /auth/sessions` to list active devices, `DELETE /auth/sessions/:sessionId` to revoke one device, and `DELETE /auth/sessions` to log out everywhere without touching other accounts.

> Production tip: swap SQLite for Postgres/MySQL by changing the TypeORM configuration (or point `DB_PATH` to a cloud disk). The entity is storage-agnostic, so you can move to Redis/SQL Server with minimal tweaks.

### JWT security attacks & prevention

| Threat | What it is | How this repo mitigates it |
| --- | --- | --- |
| Token replay | A stolen token is reused before it expires. | Short 15‑minute access-token TTL, refresh-token rotation with per-token revocation, and `logout`/`revokeAll` helpers. Consider recording token fingerprints in persistent storage for production. |
| Theft via XSS | Malicious script exfiltrates tokens from browser storage. | Optional HttpOnly, Secure cookies keep tokens out of `localStorage`/`sessionStorage`. Keep HTTPS enabled, pair with CSP and CSRF defenses on the client. |
| Signature confusion | Attacker swaps the algorithm or key type to bypass verification. | We only issue HS256 tokens and explicitly configure `passport-jwt` with our own secrets resolved by `kid`. Never accept tokens signed with unexpected algorithms or the `none` algorithm. |
| Algorithm downgrades | Accepting a weaker algorithm than intended (e.g., HS256 vs. RS256) lets an attacker forge tokens. | Configure a single algorithm in the `JwtModule` and matching strategy, and refuse any header that doesn’t carry a known `kid`. If you later adopt RSA/ECDSA keys, configure separate verification public keys per algorithm to prevent downgrades. |
| Token leakage over the wire | Plain HTTP or misconfigured TLS reveals credentials. | Built-in HTTPS support (or fronting reverse proxy) plus HSTS recommendation; CORS is limited to trusted origins with credentials enabled. |
| Missing claim validation | Accepting tokens with wrong `iss`, `aud`, or expired `exp`. | `JwtStrategy` enforces issuer, audience, and expiration on every request; refresh tokens are rotated and invalidated after use. |

> Checklist tie-in: these mitigations cover the remaining `JWT security attacks & prevention` item from `todo.md`. Extend this table with organization-specific controls (e.g., anomaly detection, device posture signals) as your threat model evolves.

### Handling token errors gracefully

Access and refresh token failures now surface as structured `401` responses so clients can react deterministically:

```json
{
  "statusCode": 401,
  "error": "Unauthorized",
  "code": "ACCESS_TOKEN_EXPIRED",
  "message": "Your access token has expired. Please refresh and try again."
}
```

- `ACCESS_TOKEN_MISSING` – no bearer token provided.
- `ACCESS_TOKEN_INVALID` – malformed or tampered JWT.
- `ACCESS_TOKEN_EXPIRED` – expired access token, prompt for refresh.
- `REFRESH_TOKEN_INVALID` – unknown/rotated refresh token (already consumed or invalid).
- `REFRESH_TOKEN_EXPIRED` – refresh token TTL elapsed; require re-login.

These responses originate from the custom `JwtAuthGuard` override and the refresh-token service so the API always returns the same shape regardless of where the failure happened.

### Audience/issuer validation & monitoring

- The `JwtModule` signs every token with the configured `JWT_AUDIENCE` and `JWT_ISSUER`, and the custom `JwtStrategy` refuses any bearer token whose claims don’t match those values.
- `TokenEventsService` records every failed access or refresh token attempt (code, reason, IP, path, user-agent) so you can ship logs to your SIEM and flag suspicious usage patterns.

> 💡 Swap `JWT_ACCESS_SECRET` for RSA/ECDSA key pairs by pointing `JwtModule` to `privateKey`/`publicKey` files when you’re ready for asymmetric signing.

## Demo credentials

| Email | Password | Roles |
| --- | --- | --- |
| `ada@example.com` | `ChangeMe123!` | `user` |
| `admin@example.com` | `AdminPass123!` | `admin` |

The passwords are hashed with bcrypt and stored only inside the in-memory user service.

## API reference

### `POST /auth/login`
Authenticates the user and returns both access & refresh tokens.

**Request body**
```json
{
  "email": "ada@example.com",
  "password": "ChangeMe123!"
}
```

**Response**
```json
{
  "accessToken": "<JWT>",
  "tokenType": "Bearer",
  "expiresIn": "15m",
  "refreshToken": "<opaque-string>",

  "refreshTokenExpiresIn": "7d",
  "refreshTokenExpiresAt": "2026-02-01T10:00:00.000Z",
  "session": {
    "sessionId": "3c7c9a1e-16e1-4d6f-9f06-2b9c2a901234",
    "familyId": "c0f3e9ab-0bd5-4eb7-8a32-0a6a8790cabc",
    "createdAt": "2026-01-12T10:00:00.000Z",
    "updatedAt": "2026-01-12T10:00:00.000Z",
    "expiresAt": "2026-01-19T10:00:00.000Z",
    "maxExpiresAt": "2026-02-11T10:00:00.000Z",
    "metadata": {
      "deviceId": "pixel-8-pro",
      "deviceName": "Pixel 8 Pro",
      "ipAddress": "203.0.113.42",
      "userAgent": "Mozilla/5.0 ..."
    }
  },
  "user": {
    "id": "1",
    "email": "ada@example.com",
    "name": "Ada Lovelace",
    "roles": ["user"]
  }
}

> The `refreshToken` is a securely generated, non-guessable string used to obtain new access tokens without re-authenticating. It is opaque, meaning its contents are not meant to be interpreted by clients.
```

### `GET /profile`
Protected route that validates the bearer token signature, issuer, audience, and expiration before returning the minimal profile derived from the token payload.

```bash
# Login (macOS/Linux)
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"ChangeMe123!"}'

# Use the returned access token
curl http://localhost:3000/profile \
  -H "Authorization: Bearer <token>"
```

```cmd
:: Windows CMD login
curl -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d "{\"email\":\"ada@example.com\",\"password\":\"ChangeMe123!\"}"
```
```cmd
https:
curl --cacert certs/local-ca.crt https://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"ChangeMe123!"}'
```
```
:: Windows CMD profile
curl http://localhost:3000/profile -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJzdWIiOiIxIiwiZW1haWwiOiJhZGFAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sImlhdCI6MTc2Nzk0ODgyNiwiZXhwIjoxNzY3OTQ5NzI2LCJhdWQiOiJqd3QtbmVzdC1jbGllbnQiLCJpc3MiOiJqd3QtbmVzdC1hcGkifQ.Xo8qm1VyiNR_A6vGkMVPvgOPONu74Hl-DLF9EVb6OFI"
```

### `POST /auth/refresh`
Exchanges a valid refresh token for a brand new access/refresh pair (rotates tokens so the old refresh token can’t be reused).

```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"18O9crT834YmPlpPE0xVbqpm_r-qlbk-daJXXdXNzt0zVstGA4iEohuzvEkLSz69"}'
```

```cmd
:: Windows CMD refresh
curl -X POST http://localhost:3000/auth/refresh -H "Content-Type: application/json" -d "{\"refreshToken\":\"1QzZ5MwLXm1KAu8prjj6qg989plBFJlKkqLWt5Bn4ZBIvrdtjHlxbn0wUzGL5i3M\"}"
```

### `POST /auth/logout`
Revokes the supplied refresh token (and the associated session).

```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh-token-from-login>"}'
```

### `GET /auth/sessions`
Returns every active refresh session for the authenticated user (requires a valid access token).

```bash
curl http://localhost:3000/auth/sessions \
  -H "Authorization: Bearer <access-token>"
```

```json
[
  {
    "sessionId": "3c7c9a1e-16e1-4d6f-9f06-2b9c2a901234",
    "familyId": "c0f3e9ab-0bd5-4eb7-8a32-0a6a8790cabc",
    "createdAt": "2026-01-12T10:00:00.000Z",
    "updatedAt": "2026-01-12T11:45:00.000Z",
    "expiresAt": "2026-01-19T11:45:00.000Z",
    "maxExpiresAt": "2026-02-11T10:00:00.000Z",
    "metadata": {
      "deviceName": "Pixel 8 Pro",
      "ipAddress": "203.0.113.42"
    }
  }
]
```

### `DELETE /auth/sessions/:sessionId`
Revokes a single device while leaving other sessions untouched.

```bash
curl -X DELETE http://localhost:3000/auth/sessions/3c7c9a1e-16e1-4d6f-9f06-2b9c2a901234 \
  -H "Authorization: Bearer <access-token>"
```

### `DELETE /auth/sessions`
Revokes *all* active sessions for the current user—handy for "Log out of all devices" buttons.

```bash
curl -X DELETE http://localhost:3000/auth/sessions \
  -H "Authorization: Bearer <access-token>"
```
```

## Testing & linting

```bash
npm run lint
npm run test
```

> The project now depends on SQLite and TypeORM; remember to run `npm install` after pulling these changes so `sqlite3` bindings are compiled for your platform. If `npm install` fails due to missing build tools on Windows, install the recommended MSVC build chain (`npm install --global --production windows-build-tools`) or switch to WSL.


## Next steps

See [`docs/TODO.md`](docs/TODO.md) for planned improvements and open tasks.
