# JWT NestJS Demo

A focused NestJS API that demonstrates how to issue and validate JSON Web Tokens (JWT) securely. It follows the checklist in `todo.md`, showing how to:

- Generate JWTs only after successful authentication
- Sign tokens with strong secrets (or drop-in RSA/ECDSA keys)
- Control token expiration through the `exp` claim
- Keep token payloads lean (only user id, email, roles)
- Validate token signatures and registered claims on every protected request

## Prerequisites

- Node.js 18+
- npm (comes with Node)

## Quick start

```bash
npm install
copy .env.example .env   # then edit the secrets!
npm run start:dev

```

> On macOS/Linux use `cp .env.example .env` instead of `copy`.

The API listens on `http://localhost:3000` by default.

## Environment variables

| Key | Description |
| --- | --- |
| `PORT` | API port (defaults to 3000) |
| `JWT_ACCESS_SECRET` | Strong random string or base64 key used to sign tokens |
| `JWT_ACCESS_EXPIRES_IN` | Access token lifetime (e.g., `15m`, `1h`) |
| `JWT_AUDIENCE` | Expected `aud` claim used by the JWT strategy |
| `JWT_ISSUER` | Expected `iss` claim used by the JWT strategy |
| `JWT_REFRESH_EXPIRES_IN` | Refresh token lifetime (default `7d`) |

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

:: Windows CMD profile
curl http://localhost:3000/profile -H "Authorization: Bearer <token>"
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
```

## Testing & linting

```bash
npm run lint
npm run test
```

## Next steps

- Replace the in-memory users list with a database lookup
- Persist issued tokens (by device) to support revocation and multi-session management

Enjoy building securely! 🚀
