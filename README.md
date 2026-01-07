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

```

The API listens on `http://localhost:3000` by default.

## Environment variables

| Key | Description |
| --- | --- |
| `PORT` | API port (defaults to 3000) |
| `JWT_ACCESS_SECRET` | Strong random string or base64 key used to sign tokens |
| `JWT_ACCESS_EXPIRES_IN` | Access token lifetime (e.g., `15m`, `1h`) |
| `JWT_AUDIENCE` | Expected `aud` claim used by the JWT strategy |
| `JWT_ISSUER` | Expected `iss` claim used by the JWT strategy |

> 💡 Swap `JWT_ACCESS_SECRET` for RSA/ECDSA key pairs by pointing `JwtModule` to `privateKey`/`publicKey` files when you’re ready for asymmetric signing.

## Demo credentials

| Email | Password | Roles |
| --- | --- | --- |
| `ada@example.com` | `ChangeMe123!` | `user` |
| `admin@example.com` | `AdminPass123!` | `admin` |

The passwords are hashed with bcrypt and stored only inside the in-memory user service.

## API reference

### `POST /auth/login`
Authenticates the user and returns a signed JWT.

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
  "user": {
    "id": "1",
    "email": "ada@example.com",
    "name": "Ada Lovelace",
    "roles": ["user"]
  }
}
```

### `GET /profile`
Protected route that validates the bearer token signature, issuer, audience, and expiration before returning the minimal profile derived from the token payload.

```bash
# Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"ChangeMe123!"}'

# For Windows
curl -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d "{\"email\":\"ada@example.com\",\"password\":\"ChangeMe123!\"}"

# Use the returned token
curl http://localhost:3000/profile \
  -H "Authorization: Bearer <token>"

  curl http://localhost:3000/profile ^
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJhZGFAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJ1c2VyIl0sImlhdCI6MTc2NzgwMDkxNywiZXhwIjoxNzcwMzkyOTE3LCJhdWQiOiJqd3QtbmVzdC1jbGllbnQiLCJpc3MiOiJqd3QtbmVzdC1hcGkifQ.V8i2254dp80Ff3cevvM_qA3R6tqvGz4bFV1Uft8E1mw"
```

## Testing & linting

```bash
npm run lint
npm run test
```

## Next steps

- Replace the in-memory users list with a database lookup
- Introduce refresh tokens + rotation for long-lived sessions
- Persist issued tokens (by device) to support revocation and multi-session management

Enjoy building securely! 🚀
