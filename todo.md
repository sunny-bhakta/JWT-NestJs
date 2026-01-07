## JWT Implementation Checklist

### Implementation
- [x] Generate JWT on successful authentication
- [x] Use strong secret keys or RSA/ECDSA key pairs
- [x] Set appropriate token expiration (`exp` claim)
- [x] Store minimal user info in token payload
- [x] Validate token signature and claims on each request

### Security
- Use HTTPS for all token transmission
- Store tokens securely (e.g., HTTP-only cookies or secure storage)
- Avoid storing sensitive data in JWT payload
- JWT security attacks & prevention
- Implement token revocation (blacklist/whitelist)
- Rotate signing keys periodically

### Best Practices
- Use short-lived access tokens and refresh tokens
- Validate token audience (`aud`) and issuer (`iss`)
- Limit token scope and permissions
- Handle token errors gracefully
- Monitor and log suspicious token usage

### Multiple Sessions
- Support multiple tokens per user (e.g., per device)
- Track issued tokens in a database (with device/session info)
- Allow independent session management

### All Sessions Logout
- Invalidate all tokens for a user (e.g., by updating a `tokenVersion` or maintaining a blacklist)
- Remove/expire refresh tokens from storage
- Notify clients to clear tokens on logout
- Ensure immediate effect across all devices/sessions

### When NOT to Use JWT

JWT is **not recommended** for:
- Highly sensitive sessions
- Applications requiring forced logout for all sessions
- Banking-grade security (prefer server-side sessions with DB/Redis)
- Scenarios needing secure session-based authentication

**Alternatives and Enhancements:**
- Consider a secure session-based auth system for sensitive use cases
- Use a JWT + session hybrid approach for flexibility
- Implement logout from all devices (token invalidation)
- Add 2FA or OTP for enhanced security
