## JWT Implementation Checklist

### Implementation
- [x] Generate JWT on successful authentication
- [x] Use strong secret keys 
- [ ] RSA/ECDSA key pairs
- [x] Set appropriate token expiration (`exp` claim)
- [x] Store minimal user info in token payload
- [x] Validate token signature and claims on each request
- [x] Introduce refresh tokens + rotation

### Security
- [x] Use HTTPS for all token transmission
- [x] Store tokens securely (e.g., HTTP-only cookies or secure storage)
- [x] Avoid storing sensitive data in JWT payload *(tokens now only include id/email/roles)*
- [x] JWT security attacks & prevention *(documented in README “JWT security attacks & prevention” section)*
- [x] Implement token revocation (blacklist/whitelist)
- [x] Rotate signing keys periodically

### Best Practices
- [x] Use short-lived access tokens and refresh tokens
- [x] Limit token scope and permissions
- [x] Handle token errors gracefully *(TokenErrorException + structured 401 responses)*
- [x] Validate token audience (`aud`) and issuer (`iss`) *(JwtStrategy enforces configured claims)*
- [x] Monitor and log suspicious token usage *(TokenEventsService records failed access/refresh attempts)*

### Multiple Sessions
- [x] Support multiple tokens per user (e.g., per device)
- [x] Track issued tokens in a database (with device/session info)
- [x] Allow independent session management
- [x] Token family IDs
- [x] Sliding expiration
- [ ] IP change detection
- [ ] Redis cache for session lookup
- [ ] WebAuthn binding
- [ ] Device fingerprinting
### All Sessions Logout
- [ ] Invalidate all tokens for a user (e.g., by updating a `tokenVersion` or maintaining a blacklist)
- [ ] Remove/expire refresh tokens from storage
- [ ] Notify clients to clear tokens on logout
- [ ] Ensure immediate effect across all devices/sessions

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
