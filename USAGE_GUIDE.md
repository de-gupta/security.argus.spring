# Usage Guide

This guide covers the complete flow for integrating `security.argus.spring` into a Spring
Boot application — from project setup through signup, login, authenticated requests,
token expiry, and revocation.

---

## The Parties

| Party                       | Role                                                            |
|-----------------------------|-----------------------------------------------------------------|
| **End user**                | The person using your application                               |
| **Client**                  | Mobile app, SPA, CLI — runs on the user's device                |
| **Identity Provider (IdP)** | Supabase, Auth0, or your own token issuer — manages credentials |
| **Your backend**            | Spring Boot app using this stack                                |
| **Your database**           | Stores your `User` entity and the `lastRevokedAt` timestamp     |

---

## What the Stack Does (and Does Not Do)

The stack handles exactly one thing: **authenticating an incoming HTTP request that carries
a bearer JWT token.**

| Concern                                                 | Handled by                                   |
|---------------------------------------------------------|----------------------------------------------|
| Verifying the upstream JWT signature and claims         | This stack (themis)                          |
| Revocation check (token issued before last revocation?) | This stack (augustus)                        |
| Exchanging the upstream token for an internal one       | This stack (hermes)                          |
| Populating the Spring `SecurityContext`                 | This stack (argus.spring)                    |
| Role-based method security                              | This stack (argus.spring)                    |
| **User signup**                                         | **Your backend**                             |
| **Login / credential verification**                     | **IdP or your own auth endpoint**            |
| **Token issuance**                                      | **IdP or your own endpoint**                 |
| **Refresh token management**                            | **IdP SDK on client + IdP server-side**      |
| **Password reset, email verification**                  | **IdP**                                      |
| **Per-device session revocation**                       | **Not supported — only per-user revocation** |
| **Audit logging of auth events**                        | **Your code**                                |

---

## Your User Entity

Add three fields to your existing `User` entity:

```java

@Entity
public class User
{
	@Id
	UUID id;

	String email;

	// The IdP's identifier for this user (the `sub` claim in their JWT).
	// This links your local User to the IdP account.
	String externalId;

	// Your application roles, e.g. {"ROLE_USER", "ROLE_ADMIN"}.
	Set<String> roles;

	// Soft revocation timestamp. Default: Instant.EPOCH (never revoked).
	// Bump this to invalidate all tokens issued before this point in time.
	Instant lastRevokedAt = Instant.EPOCH;

	// ... rest of your domain fields
}
```

---

## Project Setup

### Dependencies

```xml

<dependency>
    <groupId>io.github.de-gupta</groupId>
    <artifactId>security.argus.spring</artifactId>
    <version><!-- see security.bom --></version>
</dependency>
```

Or import the BOM and omit versions:

```xml

<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.github.de-gupta</groupId>
            <artifactId>security.bom</artifactId>
            <version>1.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### Properties

```yaml
argus:
  upstream:
    hmac-secret: ${IDP_JWT_SECRET}              # from your IdP dashboard
    issuer: https://your-project.supabase.co/auth/v1
    audiences: authenticated
    require-subject: true
    clock-skew: PT30S                           # tolerate 30s clock drift between IdP and server
  internal:
    issuer: your-app
    hmac-secret: ${INTERNAL_JWT_SECRET}         # your own randomly-generated secret
    token-ttl: PT15M
```

### Security configuration

```java

@Configuration
@EnableArgusMethodSecurity
class SecurityConfiguration
{

	@Bean
	ArgusUserResolver<User> userResolver(UserRepository users)
	{
		return externalId -> users.findByExternalId(externalId);
	}

	@Bean
	ArgusVersionResolver versionResolver(UserRepository users)
	{
		return externalId -> users.findByExternalId(externalId)
		                          .map(User::getLastRevokedAt)
		                          .orElse(Instant.EPOCH);
	}

	@Bean
	RoleResolver<User> roleResolver()
	{
		return user -> user.getRoles();
	}

	@Bean
	LocalSubjectResolver<User> localSubjectResolver()
	{
		return user -> user.getId().toString();
	}
}
```

That is the entirety of the security configuration. No filter chains, no
`WebSecurityConfigurerAdapter`, no token parsing code.

---

## Flow: Signup

The stack is not involved. Signup is a pure application concern.

```
Client → POST /signup  { email, password }
Backend:
  1. Create User record in your database
     (set lastRevokedAt = Instant.EPOCH)
  2. Call the IdP API to create the IdP account
     (Supabase: admin.auth.createUser, Auth0: Management API)
  3. Store the IdP-assigned externalId alongside the User
  4. Return 201 Created
```

---

## Flow: Login

The stack is not involved in issuing the token. It takes over from the first
authenticated request onwards.

```
Client → POST /login  { email, password }
         (or client calls IdP auth endpoint directly)

Backend (or IdP):
  1. Verify credentials
  2. Issue access token (JWT) and refresh token
  3. Return { accessToken, refreshToken }

Client:
  Stores both tokens locally.
  Sends accessToken as Authorization: Bearer <token> on every subsequent request.
```

The access token is a JWT containing:

| Claim | Description                                                       |
|-------|-------------------------------------------------------------------|
| `sub` | The IdP's identifier for this user — your `externalId`            |
| `iat` | When the token was issued — used by argus for revocation checking |
| `exp` | When the token expires                                            |
| `iss` | The IdP's issuer URL — must match `argus.upstream.issuer`         |
| `aud` | Your app's audience — must match `argus.upstream.audiences`       |

---

## Flow: Authenticated Request

This is where the stack operates. Nothing in your application code needs to know
any of this is happening.

```
Client → GET /api/orders
          Authorization: Bearer <access_token>

ArgusAuthenticationFilter (automatic):

  [1] Themis verifies the upstream token:
        - Signature valid against argus.upstream.hmac-secret?  ✓
        - Not expired?                                          ✓
        - iss matches argus.upstream.issuer?                   ✓
        - aud matches argus.upstream.audiences?                ✓
        - sub present (require-subject: true)?                 ✓

  [2] iat claim present?                                       ✓

  [3] Augustus revocation check:
        - UserResolver(token.sub) → looks up User in your DB
        - UserRevocationResolver(user) → reads user.lastRevokedAt
        - token.iat >= user.lastRevokedAt?                     ✓  → current

  [4] Hermes exchange:
        - UserResolver(token.sub) → User entity
        - RoleResolver(user) → {"ROLE_USER", "ROLE_ADMIN"}
        - LocalSubjectResolver(user) → "550e8400-e29b-41d4..."
        - Mints a short-lived internal token with those claims

  [5] Spring SecurityContext populated with AuthenticatedIdentity

Your controller:
  @GetMapping("/api/orders")
  @RequireRole("USER")
  List<Order> getOrders() {
      String subject = securityContextQueryManager.subject().orElseThrow();
      return orderService.findBySubject(subject);
  }
```

**Performance note:** The user is looked up twice per request — once in the
revocation check (step 3) and once in the exchange (step 4). This is a known
trade-off. If this becomes a bottleneck, add a request-scoped cache in front
of your `UserRepository`.

---

## Flow: Token Expiry and Refresh

```
Client → GET /api/orders
          Authorization: Bearer <expired_access_token>

Stack → Themis: token is expired → InvalidCredential → 401 Unauthorized

Client (IdP SDK detects 401):
  → Calls IdP refresh endpoint with stored refresh token
  → IdP returns new access token (new iat, new exp)
  → Client retries original request with new token

Stack → full pipeline runs again with new token → 200 OK
```

This is transparent to your application code. The client SDK handles it automatically.

---

## Flow: Forced Logout / Revocation

To invalidate all of a user's active sessions (password change, account suspension,
admin action):

```java

@Transactional
public void revokeUser(UUID userId)
{
	User user = userRepository.findById(userId).orElseThrow();

	// 1. Bump the revocation timestamp in your database.
	//    Any token with iat < now will be rejected on the next request.
	user.setLastRevokedAt(Instant.now());
	userRepository.save(user);

	// 2. If caching is enabled, evict immediately.
	//    Without this, cached results survive until their TTL expires.
	tokenCache.invalidateBySubject(user.getId().toString());

	// 3. Revoke refresh tokens at the IdP.
	//    Without this, the client SDK will silently obtain a new access token
	//    with a later iat, which would pass the revocation check.
	idpClient.revokeUserSessions(user.getExternalId());
}
```

**All three steps are required for complete, immediate revocation.**

Skipping step 2 means revocation takes effect only after the cache TTL (default 5 minutes).
Skipping step 3 means a client with a valid refresh token can silently obtain a new
access token that postdates the revocation.

---

## Flow: Permit Specific Public Paths

Some endpoints (health check, public API, auth endpoints) should not require a token:

```java

@Bean
ArgusSecurityCustomizer argusSecurityCustomizer()
{
	return http -> http.authorizeHttpRequests(
			auth -> auth.requestMatchers("/public/**", "/actuator/health", "/login", "/signup")
			            .permitAll()
	);
}
```

---

## Flow: Read the Current Identity

Inject `ArgusSecurityContextQueryManager` anywhere in your application:

```java

@Service
class CurrentUserService
{
	private final ArgusSecurityContextQueryManager security;

	String currentSubject()
	{
		return security.subject().orElseThrow();
	}

	boolean isAdmin()
	{
		return security.hasRole("ADMIN");
	}

	Set<String> currentRoles()
	{
		return security.roles();
	}
}
```

---

## Development Without an IdP

If you do not yet have an IdP, generate tokens yourself. Configure argus to trust
your own signing secret:

```yaml
argus:
  upstream:
    hmac-secret: ${DEV_SIGNING_SECRET}
    issuer: your-app-dev
    require-subject: true
  internal:
    issuer: your-app-dev
    hmac-secret: ${DEV_INTERNAL_SECRET}
```

Your login endpoint mints the upstream token directly:

```java

@PostMapping("/login")
ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request)
{
	User user = userService.authenticate(request.email(), request.password());
	String token = Jwts.builder()
	                   .subject(user.getExternalId())
	                   .issuer("your-app-dev")
	                   .audience().add("your-app").and()
	                   .issuedAt(Date.from(Instant.now()))
	                   .expiration(Date.from(Instant.now().plus(Duration.ofHours(1))))
	                   .signWith(Keys.hmacShaKeyFor(devSigningSecret.getBytes(StandardCharsets.UTF_8)))
	                   .compact();
	return ResponseEntity.ok(new LoginResponse(token));
}
```

When you switch to Supabase or Auth0 later, change `argus.upstream.hmac-secret`
and `argus.upstream.issuer` in your properties. Your application code does not change.

---

## Enabling Caching

By default there is no caching — every request runs the full pipeline. For production,
add Caffeine-backed caching:

```java

@Bean
TokenAuthenticationCache tokenAuthenticationCache()
{
	return AuthenticationCacheConfiguration.withDefaults().build();
	// defaults: 10,000 entries, 5-minute success TTL, 30-second failure TTL
}
```

Custom TTL:

```java

@Bean
TokenAuthenticationCache tokenAuthenticationCache()
{
	return AuthenticationCacheConfiguration.of(
			5_000L,
			Duration.ofMinutes(2),
			Duration.ofSeconds(15)
	).build();
}
```

Cache entries are keyed by the SHA-256 hash of the raw bearer token — the token
string itself is never stored in memory.

**When using caching, you must call `tokenCache.invalidateBySubject(subject)`
whenever you bump `lastRevokedAt`.** See the revocation flow above.

---

## Known Limitations

**Per-device revocation is not supported.**
The timestamp model revokes all sessions for a user simultaneously. If you need to
revoke one device while leaving others active, you need a per-session denylist,
which this stack does not provide.

**RSA and EC upstream keys require explicit bean configuration.**
The `argus.upstream.*` properties only support HMAC. For Auth0 (RS256) or other
asymmetric-key IdPs, declare `UpstreamTrustConfiguration` as a bean directly rather
than using properties. See the `README.md` explicit bean configuration section.

**Two user lookups per request.**
The revocation check (augustus) and the token exchange (hermes) each independently
resolve the user from the external identity. A request-scoped cache in front of your
`UserRepository` eliminates the second DB round-trip if latency is a concern.

**`AuthenticationUnavailable` produces 401, not 503.**
If your user store is unavailable, the revocation check fails and the request is
rejected with 401 Unauthorized. To return 503 Service Unavailable instead, replace
the default filter chain with a custom one that installs your own
`AuthenticationEntryPoint`.