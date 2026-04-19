# security.argus.spring

`security.argus.spring` adapts `security.argus` into Spring Security.

It wires bearer-token authentication, a stateless filter chain, Spring Security context
integration, and method-level authorization annotations — all driven by Spring beans and
`application.properties`.

## Getting Started

Add `@EnableArgusMethodSecurity` to any `@Configuration` class in your application. This
imports the Argus Spring configuration.

```java
@Configuration
@EnableArgusMethodSecurity
class SecurityConfiguration
{
}
```

From there, provide the beans and properties described below. The library will assemble the
rest.

---

## Configuration Properties

All properties are under the `argus` prefix.

### Upstream token verification

These properties control how Argus trusts incoming tokens from your identity provider.

| Property                         | Required | Default | Description                                   |
|----------------------------------|----------|---------|-----------------------------------------------|
| `argus.upstream.hmac-secret`     | yes*     | —       | HMAC secret used to verify upstream tokens    |
| `argus.upstream.issuer`          | no       | —       | Expected issuer claim value                   |
| `argus.upstream.audiences`       | no       | empty   | Expected audience claim values                |
| `argus.upstream.clock-skew`      | no       | `PT0S`  | Tolerance for clock differences, e.g. `PT30S` |
| `argus.upstream.require-subject` | no       | `true`  | Whether a `sub` claim is required             |

*Required when using HMAC upstream token verification. RSA and EC upstream trust is configured
via beans — see the [Explicit bean configuration](#explicit-bean-configuration) section.

### Internal token contract

These properties control the tokens Argus mints internally after verifying the upstream token.

| Property                                    | Required | Default        | Description                             |
|---------------------------------------------|----------|----------------|-----------------------------------------|
| `argus.internal.hmac-secret`                | yes*     | —              | HMAC secret for signing internal tokens |
| `argus.internal.issuer`                     | no       | `argus`        | Issuer claim in minted tokens           |
| `argus.internal.audiences`                  | no       | empty          | Audience claims in minted tokens        |
| `argus.internal.token-ttl`                  | no       | `PT15M`        | Time-to-live for minted tokens          |
| `argus.internal.role-claim-name`            | no       | `roles`        | JWT claim name for roles                |
| `argus.internal.version-claim-name`         | no       | `ver`          | JWT claim name for version              |
| `argus.internal.upstream-issuer-claim-name` | no       | `upstream_iss` | JWT claim name for the upstream issuer  |

*Required when using HMAC internal token signing.

---

## Required Beans

Two beans must be provided regardless of the configuration path chosen.

### User resolver

Resolves a local application user from the upstream token's subject (or a configured claim).
Return `Optional.empty()` to reject authentication when the user cannot be found.

**Option A — implement `ArgusUserResolver<User>`:**

```java

@Bean
ArgusUserResolver<User> userResolver(UserRepository users)
{
	return externalId -> users.findByExternalId(externalId);
}
```

**Option B — provide a `Function<String, Optional<User>>` bean named `argusUserResolverFunction`:**

```java

@Bean
Function<String, Optional<User>> argusUserResolverFunction(UserRepository users)
{
	return users::findByExternalId;
}
```

If an `ArgusUserResolver` bean is present, the named function bean is ignored.

### Version resolver

Resolves the current token version for an authenticated subject. Argus checks this on every
request: if the version in the token does not match the value returned here, the request is
rejected as stale. Incrementing the stored version invalidates all existing tokens for that
subject without a denylist.

**Option A — implement `ArgusVersionResolver`:**

```java

@Bean
ArgusVersionResolver versionResolver(UserRepository users)
{
	return subject -> users.findBySubject(subject)
	                       .map(User::tokenVersion)
	                       .orElse(0L);
}
```

**Option B — provide a `Function<String, Long>` bean named `argusVersionResolverFunction`:**

```java

@Bean
Function<String, Long> argusVersionResolverFunction(UserRepository users)
{
	return subject -> users.currentTokenVersion(subject);
}
```

If an `ArgusVersionResolver` bean is present, the named function bean is ignored.

---

## Optional Override Beans

The following beans are created automatically with sensible defaults. Provide your own bean
of the same type to replace the default.

### Role resolver

Controls which roles are included in the minted token. The default includes no roles — you
must provide this bean to have roles in your tokens.

```java

@Bean
RoleResolver<User> roleResolver()
{
	return user -> user.roles();
}
```

`RoleResolver<User>` is from `de.gupta.security.argus.api.identity`.

### Local subject resolver

Maps your `User` to the subject string written into the minted token. The default uses
`String.valueOf(user)`. Provide this bean if your user type does not have a useful
`toString()`.

**Option A — implement `LocalSubjectResolver<User>`:**

```java

@Bean
LocalSubjectResolver<User> localSubjectResolver()
{
	return user -> user.id();
}
```

**Option B — provide a `Function<User, String>` bean named `argusLocalSubjectResolverFunction`:**

```java

@Bean
Function<User, String> argusLocalSubjectResolverFunction()
{
	return User::id;
}
```

`LocalSubjectResolver<User>` is from `de.gupta.security.argus.api.identity`. If a typed
`LocalSubjectResolver` bean is present, the named function bean is ignored.

### User token version resolver

Resolves the version value to embed in the minted token at the time of minting. This is
distinct from the version resolver (which is checked on every request). The default returns
`1L`. Provide this bean if the version in newly minted tokens should reflect the current
stored value.

**Option A — implement `UserTokenVersionResolver<User>`:**

```java

@Bean
UserTokenVersionResolver<User> userTokenVersionResolver()
{
	return user -> user.tokenVersion();
}
```

**Option B — provide a `ToLongFunction<User>` bean named `argusUserTokenVersionResolverFunction`:**

```java

@Bean
ToLongFunction<User> argusUserTokenVersionResolverFunction()
{
	return User::tokenVersion;
}
```

`ToLongFunction<User>` is from `java.util.function` — it avoids boxing the returned `long`.
`UserTokenVersionResolver<User>` is from `de.gupta.security.argus.api.identity`. If a typed
`UserTokenVersionResolver` bean is present, the named function bean is ignored.

### Token authentication cache

Enables result caching to avoid running the full pipeline on every request. Disabled by
default. See `security.argus` documentation for caching behaviour and TTL semantics.

The cache implementation is provided by `security.argus`:

```java
import de.gupta.security.argus.api.cache.AuthenticationCacheConfiguration;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;

@Bean
TokenAuthenticationCache tokenAuthenticationCache()
{
    return AuthenticationCacheConfiguration.withDefaults().build();
}
```

### Clock

Used for all time-sensitive operations. Defaults to `Clock.systemUTC()`. Useful for testing.

```java

@Bean
Clock clock()
{
	return Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
}
```

### Authentication entry point and access denied handler

The default entry point sends HTTP 401 with no body on unauthenticated requests.
The default denied handler sends HTTP 403 with no body on authorization failures.

Both `ArgusAuthenticationEntryPoint` and `ArgusAccessDeniedHandler` are `final` —
they cannot be subclassed. To replace them entirely, declare your own `SecurityFilterChain`
bean and wire your own implementations directly:

```java
@Bean
@Order(ArgusFilterChainOrder.DEFAULT - 1)
SecurityFilterChain myChain(final HttpSecurity http,
                            final ArgusAuthenticationFilter filter) throws Exception
{
	return http.csrf(AbstractHttpConfigurer::disable)
	           .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	           .exceptionHandling(e -> e
					   .authenticationEntryPoint(new MyAuthenticationEntryPoint())
			           .accessDeniedHandler(new MyAccessDeniedHandler()))
	           .authorizeHttpRequests(a -> a.anyRequest().authenticated())
	           .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
	           .build();
}
```

`MyAuthenticationEntryPoint` must implement
`org.springframework.security.web.AuthenticationEntryPoint` and
`MyAccessDeniedHandler` must implement
`org.springframework.security.web.access.AccessDeniedHandler`.

### Filter chain customiser

Applied to `HttpSecurity` before the catch-all `anyRequest().authenticated()` rule. Use this
to permit specific paths without replacing the entire filter chain.

```java
@Bean
ArgusSecurityCustomizer argusSecurityCustomizer()
{
    return http -> http.authorizeHttpRequests(
            auth -> auth.requestMatchers("/public/**", "/actuator/health").permitAll()
    );
}
```

---

## Replacing the Default Filter Chain

The default filter chain is `@ConditionalOnMissingBean(SecurityFilterChain.class)`. Declare
your own `SecurityFilterChain` bean to replace it entirely. Use `ArgusFilterChainOrder.DEFAULT`
to position your chain relative to the default.

```java
@Bean
@Order(ArgusFilterChainOrder.DEFAULT - 1)
SecurityFilterChain securityFilterChain(final HttpSecurity http,
                                        final ArgusAuthenticationFilter filter,
                                        final ArgusAuthenticationEntryPoint entryPoint,
                                        final ArgusAccessDeniedHandler deniedHandler) throws Exception
{
    return http.csrf(AbstractHttpConfigurer::disable)
               .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .exceptionHandling(e -> e
					   .authenticationEntryPoint(entryPoint)
		               .accessDeniedHandler(deniedHandler))
               .authorizeHttpRequests(a -> a
                       .requestMatchers("/public/**").permitAll()
                       .anyRequest().authenticated())
               .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
               .build();
}
```

---

## Explicit Bean Configuration

For full control over trust configuration (RSA, EC keys, custom audiences, per-environment
policies), provide the argus domain beans directly instead of using properties. This path
activates when all five beans below are present and no `Authenticator` or
`AuthenticatorConfiguration` bean exists.

```java

@Bean
UpstreamTrustConfiguration upstreamTrustConfiguration()
{ ...}

@Bean
AuthenticatedTokenContract authenticatedTokenContract()
{ ...}

@Bean
AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration()
{ ...}

@Bean
AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration()
{ ...}

@Bean
IdentityMappingConfiguration<?, ?> identityMappingConfiguration()
{ ...}
```

---

## Full Control

Provide an `Authenticator` bean to bypass all assembly entirely. The library still contributes
the filter chain, Spring Security integration, and method security beans.

```java

@Bean
Authenticator authenticator()
{
	return AuthenticatorFactory.create(
			AuthenticatorConfiguration.<String, User>builder()
			                          .upstreamTrustConfiguration(...)
                    .authenticatedTokenContract(...)
                    .authenticatedTokenMintingConfiguration(...)
                    .authenticatedTokenVerificationConfiguration(...)
                    .identityMappingConfiguration(...)
                    .build());
}
```

---

## Method Security

```java
@RestController
class ExampleController
{
	@GetMapping("/me")
	@RequireAuthenticated
	String me()
	{
		return "authenticated";
	}

	@GetMapping("/admin")
    @RequireRole("ADMIN")
	String admin()
	{
		return "restricted to ADMIN";
	}

	@GetMapping("/staff")
	@RequireAnyRole({"ADMIN", "SUPPORT"})
	String staff()
	{
		return "restricted to ADMIN or SUPPORT";
	}
}
```

Standard Spring Security annotations also work, as Argus roles are mapped to Spring
`GrantedAuthority` values:

```java
@PreAuthorize("hasRole('ADMIN')")
```

---

## Reading the Current Identity

Inject `ArgusSecurityContextQueryManager` to query the authenticated identity within a
request without depending on Spring Security types directly.

```java
@Service
class CurrentUserService
{
    private final ArgusSecurityContextQueryManager securityContextQueryManager;

	Optional<String> currentSubject()
    {
		return securityContextQueryManager.subject();
    }

    boolean isAdmin()
    {
        return securityContextQueryManager.hasRole("ADMIN");
    }

	Set<String> currentRoles()
	{
		return securityContextQueryManager.roles();
	}
}
```