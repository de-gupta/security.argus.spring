# security.argus.spring

`security.argus.spring` adapts `security.argus` into Spring Security.

It provides:
- bearer-token authentication against Argus
- Spring `SecurityContext` population on successful authentication
- Spring `AuthenticationProvider`, filter, entry point, and denied handler beans
- a default stateless `SecurityFilterChain` with sensible defaults
- a small business-friendly context bean
- standard `@PreAuthorize` support and Argus-flavored method-security annotations

## What You Provide

You can use it in two ways.

### 1. Direct Argus mode
Provide an `Authenticator` bean yourself.

### 2. Argus assembly mode
Provide the Argus ingredient beans:
- `UpstreamTrustConfiguration`
- `AuthenticatedTokenContract`
- `AuthenticatedTokenMintingConfiguration`
- `AuthenticatedTokenVerificationConfiguration`
- `IdentityMappingConfiguration<?, ?>`
- optional `Clock`
- optional `TokenAuthenticationCache`

The library will assemble the `Authenticator` for you.

## What You Get

The library exposes Spring beans for:
- `ArgusAuthenticationFilter`
- `AuthenticationManager`
- `ArgusAuthenticationProvider`
- `ArgusAuthenticationEntryPoint`
- `ArgusAccessDeniedHandler`
- `ArgusSecurityContextQueryManager`
- `argusMethodAccess`
- a default `SecurityFilterChain` (stateless, CSRF disabled, all endpoints require authentication)

## Zero-Configuration Usage

If you provide an `Authenticator` bean (or the ingredient beans), the library wires everything
automatically. All endpoints require authentication by default.

```java
@Configuration
@EnableArgusMethodSecurity
class SecurityConfiguration
{
    @Bean
    Authenticator authenticator()
    {
        return AuthenticatorFactory.create(authenticatorConfiguration());
    }
}
```

That is the entire security configuration. No `SecurityFilterChain` bean needed.

## Customising The Default Filter Chain

To permit specific paths or add other customisations without replacing the entire chain,
provide an `ArgusSecurityCustomizer` bean. It is applied before the catch-all
`anyRequest().authenticated()` rule, so permit-list matchers take precedence.

```java
@Bean
ArgusSecurityCustomizer argusSecurityCustomizer()
{
    return http -> http.authorizeHttpRequests(
            auth -> auth.requestMatchers("/public/**", "/actuator/health").permitAll()
    );
}
```

## Replacing The Default Filter Chain

To take full control, declare your own `SecurityFilterChain` bean. The library's default chain
is annotated `@ConditionalOnMissingBean(SecurityFilterChain.class)` and steps aside entirely.
Use `ArgusFilterChainOrder.DEFAULT` to position your chain relative to the default if you need
multiple chains.

```java
@Bean
@Order(ArgusFilterChainOrder.DEFAULT - 1)
SecurityFilterChain myChain(final HttpSecurity http,
                            final ArgusAuthenticationFilter argusAuthenticationFilter,
                            final ArgusAuthenticationEntryPoint authenticationEntryPoint,
                            final ArgusAccessDeniedHandler accessDeniedHandler) throws Exception
{
    return http.csrf(AbstractHttpConfigurer::disable)
               .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .exceptionHandling(exceptions -> exceptions
                       .authenticationEntryPoint(authenticationEntryPoint)
                       .accessDeniedHandler(accessDeniedHandler))
               .authorizeHttpRequests(authorize -> authorize
                       .requestMatchers("/public/**").permitAll()
                       .anyRequest().authenticated())
               .addFilterBefore(argusAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
               .build();
}
```

## Controller Example

Using the custom Argus annotation:

```java
@RestController
class AdminController
{
    @GetMapping("/admin/reports")
    @RequireRole("ADMIN")
    String reports()
    {
        return "restricted";
    }
}
```

Using standard Spring Security annotations also works because Argus roles are mapped into Spring authorities:

```java
@RestController
class AdminController
{
    @GetMapping("/admin/reports")
    @PreAuthorize("hasRole('ADMIN')")
    String reports()
    {
        return "restricted";
    }
}
```

## Reading The Current Identity

```java
@Service
class CurrentUserService
{
    private final ArgusSecurityContextQueryManager securityContextQueryManager;

    CurrentUserService(final ArgusSecurityContextQueryManager securityContextQueryManager)
    {
        this.securityContextQueryManager = securityContextQueryManager;
    }

    String currentSubject()
    {
        return securityContextQueryManager.subject().orElseThrow();
    }

    boolean isAdmin()
    {
        return securityContextQueryManager.hasRole("ADMIN");
    }
}
```

## Caching

If you provide a `TokenAuthenticationCache` bean, `argus.spring` picks it up automatically and
passes it into the assembled `AuthenticatorConfiguration`. No other changes are needed.

```java
@Bean
TokenAuthenticationCache tokenAuthenticationCache()
{
    return CaffeineTokenAuthenticationCache.create(AuthenticationCacheConfiguration.withDefaults());
}
```

See the `security.argus` README for full caching documentation.
