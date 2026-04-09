# security.argus.spring

`security.argus.spring` adapts `security.argus` into Spring Security.

It provides:
- bearer-token authentication against Argus
- Spring `SecurityContext` population on successful authentication
- Spring `AuthenticationProvider`, filter, entry point, and denied handler beans
- a small business-friendly context bean
- standard `@PreAuthorize` support and Argus-flavored method-security annotations

It does not own your application's full `SecurityFilterChain`.

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

## Basic Usage

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

    @Bean
    SecurityFilterChain securityFilterChain(final HttpSecurity http,
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
