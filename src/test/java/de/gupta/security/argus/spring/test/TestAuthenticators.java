package de.gupta.security.argus.spring.test;

import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.authentication.AuthenticatorFactory;
import de.gupta.security.argus.api.identity.AuthenticatedSubjectVersionResolver;
import de.gupta.security.argus.api.identity.ExternalIdentityAdapter;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.token.TokenSignerConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.identity.AuthenticatedIdentity;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public final class TestAuthenticators
{
    public static final Clock CLOCK = Clock.fixed(Instant.parse("2026-04-09T12:00:00Z"), ZoneOffset.UTC);
    public static final String UPSTREAM_ISSUER = "supabase";
    public static final String INTERNAL_ISSUER = "argus";
    public static final String AUDIENCE = "inventory";
    public static final String UPSTREAM_SECRET = "upstream-secret-value-that-is-long-enough";
    public static final String DIFFERENT_UPSTREAM_SECRET = "other-upstream-secret-value-long-enough";
    public static final String INTERNAL_SECRET = "internal-secret-value-that-is-long-enough";

    public static Authenticator directAuthenticator(final AtomicLong currentVersion)
    {
        return AuthenticatorFactory.create(authenticatorConfiguration(currentVersion));
    }

    public static AuthenticatorConfiguration<String, String> authenticatorConfiguration(final AtomicLong currentVersion)
    {
        return AuthenticatorConfiguration.<String, String>builder()
                .upstreamTrustConfiguration(upstreamTrustConfiguration())
                .authenticatedTokenContract(authenticatedTokenContract())
                .authenticatedTokenMintingConfiguration(authenticatedTokenMintingConfiguration())
                .authenticatedTokenVerificationConfiguration(authenticatedTokenVerificationConfiguration())
                .identityMappingConfiguration(identityMappingConfiguration(_ -> currentVersion.get()))
                .clock(CLOCK)
                .build();
    }

    public static UpstreamTrustConfiguration upstreamTrustConfiguration()
    {
        return UpstreamTrustConfiguration.Hmac.of(TokenTrustPolicy.of(Duration.ZERO,
                        true,
                        Set.of(AUDIENCE),
                        Optional.of(UPSTREAM_ISSUER)),
                UPSTREAM_SECRET);
    }

    public static AuthenticatedTokenContract authenticatedTokenContract()
    {
        return AuthenticatedTokenContract.of(INTERNAL_ISSUER,
                Set.of(AUDIENCE),
                Duration.ofMinutes(15));
    }

    public static AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration()
    {
        return AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Hmac.of(INTERNAL_SECRET));
    }

    public static AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration()
    {
        return AuthenticatedTokenVerificationConfiguration.of(TokenTrustPolicy.of(Duration.ZERO,
                true,
                Set.of(AUDIENCE),
                Optional.of(INTERNAL_ISSUER)));
    }

    public static IdentityMappingConfiguration<String, String> identityMappingConfiguration(
            final AuthenticatedSubjectVersionResolver authenticatedSubjectVersionResolver)
    {
        return IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
                externalIdentity -> switch (externalIdentity)
                {
                    case "missing-user" -> Optional.empty();
                    case "exploding-user" -> throw new IllegalStateException("user lookup offline");
                    default -> Optional.of(externalIdentity.replace("external-", ""));
                },
                user -> switch (user)
                {
                    case "missing-subject" -> " ";
                    case "stale-user" -> "local-stale-user";
                    default -> "local-" + user;
                },
                user -> switch (user)
                {
                    case "admin-user" -> Set.of("ROLE_USER", "ROLE_ADMIN");
                    case "support-user" -> Set.of("ROLE_USER", "ROLE_SUPPORT");
                    default -> Set.of("ROLE_USER");
                },
                user -> "stale-user".equals(user) ? 7L : 3L,
                authenticatedSubjectVersionResolver);
    }

    public static AuthenticatedIdentity authenticatedIdentity(final AtomicLong currentVersion)
    {
        final AuthenticationResult result = directAuthenticator(currentVersion).authenticate(token("external-user"));
        return ((AuthenticationSuccess) result).identity();
    }

    public static String token(final String subject)
    {
        return token(subject, UPSTREAM_SECRET);
    }

    public static String invalidSignatureToken(final String subject)
    {
        return token(subject, DIFFERENT_UPSTREAM_SECRET);
    }

    private static String token(final String subject, final String secret)
    {
        final var builder = Jwts.builder()
                                .subject(subject)
                                .issuer(UPSTREAM_ISSUER)
                                .issuedAt(Date.from(CLOCK.instant()))
                                .expiration(Date.from(CLOCK.instant().plus(Duration.ofMinutes(30))))
                                .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)));
        builder.audience().add(Set.of(AUDIENCE)).and();
        return builder.compact();
    }

    private TestAuthenticators()
    {
    }
}

