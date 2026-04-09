package de.gupta.security.argus.spring.api.authentication;

import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.authentication.AuthenticatorFactory;
import de.gupta.security.argus.api.identity.ExternalIdentityAdapter;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.spring.adapter.authentication.ArgusAuthenticationProvider;
import de.gupta.security.argus.spring.test.TestAuthenticators;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("ArgusAuthenticationProvider.authenticate")
@TestInstance(PER_CLASS)
final class ArgusAuthenticationProviderAuthenticateTest
{
    private record SuccessCase(String description, Authentication request)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record FailureCase(String description,
                               Authentication request,
                               Class<? extends Exception> expectedType)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record UnsupportedCase(String description, Authentication request)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record SupportsCase(String description, Class<?> authenticationType, boolean expected)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    @Nested
    @DisplayName("as successful authentication")
    @TestInstance(PER_CLASS)
    final class SuccessfulAuthentication
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldReturnAuthenticatedToken(final SuccessCase input)
        {
            final var provider = new ArgusAuthenticationProvider(TestAuthenticators.directAuthenticator(new AtomicLong(3L)));

            final Authentication result = provider.authenticate(input.request());

            assertThat(result)
                    .as(input.description())
                    .isInstanceOf(ArgusAuthenticationToken.class);
            assertThat(result.isAuthenticated())
                    .as(input.description())
                    .isTrue();
            assertThat(result.getName())
                    .as(input.description())
                    .isEqualTo("local-admin-user");
            assertThat(result.getAuthorities())
                    .as(input.description())
                    .extracting(GrantedAuthority::getAuthority)
                    .contains("ROLE_ADMIN", "ROLE_USER");
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new SuccessCase("when argus returns a successful authenticated identity",
                            ArgusAuthenticationToken.unauthenticated(TestAuthenticators.token("external-admin-user"))))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as failed authentication")
    @TestInstance(PER_CLASS)
    final class FailedAuthentication
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldTranslateAuthenticationFailureIntoSpringException(final FailureCase input)
        {
            final var provider = new ArgusAuthenticationProvider(TestAuthenticators.directAuthenticator(new AtomicLong(3L)));

            assertThatThrownBy(() -> provider.authenticate(input.request()))
                    .as(input.description())
                    .isInstanceOf(input.expectedType());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new FailureCase("when the credential signature is invalid",
                                    ArgusAuthenticationToken.unauthenticated(
                                            TestAuthenticators.invalidSignatureToken("external-user")),
                                    BadCredentialsException.class),
                            new FailureCase("when no local user can be resolved",
                                    ArgusAuthenticationToken.unauthenticated(TestAuthenticators.token("missing-user")),
                                    BadCredentialsException.class),
                            new FailureCase("when the token is no longer current",
                                    ArgusAuthenticationToken.unauthenticated(TestAuthenticators.token("external-stale-user")),
                                    CredentialsExpiredException.class),
                            new FailureCase("when the resolver throws unexpectedly",
                                    ArgusAuthenticationToken.unauthenticated(TestAuthenticators.token("exploding-user")),
                                    AuthenticationServiceException.class))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as unsupported authentication")
    @TestInstance(PER_CLASS)
    final class UnsupportedAuthentication
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldReturnNullWhenTheRequestCannotBeHandled(final UnsupportedCase input)
        {
            final var provider = new ArgusAuthenticationProvider(TestAuthenticators.directAuthenticator(new AtomicLong(3L)));

            assertThat(provider.authenticate(input.request()))
                    .as(input.description())
                    .isNull();
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new UnsupportedCase("when the request is not an argus authentication token",
                                    UsernamePasswordAuthenticationToken.unauthenticated("user", "secret")),
                            new UnsupportedCase("when the argus token no longer carries a raw bearer credential",
                                    ArgusAuthenticationToken.authenticated(TestAuthenticators.authenticatedIdentity(new AtomicLong(3L)),
                                            List.of())))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as supported authentication type")
    @TestInstance(PER_CLASS)
    final class SupportedAuthenticationType
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldOnlySupportArgusAuthenticationTokens(final SupportsCase input)
        {
            final var provider = new ArgusAuthenticationProvider(TestAuthenticators.directAuthenticator(new AtomicLong(3L)));

            assertThat(provider.supports(input.authenticationType()))
                    .as(input.description())
                    .isEqualTo(input.expected());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new SupportsCase("when the requested type is an argus token", ArgusAuthenticationToken.class, true),
                            new SupportsCase("when the requested type is a different spring authentication", UsernamePasswordAuthenticationToken.class, false))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as authority normalization")
    @TestInstance(PER_CLASS)
    final class AuthorityNormalization
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldAddSpringRoleAuthorityWhenTheIdentityUsesBusinessRoles(final SuccessCase input)
        {
            final var provider = new ArgusAuthenticationProvider(authenticatorReturningNonPrefixedRoles());

            final Authentication result = provider.authenticate(input.request());

            assertThat(result.getAuthorities())
                    .as(input.description())
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactlyInAnyOrder("ADMIN", "ROLE_ADMIN", "USER", "ROLE_USER");
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new SuccessCase("when the authenticated identity exposes non-prefixed business roles",
                            ArgusAuthenticationToken.unauthenticated(TestAuthenticators.token("external-admin-user"))))
                    .map(Arguments::of);
        }
    }

    private Authenticator authenticatorReturningNonPrefixedRoles()
    {
        final AuthenticatorConfiguration<String, String> configuration = AuthenticatorConfiguration.<String, String>builder()
                .upstreamTrustConfiguration(TestAuthenticators.upstreamTrustConfiguration())
                .authenticatedTokenContract(TestAuthenticators.authenticatedTokenContract())
                .authenticatedTokenMintingConfiguration(TestAuthenticators.authenticatedTokenMintingConfiguration())
                .authenticatedTokenVerificationConfiguration(TestAuthenticators.authenticatedTokenVerificationConfiguration())
                .identityMappingConfiguration(IdentityMappingConfiguration.of(ExternalIdentityAdapter.stringIdentity(),
                        externalIdentity -> Optional.of(externalIdentity.replace("external-", "")),
                        user -> "local-" + user,
                        user -> Set.of("ADMIN", "USER"),
                        user -> 3L,
                        _ -> 3L))
                .clock(TestAuthenticators.CLOCK)
                .build();
        return AuthenticatorFactory.create(configuration);
    }
}