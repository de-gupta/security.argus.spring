package de.gupta.security.argus.spring.api.context;

import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationToken;
import de.gupta.security.argus.spring.adapter.context.DefaultArgusSecurityContextQueryManager;
import de.gupta.security.argus.spring.test.TestAuthenticators;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("ArgusSecurityContextQueryManager")
@TestInstance(PER_CLASS)
final class ArgusSecurityContextQueryManagerAuthenticatedIdentityTest
{
    private final ArgusSecurityContextQueryManager queryManager = new DefaultArgusSecurityContextQueryManager();

    @AfterEach
    void clearSecurityContext()
    {
        SecurityContextHolder.clearContext();
    }

    private record EmptyCase(String description)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record AnonymousCase(String description)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record UnauthenticatedCase(String description)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record AuthorityBackedCase(String description)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record PopulatedCase(String description)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    @Nested
    @DisplayName("as empty security context")
    @TestInstance(PER_CLASS)
    final class EmptySecurityContext
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldExposeNoAuthenticatedIdentity(final EmptyCase input)
        {
            assertThat(queryManager.authentication())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.authenticatedIdentity())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.subject())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.roles())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.isAuthenticated())
                    .as(input.description())
                    .isFalse();
            assertThat(queryManager.hasRole("ADMIN"))
                    .as(input.description())
                    .isFalse();
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new EmptyCase("when no authentication is present"))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as anonymous authentication")
    @TestInstance(PER_CLASS)
    final class AnonymousAuthenticationContext
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldTreatAnonymousAuthenticationAsUnauthenticated(final AnonymousCase input)
        {
            SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken(
                    "key",
                    "anonymousUser",
                    List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));

            assertThat(queryManager.authentication())
                    .as(input.description())
                    .isPresent();
            assertThat(queryManager.authenticatedIdentity())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.subject())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.roles())
                    .as(input.description())
                    .containsExactly("ROLE_ANONYMOUS");
            assertThat(queryManager.isAuthenticated())
                    .as(input.description())
                    .isFalse();
            assertThat(queryManager.hasRole("ANONYMOUS"))
                    .as(input.description())
                    .isTrue();
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new AnonymousCase("when an anonymous authentication is present in the security context"))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as unauthenticated non-anonymous authentication")
    @TestInstance(PER_CLASS)
    final class UnauthenticatedNonAnonymousAuthenticationContext
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldTreatUnauthenticatedTokensAsNotAuthenticated(final UnauthenticatedCase input)
        {
            SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.unauthenticated(
                    "spring-user",
                    "ignored"));

            assertThat(queryManager.authentication())
                    .as(input.description())
                    .isPresent();
            assertThat(queryManager.authenticatedIdentity())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.subject())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.roles())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.isAuthenticated())
                    .as(input.description())
                    .isFalse();
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new UnauthenticatedCase("when a spring authentication exists but is not authenticated yet"))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as authority-backed authentication")
    @TestInstance(PER_CLASS)
    final class AuthorityBackedAuthenticationContext
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldFallBackToSpringAuthoritiesWhenThePrincipalIsNotAnArgusIdentity(final AuthorityBackedCase input)
        {
            SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                    "spring-user",
                    "ignored",
                    List.of(new SimpleGrantedAuthority("ROLE_SUPPORT"), new SimpleGrantedAuthority("ROLE_USER"))));

            assertThat(queryManager.authentication())
                    .as(input.description())
                    .isPresent();
            assertThat(queryManager.authenticatedIdentity())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.subject())
                    .as(input.description())
                    .isEmpty();
            assertThat(queryManager.roles())
                    .as(input.description())
                    .containsExactly("ROLE_SUPPORT", "ROLE_USER");
            assertThat(queryManager.isAuthenticated())
                    .as(input.description())
                    .isTrue();
            assertThat(queryManager.hasRole("SUPPORT"))
                    .as(input.description())
                    .isTrue();
            assertThat(queryManager.hasRole("ADMIN"))
                    .as(input.description())
                    .isFalse();
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new AuthorityBackedCase("when a real spring authentication has authorities but no argus identity principal"))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as populated security context")
    @TestInstance(PER_CLASS)
    final class PopulatedSecurityContext
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldExposeIdentityFirstQueries(final PopulatedCase input)
        {
            final var identity = TestAuthenticators.authenticatedIdentity(new AtomicLong(3L));
            SecurityContextHolder.getContext().setAuthentication(ArgusAuthenticationToken.authenticated(identity,
                    List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN"))));

            assertThat(queryManager.authenticatedIdentity())
                    .as(input.description())
                    .isPresent();
            assertThat(queryManager.subject())
                    .as(input.description())
                    .contains("local-user");
            assertThat(queryManager.roles())
                    .as(input.description())
                    .contains("ROLE_USER");
            assertThat(queryManager.isAuthenticated())
                    .as(input.description())
                    .isTrue();
            assertThat(queryManager.hasRole("USER"))
                    .as(input.description())
                    .isTrue();
            assertThat(queryManager.hasRole("ROLE_USER"))
                    .as(input.description())
                    .isTrue();
            assertThat(queryManager.hasRole("SUPPORT"))
                    .as(input.description())
                    .isFalse();
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new PopulatedCase("when an argus authentication has been stored in the security context"))
                    .map(Arguments::of);
        }
    }
}