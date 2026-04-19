package de.gupta.security.argus.spring.api.authentication;

import de.gupta.security.argus.spring.test.TestAuthenticators;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("ArgusAuthenticationToken")
@TestInstance(PER_CLASS)
final class ArgusAuthenticationTokenTest
{
    private record UnauthenticatedCase(String description, String rawToken)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record AuthenticatedCase(String description)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    @Nested
    @DisplayName("as unauthenticated request token")
    @TestInstance(PER_CLASS)
    final class UnauthenticatedRequestToken
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldExposeRawRequestState(final UnauthenticatedCase input)
        {
            final ArgusAuthenticationToken token = ArgusAuthenticationToken.unauthenticated(input.rawToken());

            assertThat(token.isAuthenticated())
                    .as(input.description())
                    .isFalse();
            assertThat(token.getCredentials())
                    .as(input.description())
                    .isEqualTo(input.rawToken());
            assertThat(token.getPrincipal())
                    .as(input.description())
                    .isNull();
            assertThat(token.getName())
                    .as(input.description())
                    .isEmpty();
            assertThat(token.authenticatedIdentity())
                    .as(input.description())
                    .isEmpty();
            assertThat(token.getAuthorities())
                    .as(input.description())
                    .isEmpty();
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new UnauthenticatedCase("when the token only carries the raw bearer credential", "raw-token"))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as authenticated result token")
    @TestInstance(PER_CLASS)
    final class AuthenticatedResultToken
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldExposeAuthenticatedIdentityState(final AuthenticatedCase input)
        {
            final var identity = TestAuthenticators.authenticatedIdentity(new AtomicLong(3L));
            final ArgusAuthenticationToken token = ArgusAuthenticationToken.authenticated(identity,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));

            assertThat(token.isAuthenticated())
                    .as(input.description())
                    .isTrue();
            assertThat(token.getCredentials())
                    .as(input.description())
                    .isNull();
            assertThat(token.getPrincipal())
                    .as(input.description())
                    .isSameAs(identity);
            assertThat(token.getName())
                    .as(input.description())
                    .isEqualTo("local-user");
            assertThat(token.authenticatedIdentity())
                    .as(input.description())
                    .contains(identity);
            assertThat(token.getAuthorities())
                    .as(input.description())
                    .extracting(authority -> authority.getAuthority())
                    .containsExactly("ROLE_USER");
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new AuthenticatedCase("when the token wraps a trusted authenticated identity"))
                    .map(Arguments::of);
        }
    }
}
