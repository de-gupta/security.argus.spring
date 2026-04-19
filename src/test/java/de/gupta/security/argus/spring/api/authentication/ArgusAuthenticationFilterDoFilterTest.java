package de.gupta.security.argus.spring.api.authentication;

import de.gupta.security.argus.spring.test.TestAuthenticators;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;

import jakarta.servlet.FilterChain;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("ArgusAuthenticationFilter.doFilter")
@TestInstance(PER_CLASS)
final class ArgusAuthenticationFilterDoFilterTest
{
    @AfterEach
    void clearSecurityContext()
    {
        SecurityContextHolder.clearContext();
    }

    private record SkipCase(String description, boolean prepopulateSecurityContext, Authentication converterResult)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record SuccessCase(String description)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record FailureCase(String description)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    @Nested
    @DisplayName("as short-circuiting request")
    @TestInstance(PER_CLASS)
    final class ShortCircuitingRequest
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldContinueWithoutAuthenticating(final SkipCase input) throws Exception
        {
            if (input.prepopulateSecurityContext())
            {
                SecurityContextHolder.getContext().setAuthentication(ArgusAuthenticationToken.authenticated(
                        TestAuthenticators.authenticatedIdentity(new AtomicLong(3L)),
                        java.util.List.of()));
            }

            final AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
            final AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
            final AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
            final FilterChain filterChain = mock(FilterChain.class);
            final var request = new MockHttpServletRequest();
            final var response = new MockHttpServletResponse();
            final var filter = new ArgusAuthenticationFilter(authenticationManager, authenticationConverter,
                    authenticationEntryPoint);
            when(authenticationConverter.convert(request)).thenReturn(input.converterResult());

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(same(request), same(response));
            if (input.prepopulateSecurityContext())
            {
                verify(authenticationConverter, never()).convert(any());
            }
            else
            {
                verify(authenticationConverter).convert(same(request));
                verify(authenticationManager, never()).authenticate(any());
            }
            verify(authenticationEntryPoint, never()).commence(any(), any(), any());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new SkipCase("when the security context is already populated", true, null),
                            new SkipCase("when no bearer token can be converted", false, null))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as successful authentication")
    @TestInstance(PER_CLASS)
    final class SuccessfulAuthentication
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldPopulateTheSecurityContext(final SuccessCase input) throws Exception
        {
            final AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
            final AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
            final AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
            final FilterChain filterChain = mock(FilterChain.class);
            final var request = new MockHttpServletRequest();
            final var response = new MockHttpServletResponse();
            final var filter = new ArgusAuthenticationFilter(authenticationManager, authenticationConverter,
                    authenticationEntryPoint);
            final Authentication requestAuthentication = ArgusAuthenticationToken.unauthenticated("raw-token");
            final Authentication successfulAuthentication = ArgusAuthenticationToken.authenticated(
                    TestAuthenticators.authenticatedIdentity(new AtomicLong(3L)),
                    java.util.List.of());
            when(authenticationConverter.convert(request)).thenReturn(requestAuthentication);
            when(authenticationManager.authenticate(requestAuthentication)).thenReturn(successfulAuthentication);

            filter.doFilter(request, response, filterChain);

            assertThat(SecurityContextHolder.getContext().getAuthentication())
                    .as(input.description())
                    .isSameAs(successfulAuthentication);
            verify(filterChain).doFilter(same(request), same(response));
            verify(authenticationEntryPoint, never()).commence(any(), any(), any());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new SuccessCase("when the authentication manager authenticates the converted request"))
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
        void shouldClearTheSecurityContextAndCommenceTheEntryPoint(final FailureCase input) throws Exception
        {
            final AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
            final AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
            final AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
            final FilterChain filterChain = mock(FilterChain.class);
            final var request = new MockHttpServletRequest();
            final var response = new MockHttpServletResponse();
            final var filter = new ArgusAuthenticationFilter(authenticationManager, authenticationConverter,
                    authenticationEntryPoint);
            final Authentication requestAuthentication = ArgusAuthenticationToken.unauthenticated("raw-token");
            when(authenticationConverter.convert(request)).thenReturn(requestAuthentication);
            when(authenticationManager.authenticate(requestAuthentication)).thenThrow(new BadCredentialsException("invalid"));
            SecurityContextHolder.getContext().setAuthentication(ArgusAuthenticationToken.unauthenticated("stale-token"));

            filter.doFilter(request, response, filterChain);

            assertThat(SecurityContextHolder.getContext().getAuthentication())
                    .as(input.description())
                    .isNull();
            verify(authenticationEntryPoint).commence(same(request), same(response), any(BadCredentialsException.class));
            verify(filterChain, never()).doFilter(any(), any());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(new FailureCase("when the authentication manager rejects the converted request"))
                    .map(Arguments::of);
        }
    }
}
