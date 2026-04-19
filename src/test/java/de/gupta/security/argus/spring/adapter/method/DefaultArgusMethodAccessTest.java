package de.gupta.security.argus.spring.adapter.method;

import de.gupta.security.argus.spring.api.context.ArgusSecurityContextQueryManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("DefaultArgusMethodAccess")
@TestInstance(PER_CLASS)
final class DefaultArgusMethodAccessTest
{
    private record AuthenticationCase(String description, boolean authenticated, boolean expected)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record RoleCase(String description, String role, boolean present, boolean expected)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record AnyRoleCase(String description, String[] roles, Set<String> presentRoles, boolean expected)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    private record SubjectCase(String description, Optional<String> subject, String requestedSubject, boolean expected)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    @Nested
    @DisplayName("as authentication query")
    @TestInstance(PER_CLASS)
    final class AuthenticationQuery
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldDelegateAuthenticationStatus(final AuthenticationCase input)
        {
            final ArgusSecurityContextQueryManager queryManager = mock(ArgusSecurityContextQueryManager.class);
            when(queryManager.isAuthenticated()).thenReturn(input.authenticated());
            final var methodAccess = new DefaultArgusMethodAccess(queryManager);

            assertThat(methodAccess.isAuthenticated())
                    .as(input.description())
                    .isEqualTo(input.expected());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new AuthenticationCase("when the current security context is authenticated", true, true),
                            new AuthenticationCase("when the current security context is anonymous", false, false))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as role query")
    @TestInstance(PER_CLASS)
    final class RoleQuery
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldDelegateSingleRoleChecks(final RoleCase input)
        {
            final ArgusSecurityContextQueryManager queryManager = mock(ArgusSecurityContextQueryManager.class);
            when(queryManager.hasRole(input.role())).thenReturn(input.present());
            final var methodAccess = new DefaultArgusMethodAccess(queryManager);

            assertThat(methodAccess.hasRole(input.role()))
                    .as(input.description())
                    .isEqualTo(input.expected());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new RoleCase("when the requested role is present", "ADMIN", true, true),
                            new RoleCase("when the requested role is absent", "SUPPORT", false, false))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as any-role query")
    @TestInstance(PER_CLASS)
    final class AnyRoleQuery
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldSupportCommaSeparatedAndTrimmedRoles(final AnyRoleCase input)
        {
            final ArgusSecurityContextQueryManager queryManager = mock(ArgusSecurityContextQueryManager.class);
            input.presentRoles().forEach(role -> when(queryManager.hasRole(role)).thenReturn(true));
            final var methodAccess = new DefaultArgusMethodAccess(queryManager);

            assertThat(methodAccess.hasAnyRole(input.roles()))
                    .as(input.description())
                    .isEqualTo(input.expected());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new AnyRoleCase("when one of multiple roles is present",
                                    new String[]{"ADMIN", "SUPPORT"},
                                    Set.of("SUPPORT"),
                                    true),
                            new AnyRoleCase("when the annotation-style comma separated role value is present",
                                    new String[]{" ADMIN, SUPPORT "},
                                    Set.of("ADMIN"),
                                    true),
                            new AnyRoleCase("when only blank role values are given",
                                    new String[]{"   ", ""},
                                    Set.of(),
                                    false),
                            new AnyRoleCase("when none of the requested roles are present",
                                    new String[]{"ADMIN", "SUPPORT"},
                                    Set.of("USER"),
                                    false))
                    .map(Arguments::of);
        }
    }

    @Nested
    @DisplayName("as subject query")
    @TestInstance(PER_CLASS)
    final class SubjectQuery
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldCompareAgainstTheCurrentSubject(final SubjectCase input)
        {
            final ArgusSecurityContextQueryManager queryManager = mock(ArgusSecurityContextQueryManager.class);
            when(queryManager.subject()).thenReturn(input.subject());
            final var methodAccess = new DefaultArgusMethodAccess(queryManager);

            assertThat(methodAccess.hasSubject(input.requestedSubject()))
                    .as(input.description())
                    .isEqualTo(input.expected());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new SubjectCase("when the current subject matches", Optional.of("local-admin-user"), "local-admin-user", true),
                            new SubjectCase("when the current subject does not match", Optional.of("local-user"), "local-admin-user", false),
                            new SubjectCase("when there is no authenticated subject", Optional.empty(), "local-user", false))
                    .map(Arguments::of);
        }
    }
}
