package de.gupta.security.argus.spring.api.authentication;

import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.spring.api.context.ArgusSecurityContextQueryManager;
import de.gupta.security.argus.spring.api.method.EnableArgusMethodSecurity;
import de.gupta.security.argus.spring.api.method.RequireAnyRole;
import de.gupta.security.argus.spring.api.method.RequireAuthenticated;
import de.gupta.security.argus.spring.api.method.RequireRole;
import de.gupta.security.argus.spring.test.TestAuthenticators;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Service;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = ArgusSpringSecurityIntegrationTest.TestApplication.class)
@AutoConfigureMockMvc
@DisplayName("Argus spring security integration")
@TestInstance(PER_CLASS)
final class ArgusSpringSecurityIntegrationTest
{
    @Autowired
    private MockMvc mockMvc;

    private record RequestCase(String description, String path, String token, int expectedStatus, String expectedBody)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    @Nested
    @DisplayName("as request authentication")
    @TestInstance(PER_CLASS)
    final class RequestAuthentication
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldDriveTheSpringSecurityPipeline(final RequestCase input) throws Exception
        {
            final var requestBuilder = get(input.path()).accept(MediaType.TEXT_PLAIN);
            if (input.token() != null)
            {
                requestBuilder.header("Authorization", "Bearer " + input.token());
            }

            final var resultActions = mockMvc.perform(requestBuilder)
                                             .andExpect(status().is(input.expectedStatus()));
            if (input.expectedBody() != null)
            {
                resultActions.andExpect(content().string(input.expectedBody()));
            }
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new RequestCase("when a public endpoint is called without a token",
                                    "/public/state",
                                    null,
                                    200,
                                    "false"),
                            new RequestCase("when a valid user token accesses a standard pre-authorized endpoint",
                                    "/me",
                                    TestAuthenticators.token("external-user"),
                                    200,
                                    "local-user"),
                            new RequestCase("when a valid user token accesses a custom authenticated endpoint",
                                    "/authenticated",
                                    TestAuthenticators.token("external-user"),
                                    200,
                                    "local-user"),
                            new RequestCase("when a valid admin token accesses a custom role endpoint",
                                    "/admin",
                                    TestAuthenticators.token("external-admin-user"),
                                    200,
                                    "admin"),
                            new RequestCase("when a valid support token accesses an any-role endpoint",
                                    "/operations",
                                    TestAuthenticators.token("external-support-user"),
                                    200,
                                    "operations"),
                            new RequestCase("when a normal user lacks the required admin role",
                                    "/admin",
                                    TestAuthenticators.token("external-user"),
                                    403,
                                    null),
                            new RequestCase("when the token signature is invalid",
                                    "/me",
                                    TestAuthenticators.invalidSignatureToken("external-user"),
                                    401,
                                    null),
                            new RequestCase("when no local user can be resolved",
                                    "/me",
                                    TestAuthenticators.token("missing-user"),
                                    401,
                                    null),
                            new RequestCase("when the token is no longer current",
                                    "/me",
                                    TestAuthenticators.token("external-stale-user"),
                                    401,
                                    null),
                            new RequestCase("when a resolver throws unexpectedly",
                                    "/me",
                                    TestAuthenticators.token("exploding-user"),
                                    401,
                                    null))
                    .map(Arguments::of);
        }
    }

    @SpringBootApplication
    @EnableArgusMethodSecurity
    static class TestApplication
    {
        @Bean
        Authenticator authenticator()
        {
            return TestAuthenticators.directAuthenticator(new AtomicLong(3L));
        }

        @Bean
        SecurityFilterChain securityFilterChain(final HttpSecurity http,
                                                final ArgusAuthenticationFilter argusAuthenticationFilter,
                                                final ArgusAuthenticationEntryPoint authenticationEntryPoint,
                                                final ArgusAccessDeniedHandler accessDeniedHandler)
                throws Exception
        {
            return http.csrf(AbstractHttpConfigurer::disable)
                       .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                       .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint)
                                                                 .accessDeniedHandler(accessDeniedHandler))
                       .authorizeHttpRequests(authorize -> authorize.requestMatchers("/public/**").permitAll()
                                                                    .anyRequest()
                                                                    .authenticated())
                       .addFilterBefore(argusAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                       .build();
        }

        @RestController
        static class TestController
        {
            private final SecuredService securedService;
            private final ArgusSecurityContextQueryManager securityContextQueryManager;

            TestController(final SecuredService securedService,
                           final ArgusSecurityContextQueryManager securityContextQueryManager)
            {
                this.securedService = securedService;
                this.securityContextQueryManager = securityContextQueryManager;
            }

            @GetMapping("/public/state")
            String state()
            {
                return Boolean.toString(securityContextQueryManager.isAuthenticated());
            }

            @GetMapping("/me")
            String me()
            {
                return securedService.me();
            }

            @GetMapping("/authenticated")
            String authenticated()
            {
                return securedService.authenticated();
            }

            @GetMapping("/admin")
            String admin()
            {
                return securedService.admin();
            }

            @GetMapping("/operations")
            String operations()
            {
                return securedService.operations();
            }
        }

        @Service
        static class SecuredService
        {
            private final ArgusSecurityContextQueryManager securityContextQueryManager;

            SecuredService(final ArgusSecurityContextQueryManager securityContextQueryManager)
            {
                this.securityContextQueryManager = securityContextQueryManager;
            }

            @org.springframework.security.access.prepost.PreAuthorize("hasRole('USER')")
            String me()
            {
                return securityContextQueryManager.subject().orElse("anonymous");
            }

            @RequireAuthenticated
            String authenticated()
            {
                return securityContextQueryManager.subject().orElse("anonymous");
            }

            @RequireRole("ADMIN")
            String admin()
            {
                return "admin";
            }

            @RequireAnyRole({"ADMIN", "SUPPORT"})
            String operations()
            {
                return "operations";
            }
        }
    }
}
