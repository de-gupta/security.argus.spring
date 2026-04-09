package de.gupta.security.argus.spring.api.configuration;

import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationFilter;
import de.gupta.security.argus.spring.api.context.ArgusSecurityContextQueryManager;
import de.gupta.security.argus.spring.test.TestAuthenticators;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("ArgusSpringConfiguration")
@TestInstance(PER_CLASS)
final class ArgusSpringConfigurationTest
{
    private record ContextCase(String description, Consumer<ApplicationContextRunner> assertion)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    @Nested
    @DisplayName("as bean assembly")
    @TestInstance(PER_CLASS)
    final class BeanAssembly
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldExposeCoreAdapterBeans(final ContextCase input)
        {
            input.assertion().accept(baseRunner());
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new ContextCase("when the consumer provides an authenticator bean",
                                    runner -> runner.withBean(Authenticator.class,
                                                    () -> TestAuthenticators.directAuthenticator(new AtomicLong(3L)))
                                            .run(context -> {
                                                assertThat(context).hasSingleBean(Authenticator.class);
                                                assertThat(context).hasSingleBean(ArgusAuthenticationFilter.class);
                                                assertThat(context).hasSingleBean(ArgusSecurityContextQueryManager.class);
                                            })),
                            new ContextCase("when the consumer provides an authenticator configuration bean",
                                    runner -> runner.withBean(AuthenticatorConfiguration.class,
                                                    () -> TestAuthenticators.authenticatorConfiguration(new AtomicLong(3L)))
                                            .run(context -> {
                                                assertThat(context).hasSingleBean(Authenticator.class);
                                                assertThat(context).hasSingleBean(ArgusAuthenticationFilter.class);
                                                assertThat(context).hasSingleBean(ArgusSecurityContextQueryManager.class);
                                            })),
                            new ContextCase("when the consumer provides the individual argus ingredients",
                                    runner -> runner.withBean(UpstreamTrustConfiguration.class,
                                                    TestAuthenticators::upstreamTrustConfiguration)
                                            .withBean(AuthenticatedTokenContract.class,
                                                    TestAuthenticators::authenticatedTokenContract)
                                            .withBean(AuthenticatedTokenMintingConfiguration.class,
                                                    TestAuthenticators::authenticatedTokenMintingConfiguration)
                                            .withBean(AuthenticatedTokenVerificationConfiguration.class,
                                                    TestAuthenticators::authenticatedTokenVerificationConfiguration)
                                            .withBean(IdentityMappingConfiguration.class,
                                                    () -> TestAuthenticators.identityMappingConfiguration(_ -> 3L))
                                            .run(context -> {
                                                assertThat(context).hasSingleBean(AuthenticatorConfiguration.class);
                                                assertThat(context).hasSingleBean(Authenticator.class);
                                                assertThat(context).hasSingleBean(ArgusAuthenticationFilter.class);
                                            })))
                    .map(Arguments::of);
        }
    }

    private ApplicationContextRunner baseRunner()
    {
        return new ApplicationContextRunner().withUserConfiguration(ArgusSpringConfiguration.class);
    }
}
