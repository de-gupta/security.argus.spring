package de.gupta.security.argus.spring.api.configuration;

import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.authentication.AuthenticatorFactory;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.argus.spring.adapter.authentication.ArgusAuthenticationProvider;
import de.gupta.security.argus.spring.adapter.authentication.BearerTokenAuthenticationConverter;
import de.gupta.security.argus.spring.adapter.context.DefaultArgusSecurityContextQueryManager;
import de.gupta.security.argus.spring.adapter.method.DefaultArgusMethodAccess;
import de.gupta.security.argus.spring.api.authentication.ArgusAccessDeniedHandler;
import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationEntryPoint;
import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationFilter;
import de.gupta.security.argus.spring.api.context.ArgusSecurityContextQueryManager;
import de.gupta.security.argus.spring.api.method.ArgusMethodAccess;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Clock;

@Configuration(proxyBeanMethods = false)
public class ArgusSpringConfiguration
{
    @Bean(name = "argusManagedAuthenticatorConfiguration")
    @ConditionalOnMissingBean(value = {Authenticator.class, AuthenticatorConfiguration.class})
    @ConditionalOnBean(value = {UpstreamTrustConfiguration.class,
            AuthenticatedTokenContract.class,
            AuthenticatedTokenMintingConfiguration.class,
            AuthenticatedTokenVerificationConfiguration.class,
            IdentityMappingConfiguration.class})
    AuthenticatorConfiguration<?, ?> argusManagedAuthenticatorConfiguration(
            final UpstreamTrustConfiguration upstreamTrustConfiguration,
            final AuthenticatedTokenContract authenticatedTokenContract,
            final AuthenticatedTokenMintingConfiguration authenticatedTokenMintingConfiguration,
            final AuthenticatedTokenVerificationConfiguration authenticatedTokenVerificationConfiguration,
            final IdentityMappingConfiguration<?, ?> identityMappingConfiguration,
            final ObjectProvider<Clock> clockProvider,
            final ObjectProvider<TokenAuthenticationCache> cacheProvider)
    {
        return AuthenticatorConfiguration.of(upstreamTrustConfiguration,
                authenticatedTokenContract,
                authenticatedTokenMintingConfiguration,
                authenticatedTokenVerificationConfiguration,
                identityMappingConfiguration,
                clockProvider.getIfAvailable(Clock::systemUTC),
                cacheProvider.getIfAvailable(TokenAuthenticationCache::noOp));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Bean(name = "argusManagedAuthenticator")
    @ConditionalOnMissingBean(Authenticator.class)
    @ConditionalOnBean(AuthenticatorConfiguration.class)
    Authenticator argusManagedAuthenticator(final AuthenticatorConfiguration<?, ?> authenticatorConfiguration)
    {
        return AuthenticatorFactory.create((AuthenticatorConfiguration) authenticatorConfiguration);
    }

    @Bean
    @ConditionalOnMissingBean(org.springframework.security.authentication.AuthenticationProvider.class)
    ArgusAuthenticationProvider argusAuthenticationProvider(final Authenticator authenticator)
    {
        return new ArgusAuthenticationProvider(authenticator);
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    AuthenticationManager authenticationManager(final ArgusAuthenticationProvider authenticationProvider)
    {
        return new ProviderManager(authenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationConverter.class)
    AuthenticationConverter authenticationConverter()
    {
        return new BearerTokenAuthenticationConverter();
    }

    @Bean
    @ConditionalOnMissingBean(ArgusAuthenticationEntryPoint.class)
    ArgusAuthenticationEntryPoint argusAuthenticationEntryPoint()
    {
        return new ArgusAuthenticationEntryPoint();
    }

    @Bean
    @ConditionalOnMissingBean(ArgusAccessDeniedHandler.class)
    ArgusAccessDeniedHandler argusAccessDeniedHandler()
    {
        return new ArgusAccessDeniedHandler();
    }

    @Bean
    @ConditionalOnMissingBean(ArgusAuthenticationFilter.class)
    ArgusAuthenticationFilter argusAuthenticationFilter(final AuthenticationManager authenticationManager,
                                                        final AuthenticationConverter authenticationConverter,
                                                        final AuthenticationEntryPoint authenticationEntryPoint)
    {
        return new ArgusAuthenticationFilter(authenticationManager, authenticationConverter, authenticationEntryPoint);
    }

    @Bean
    @ConditionalOnMissingBean(ArgusSecurityContextQueryManager.class)
    ArgusSecurityContextQueryManager argusSecurityContextQueryManager()
    {
        return new DefaultArgusSecurityContextQueryManager();
    }

    @Bean(name = "argusMethodAccess")
    @ConditionalOnMissingBean(name = "argusMethodAccess")
    ArgusMethodAccess argusMethodAccess(final ArgusSecurityContextQueryManager securityContextQueryManager)
    {
        return new DefaultArgusMethodAccess(securityContextQueryManager);
    }

    @Bean
    @ConditionalOnMissingBean(AnnotationTemplateExpressionDefaults.class)
    AnnotationTemplateExpressionDefaults annotationTemplateExpressionDefaults()
    {
        return new AnnotationTemplateExpressionDefaults();
    }

    @Bean(name = "argusDefaultSecurityFilterChain")
    @Order(-99)
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    SecurityFilterChain argusDefaultSecurityFilterChain(
            final HttpSecurity http,
            final ArgusAuthenticationFilter authenticationFilter,
            final ArgusAuthenticationEntryPoint authenticationEntryPoint,
            final ArgusAccessDeniedHandler accessDeniedHandler,
            final ObjectProvider<ArgusSecurityCustomizer> customizerProvider) throws Exception
    {
        http.csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(exceptions -> exceptions
                    .authenticationEntryPoint(authenticationEntryPoint)
                    .accessDeniedHandler(accessDeniedHandler));

        customizerProvider.getIfAvailable(ArgusSecurityCustomizer::noOp).customize(http);

        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

        return http.build();
    }
}