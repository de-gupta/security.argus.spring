package de.gupta.security.argus.spring.api.configuration;

import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.authentication.AuthenticatorFactory;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.identity.LocalSubjectResolver;
import de.gupta.security.argus.api.identity.RoleResolver;
import de.gupta.security.argus.api.identity.UserTokenVersionResolver;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.argus.spring.adapter.authentication.ArgusAuthenticationProvider;
import de.gupta.security.argus.spring.adapter.authentication.BearerTokenAuthenticationConverter;
import de.gupta.security.argus.spring.adapter.configuration.ArgusPropertiesAssembler;
import de.gupta.security.argus.spring.api.authentication.ArgusAccessDeniedHandler;
import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationEntryPoint;
import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
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
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Clock;

/**
 * Spring Boot autoconfiguration that assembles the Argus authenticator pipeline
 * and wires it into Spring Security.
 *
 * <p>Registered as a Spring Boot autoconfiguration (via
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports})
 * so that it is processed <em>after</em> all user-defined beans are fully registered.
 * This guarantees that {@code @ConditionalOnBean} checks against user-provided resolver
 * beans ({@link ArgusUserResolver}, {@link ArgusVersionResolver}, domain beans, etc.)
 * resolve correctly regardless of the order in which user configurations are processed.
 *
 * <p>Three assembly paths are provided, in descending priority:
 * <ol>
 *   <li>Consumer provides {@link Authenticator} directly — all assembly skipped
 *   <li>Consumer provides {@link AuthenticatorConfiguration} — assembler creates {@code Authenticator}
 *   <li>Consumer provides individual domain beans ({@link UpstreamTrustConfiguration} etc.) — assembler
 *       builds {@code AuthenticatorConfiguration} then {@code Authenticator}
 *   <li>Consumer provides {@link ArgusProperties} via {@code application.properties} and
 *       {@link ArgusUserResolver} + {@link ArgusVersionResolver} beans — fully auto-assembled
 * </ol>
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(ArgusSpringConfiguration.class)
public class ArgusAuthenticatorAdapterConfiguration
{
	// -------------------------------------------------------------------------
	// Assembly path 4: properties-driven
	// -------------------------------------------------------------------------

	@Bean(name = "argusManagedAuthenticatorConfigurationFromProperties")
	@ConditionalOnMissingBean(value = {Authenticator.class, AuthenticatorConfiguration.class})
	@ConditionalOnBean(value = {ArgusUserResolver.class, ArgusVersionResolver.class})
	@SuppressWarnings({"rawtypes", "unchecked"})
	AuthenticatorConfiguration<?, ?> argusManagedAuthenticatorConfigurationFromProperties(
			final ArgusProperties argusProperties,
			final ArgusUserResolver<?> userResolver,
			final ArgusVersionResolver versionResolver,
			final ObjectProvider<RoleResolver<?>> roleResolverProvider,
			final ObjectProvider<LocalSubjectResolver<?>> localSubjectResolverProvider,
			final ObjectProvider<UserTokenVersionResolver<?>> userTokenVersionResolverProvider,
			final ObjectProvider<Clock> clockProvider,
			final ObjectProvider<TokenAuthenticationCache> cacheProvider)
	{
		return ArgusPropertiesAssembler.of(argusProperties, userResolver, versionResolver,
											   roleResolverProvider, localSubjectResolverProvider,
											   userTokenVersionResolverProvider, clockProvider, cacheProvider)
		                               .assemble();
	}

	// -------------------------------------------------------------------------
	// Assembly path 3: explicit domain beans
	// -------------------------------------------------------------------------

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

	// -------------------------------------------------------------------------
	// Core authenticator — assembly paths 2, 3, 4
	// -------------------------------------------------------------------------

	@SuppressWarnings({"rawtypes", "unchecked"})
	@Bean(name = "argusManagedAuthenticator")
	@ConditionalOnMissingBean(Authenticator.class)
	@ConditionalOnBean(AuthenticatorConfiguration.class)
	Authenticator argusManagedAuthenticator(final AuthenticatorConfiguration<?, ?> authenticatorConfiguration)
	{
		return AuthenticatorFactory.create((AuthenticatorConfiguration) authenticatorConfiguration);
	}

	// -------------------------------------------------------------------------
	// Spring Security adapter beans — only created when Authenticator exists
	// -------------------------------------------------------------------------

	@Bean
	@ConditionalOnMissingBean(org.springframework.security.authentication.AuthenticationProvider.class)
	@ConditionalOnBean(Authenticator.class)
	ArgusAuthenticationProvider argusAuthenticationProvider(final Authenticator authenticator)
	{
		return new ArgusAuthenticationProvider(authenticator);
	}

	@Bean
	@ConditionalOnMissingBean(AuthenticationManager.class)
	@ConditionalOnBean(ArgusAuthenticationProvider.class)
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
	@ConditionalOnBean(AuthenticationManager.class)
	ArgusAuthenticationFilter argusAuthenticationFilter(final AuthenticationManager authenticationManager,
	                                                    final AuthenticationConverter authenticationConverter,
	                                                    final AuthenticationEntryPoint authenticationEntryPoint)
	{
		return new ArgusAuthenticationFilter(authenticationManager, authenticationConverter,
				authenticationEntryPoint);
	}

	@Bean(name = "argusDefaultSecurityFilterChain")
	@Order(-99)
	@ConditionalOnMissingBean(SecurityFilterChain.class)
	@ConditionalOnBean(ArgusAuthenticationFilter.class)
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