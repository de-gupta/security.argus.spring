package de.gupta.security.argus.spring.api.configuration;

import de.gupta.security.argus.api.identity.LocalSubjectResolver;
import de.gupta.security.argus.api.identity.UserTokenVersionResolver;
import de.gupta.security.argus.spring.adapter.context.DefaultArgusSecurityContextQueryManager;
import de.gupta.security.argus.spring.adapter.method.DefaultArgusMethodAccess;
import de.gupta.security.argus.spring.api.context.ArgusSecurityContextQueryManager;
import de.gupta.security.argus.spring.api.method.ArgusMethodAccess;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;

import java.util.Optional;
import java.util.function.Function;
import java.util.function.ToLongFunction;

/**
 * Core Argus Spring configuration.
 *
 * <p>Imported into the application context via {@link
 * de.gupta.security.argus.spring.api.method.EnableArgusMethodSecurity}.
 *
 * <p>This configuration handles:
 * <ul>
 *   <li>Function-to-typed-interface adapter beans for optional resolver overrides
 *   <li>Non-Authenticator-dependent infrastructure beans (context query manager,
 *       method access, annotation template defaults)
 * </ul>
 *
 * <p>Authenticator assembly and all Authenticator-dependent adapter beans
 * (provider, manager, filter, filter chain) are handled by
 * {@link ArgusAuthenticatorAdapterConfiguration}, which is registered as a
 * Spring Boot autoconfiguration so it is processed after all user beans are
 * fully registered — allowing {@code @ConditionalOnBean} checks against user-provided
 * resolver beans to resolve correctly.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ArgusProperties.class)
public class ArgusSpringConfiguration
{
	// -------------------------------------------------------------------------
	// Function<> adapters — bridge between plain named Function beans and
	// the typed resolver interfaces. Using @Qualifier("name") rather than
	// @ConditionalOnBean(type) avoids ordering sensitivity.
	// -------------------------------------------------------------------------

	@Bean(name = "argusManagedUserResolver")
	@ConditionalOnMissingBean(ArgusUserResolver.class)
	@ConditionalOnBean(name = "argusUserResolverFunction")
	@SuppressWarnings("unchecked")
	ArgusUserResolver<?> argusManagedUserResolver(
			@Qualifier("argusUserResolverFunction") final Function<String, Optional<?>> function)
	{
		return externalIdentity -> (Optional) function.apply(externalIdentity);
	}

	@Bean(name = "argusManagedVersionResolver")
	@ConditionalOnMissingBean(ArgusVersionResolver.class)
	@ConditionalOnBean(name = "argusVersionResolverFunction")
	ArgusVersionResolver argusManagedVersionResolver(
			@Qualifier("argusVersionResolverFunction") final Function<String, Long> function)
	{
		return function::apply;
	}

	@Bean(name = "argusManagedLocalSubjectResolver")
	@ConditionalOnMissingBean(LocalSubjectResolver.class)
	@ConditionalOnBean(name = "argusLocalSubjectResolverFunction")
	@SuppressWarnings("unchecked")
	LocalSubjectResolver<?> argusManagedLocalSubjectResolver(
			@Qualifier("argusLocalSubjectResolverFunction") final Function<?, String> function)
	{
		return user -> ((Function<Object, String>) function).apply(user);
	}

	@Bean(name = "argusManagedUserTokenVersionResolver")
	@ConditionalOnMissingBean(UserTokenVersionResolver.class)
	@ConditionalOnBean(name = "argusUserTokenVersionResolverFunction")
	@SuppressWarnings("unchecked")
	UserTokenVersionResolver<?> argusManagedUserTokenVersionResolver(
			@Qualifier("argusUserTokenVersionResolverFunction") final ToLongFunction<?> function)
	{
		return user -> ((ToLongFunction<Object>) function).applyAsLong(user);
	}

	// -------------------------------------------------------------------------
	// Infrastructure beans — no Authenticator dependency
	// -------------------------------------------------------------------------

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
}
