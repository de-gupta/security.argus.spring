package de.gupta.security.argus.spring.adapter.configuration;

import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.api.identity.*;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.token.TokenSignerConfiguration;
import de.gupta.security.argus.api.trust.TokenTrustPolicy;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.argus.spring.api.configuration.ArgusProperties;
import de.gupta.security.argus.spring.api.configuration.ArgusUserResolver;
import de.gupta.security.argus.spring.api.configuration.ArgusVersionResolver;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

public final class ArgusPropertiesAssembler
{
	private final ArgusProperties properties;
	private final ArgusUserResolver<?> userResolver;
	private final ArgusVersionResolver versionResolver;
	private final ObjectProvider<RoleResolver<?>> roleResolverProvider;
	private final ObjectProvider<LocalSubjectResolver<?>> localSubjectResolverProvider;
	private final ObjectProvider<UserTokenVersionResolver<?>> userTokenVersionResolverProvider;
	private final ObjectProvider<Clock> clockProvider;
	private final ObjectProvider<TokenAuthenticationCache> cacheProvider;

	public static ArgusPropertiesAssembler of(
			final ArgusProperties properties,
			final ArgusUserResolver<?> userResolver,
			final ArgusVersionResolver versionResolver,
			final ObjectProvider<RoleResolver<?>> roleResolverProvider,
			final ObjectProvider<LocalSubjectResolver<?>> localSubjectResolverProvider,
			final ObjectProvider<UserTokenVersionResolver<?>> userTokenVersionResolverProvider,
			final ObjectProvider<Clock> clockProvider,
			final ObjectProvider<TokenAuthenticationCache> cacheProvider)
	{
		return new ArgusPropertiesAssembler(properties, userResolver, versionResolver,
				roleResolverProvider, localSubjectResolverProvider, userTokenVersionResolverProvider,
				clockProvider, cacheProvider);
	}

	@SuppressWarnings({"rawtypes", "unchecked"})
	public AuthenticatorConfiguration<?, ?> assemble()
	{
		final ArgusProperties.Upstream upstream = properties.upstream();
		final ArgusProperties.Internal internal = properties.internal();

		final UpstreamTrustConfiguration upstreamTrustConfiguration = buildUpstreamTrust(upstream);
		final AuthenticatedTokenContract contract = buildTokenContract(internal);
		final AuthenticatedTokenMintingConfiguration minting = buildMinting(internal);
		final AuthenticatedTokenVerificationConfiguration verification = buildVerification(internal);
		final IdentityMappingConfiguration<?, ?> identity =
				buildIdentityMapping((ArgusUserResolver<Object>) userResolver,
						versionResolver);

		return AuthenticatorConfiguration.of(
				upstreamTrustConfiguration,
				contract,
				minting,
				verification,
				(IdentityMappingConfiguration) identity,
				clockProvider.getIfAvailable(Clock::systemUTC),
				cacheProvider.getIfAvailable(TokenAuthenticationCache::noOp));
	}

	private static UpstreamTrustConfiguration buildUpstreamTrust(final ArgusProperties.Upstream upstream)
	{
		if (upstream.hmacSecret() == null || upstream.hmacSecret().isBlank())
		{
			throw new IllegalStateException(
					"argus.upstream.hmac-secret is required — property-based assembly only supports HMAC upstream tokens");
		}

		final TokenTrustPolicy policy = TokenTrustPolicy.of(
				upstream.clockSkew() != null ? upstream.clockSkew() : Duration.ZERO,
				upstream.requireSubject(),
				upstream.audiences() != null ? upstream.audiences() : Set.of(),
				Optional.ofNullable(upstream.issuer()).filter(s -> !s.isBlank()));

		return UpstreamTrustConfiguration.Hmac.of(policy, upstream.hmacSecret());
	}

	private static AuthenticatedTokenContract buildTokenContract(final ArgusProperties.Internal internal)
	{
		return AuthenticatedTokenContract.of(
				internal.issuer(),
				internal.audiences(),
				internal.tokenTtl(),
				internal.roleClaimName(),
				internal.versionClaimName(),
				Optional.of(internal.upstreamIssuerClaimName()),
				true);
	}

	private static AuthenticatedTokenMintingConfiguration buildMinting(final ArgusProperties.Internal internal)
	{
		if (internal.hmacSecret() == null || internal.hmacSecret().isBlank())
		{
			throw new IllegalStateException(
					"argus.internal.hmac-secret is required — property-based assembly only supports HMAC internal token signing");
		}
		return AuthenticatedTokenMintingConfiguration.of(TokenSignerConfiguration.Hmac.of(internal.hmacSecret()));
	}

	private static AuthenticatedTokenVerificationConfiguration buildVerification(
			final ArgusProperties.Internal internal)
	{
		final TokenTrustPolicy internalPolicy = TokenTrustPolicy.of(
				Duration.ZERO,
				true,
				internal.audiences(),
				Optional.of(internal.issuer()));
		return AuthenticatedTokenVerificationConfiguration.of(internalPolicy);
	}

	@SuppressWarnings({"unchecked"})
	private <User> IdentityMappingConfiguration<String, User> buildIdentityMapping(
			final ArgusUserResolver<User> userResolver,
			final ArgusVersionResolver versionResolver)
	{
		final UserResolver<String, User> argusUserResolver = userResolver::resolveUser;
		final ExternalIdentityAdapter<String> identityAdapter = ExternalIdentityAdapter.stringIdentity();
		final AuthenticatedSubjectVersionResolver currentVersionResolver = versionResolver::currentVersion;

		final LocalSubjectResolver<User> localSubjectResolver =
				(LocalSubjectResolver<User>) localSubjectResolverProvider.getIfAvailable(
						() -> String::valueOf);

		final RoleResolver<User> roleResolver =
				(RoleResolver<User>) roleResolverProvider.getIfAvailable(() -> _ -> Set.of());

		final UserTokenVersionResolver<User> versionAtMintResolver =
				(UserTokenVersionResolver<User>) userTokenVersionResolverProvider.getIfAvailable(() -> _ -> 1L);

		return IdentityMappingConfiguration.of(
				identityAdapter,
				argusUserResolver,
				localSubjectResolver,
				roleResolver,
				versionAtMintResolver,
				currentVersionResolver);
	}

	private ArgusPropertiesAssembler(
			final ArgusProperties properties,
			final ArgusUserResolver<?> userResolver,
			final ArgusVersionResolver versionResolver,
			final ObjectProvider<RoleResolver<?>> roleResolverProvider,
			final ObjectProvider<LocalSubjectResolver<?>> localSubjectResolverProvider,
			final ObjectProvider<UserTokenVersionResolver<?>> userTokenVersionResolverProvider,
			final ObjectProvider<Clock> clockProvider,
			final ObjectProvider<TokenAuthenticationCache> cacheProvider)
	{
		this.properties = properties;
		this.userResolver = userResolver;
		this.versionResolver = versionResolver;
		this.roleResolverProvider = roleResolverProvider;
		this.localSubjectResolverProvider = localSubjectResolverProvider;
		this.userTokenVersionResolverProvider = userTokenVersionResolverProvider;
		this.clockProvider = clockProvider;
		this.cacheProvider = cacheProvider;
	}
}