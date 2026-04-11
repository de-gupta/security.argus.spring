package de.gupta.security.argus.spring.api.configuration;

import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.api.authentication.AuthenticatorConfiguration;
import de.gupta.security.argus.api.cache.TokenAuthenticationCache;
import de.gupta.security.argus.api.identity.IdentityMappingConfiguration;
import de.gupta.security.argus.api.identity.LocalSubjectResolver;
import de.gupta.security.argus.api.identity.RoleResolver;
import de.gupta.security.argus.api.identity.UserTokenVersionResolver;
import de.gupta.security.argus.api.token.AuthenticatedTokenContract;
import de.gupta.security.argus.api.token.AuthenticatedTokenMintingConfiguration;
import de.gupta.security.argus.api.token.AuthenticatedTokenVerificationConfiguration;
import de.gupta.security.argus.api.trust.UpstreamTrustConfiguration;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolved;
import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationFilter;
import de.gupta.security.argus.spring.api.context.ArgusSecurityContextQueryManager;
import de.gupta.security.argus.spring.test.TestAuthenticators;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Argus properties-driven auto-assembly")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class ArgusPropertiesAssemblyTest
{
	private static final String UPSTREAM_SECRET = TestAuthenticators.UPSTREAM_SECRET;
	private static final String INTERNAL_SECRET = TestAuthenticators.INTERNAL_SECRET;
	private static final String UPSTREAM_ISSUER = TestAuthenticators.UPSTREAM_ISSUER;
	private static final String INTERNAL_ISSUER = TestAuthenticators.INTERNAL_ISSUER;
	private static final String AUDIENCE = TestAuthenticators.AUDIENCE;
	private static final Clock CLOCK = TestAuthenticators.CLOCK;

	private ApplicationContextRunner baseRunner()
	{
		return new ApplicationContextRunner().withUserConfiguration(ArgusSpringConfiguration.class);
	}

	/**
	 * Standard runner with:
	 * - all required properties set
	 * - ArgusUserResolver returning the externalId as-is (empty for "missing-user")
	 * - ArgusVersionResolver returning 3L for all subjects
	 * - Clock fixed at the test instant so tokens don't expire
	 */
	private ApplicationContextRunner runnerWithMinimalProperties()
	{
		return baseRunner()
				.withPropertyValues(
						"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
						"argus.upstream.issuer=" + UPSTREAM_ISSUER,
						"argus.upstream.audiences=" + AUDIENCE,
						"argus.upstream.require-subject=true",
						"argus.internal.issuer=" + INTERNAL_ISSUER,
						"argus.internal.audiences=" + AUDIENCE,
						"argus.internal.hmac-secret=" + INTERNAL_SECRET)
				.withBean(ArgusUserResolver.class,
						() -> (ArgusUserResolver<String>) externalId ->
								"missing-user".equals(externalId) ? Optional.empty() : Optional.of(externalId))
				.withBean(ArgusVersionResolver.class, () -> _ -> 3L)
				.withBean(Clock.class, () -> CLOCK);
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Assembly activation conditions
	// ─────────────────────────────────────────────────────────────────────────

	private static final class RecordingCache implements TokenAuthenticationCache
	{
		private final Map<String, AuthenticationResult> store = new HashMap<>();
		private int getCallCount;
		private int putCallCount;

		@Override
		public Optional<AuthenticationResult> get(final String tokenHash)
		{
			getCallCount++;
			return Optional.ofNullable(store.get(tokenHash));
		}

		@Override
		public void put(final String tokenHash, final AuthenticationResult result, final Instant expiresAt)
		{
			putCallCount++;
			store.put(tokenHash, result);
		}

		@Override
		public void invalidateBySubject(final String subject)
		{
		}

		int getCallCount()
		{
			return getCallCount;
		}

		int putCallCount()
		{
			return putCallCount;
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Assembly path precedence
	// ─────────────────────────────────────────────────────────────────────────

	@Nested
	@DisplayName("assembly activation conditions")
	final class ActivationConditions
	{
		@Test
		void shouldCreateAuthenticatorWhenResolversAndPropertiesArePresent()
		{
			runnerWithMinimalProperties()
					.run(context ->
					{
						assertThat(context).hasSingleBean(Authenticator.class);
						assertThat(context).hasSingleBean(AuthenticatorConfiguration.class);
						assertThat(context).hasSingleBean(ArgusAuthenticationFilter.class);
						assertThat(context).hasSingleBean(ArgusSecurityContextQueryManager.class);
					});
		}

		@Test
		void shouldNotActivateWhenBothResolverBeansAreMissing()
		{
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.internal.hmac-secret=" + INTERNAL_SECRET)
					.run(context -> assertThat(context).doesNotHaveBean(Authenticator.class));
		}

		@Test
		void shouldNotActivateWhenVersionResolverIsMissing()
		{
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.internal.hmac-secret=" + INTERNAL_SECRET)
					.withBean(ArgusUserResolver.class,
							() -> (ArgusUserResolver<String>) Optional::of)
					.run(context -> assertThat(context).doesNotHaveBean(Authenticator.class));
		}

		@Test
		void shouldNotActivateWhenUserResolverIsMissing()
		{
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.internal.hmac-secret=" + INTERNAL_SECRET)
					.withBean(ArgusVersionResolver.class, () -> _ -> 1L)
					.run(context -> assertThat(context).doesNotHaveBean(Authenticator.class));
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Function bean adapters
	// ─────────────────────────────────────────────────────────────────────────

	@Nested
	@DisplayName("assembly path precedence")
	final class AssemblyPathPrecedence
	{
		@Test
		void explicitAuthenticatorBeanTakesPrecedenceOverPropertiesAssembly()
		{
			runnerWithMinimalProperties()
					.withBean(Authenticator.class,
							() -> TestAuthenticators.directAuthenticator(new AtomicLong(3L)))
					.run(context ->
					{
						assertThat(context).hasSingleBean(Authenticator.class);
						assertThat(context).doesNotHaveBean("argusManagedAuthenticatorConfigurationFromProperties");
						assertThat(context).doesNotHaveBean("argusManagedAuthenticatorConfiguration");
					});
		}

		@Test
		void explicitAuthenticatorConfigurationBeanTakesPrecedenceOverPropertiesAssembly()
		{
			runnerWithMinimalProperties()
					.withBean(AuthenticatorConfiguration.class,
							() -> TestAuthenticators.authenticatorConfiguration(new AtomicLong(3L)))
					.run(context ->
					{
						assertThat(context).hasSingleBean(Authenticator.class);
						assertThat(context).doesNotHaveBean("argusManagedAuthenticatorConfigurationFromProperties");
					});
		}

		@Test
		void explicitDomainBeansTakesPrecedenceOverPropertiesAssembly()
		{
			// Only domain beans provided — no resolver beans — so properties path cannot activate.
			// Domain-bean path creates "argusManagedAuthenticatorConfiguration".
			baseRunner()
					.withBean(UpstreamTrustConfiguration.class,
							TestAuthenticators::upstreamTrustConfiguration)
					.withBean(AuthenticatedTokenContract.class,
							TestAuthenticators::authenticatedTokenContract)
					.withBean(AuthenticatedTokenMintingConfiguration.class,
							TestAuthenticators::authenticatedTokenMintingConfiguration)
					.withBean(AuthenticatedTokenVerificationConfiguration.class,
							TestAuthenticators::authenticatedTokenVerificationConfiguration)
					.withBean(IdentityMappingConfiguration.class,
							() -> TestAuthenticators.identityMappingConfiguration(_ -> 3L))
					.run(context ->
					{
						assertThat(context).hasSingleBean(Authenticator.class);
						assertThat(context).hasSingleBean(AuthenticatorConfiguration.class);
						assertThat(context).doesNotHaveBean("argusManagedAuthenticatorConfigurationFromProperties");
						assertThat(context).hasBean("argusManagedAuthenticatorConfiguration");
					});
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Property values are propagated correctly
	// ─────────────────────────────────────────────────────────────────────────

	@Nested
	@DisplayName("Function bean adapters")
	final class FunctionBeanAdapters
	{
		@Test
		void shouldWireAuthenticatorFromFunctionBeans()
		{
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.upstream.issuer=" + UPSTREAM_ISSUER,
							"argus.upstream.audiences=" + AUDIENCE,
							"argus.internal.issuer=" + INTERNAL_ISSUER,
							"argus.internal.audiences=" + AUDIENCE,
							"argus.internal.hmac-secret=" + INTERNAL_SECRET)
					.withBean("argusUserResolverFunction", Function.class,
							() -> (Function<String, Optional<String>>) id ->
									"missing-user".equals(id) ? Optional.empty() : Optional.of(id))
					.withBean("argusVersionResolverFunction", Function.class,
							() -> (Function<String, Long>) _ -> 3L)
					.withBean(Clock.class, () -> CLOCK)
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.run(context ->
					{
						assertThat(context).hasSingleBean(Authenticator.class);
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("external-user"));
						assertThat(result).isInstanceOf(AuthenticationSuccess.class);
					});
		}

		@Test
		void shouldPreferArgusUserResolverBeanOverFunctionBean()
		{
			final AtomicInteger functionCallCount = new AtomicInteger();

			runnerWithMinimalProperties()
					.withBean("argusUserResolverFunction", Function.class,
							() -> (Function<String, Optional<String>>) id ->
							{
								functionCallCount.incrementAndGet();
								return Optional.of(id);
							})
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.run(context ->
					{
						final Authenticator authenticator = context.getBean(Authenticator.class);
						authenticator.authenticate(TestAuthenticators.token("external-user"));
						assertThat(functionCallCount).hasValue(0);
					});
		}

		@Test
		void shouldPreferArgusVersionResolverBeanOverFunctionBean()
		{
			final AtomicInteger functionCallCount = new AtomicInteger();

			runnerWithMinimalProperties()
					.withBean("argusVersionResolverFunction", Function.class,
							() -> (Function<String, Long>) _ ->
							{
								functionCallCount.incrementAndGet();
								return 3L;
							})
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.run(context ->
					{
						final Authenticator authenticator = context.getBean(Authenticator.class);
						authenticator.authenticate(TestAuthenticators.token("external-user"));
						assertThat(functionCallCount).hasValue(0);
					});
		}

		@Test
		void shouldNotActivateWhenOnlyUserFunctionBeanIsPresentWithoutVersionFunction()
		{
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.internal.hmac-secret=" + INTERNAL_SECRET)
					.withBean("argusUserResolverFunction", Function.class,
							() -> (Function<String, Optional<String>>) Optional::ofNullable)
					.run(context -> assertThat(context).doesNotHaveBean(Authenticator.class));
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Optional resolver beans override defaults
	// ─────────────────────────────────────────────────────────────────────────

	@Nested
	@DisplayName("property propagation")
	final class PropertyPropagation
	{
		@Test
		void shouldUseDefaultsWhenOnlySecretsAreProvided()
		{
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.internal.hmac-secret=" + INTERNAL_SECRET)
					.withBean(ArgusUserResolver.class,
							() -> (ArgusUserResolver<String>) Optional::of)
					.withBean(ArgusVersionResolver.class, () -> _ -> 1L)
					.run(context ->
					{
						assertThat(context).hasSingleBean(Authenticator.class);
						final ArgusProperties props = context.getBean(ArgusProperties.class);
						assertThat(props.internal().issuer()).isEqualTo("argus");
						assertThat(props.internal().roleClaimName()).isEqualTo("roles");
						assertThat(props.internal().versionClaimName()).isEqualTo("ver");
						assertThat(props.internal().tokenTtl()).isEqualTo(Duration.ofMinutes(15));
						assertThat(props.internal().upstreamIssuerClaimName()).isEqualTo("upstream_iss");
						assertThat(props.upstream().requireSubject()).isTrue();
						assertThat(props.upstream().clockSkew()).isEqualTo(Duration.ZERO);
						assertThat(props.upstream().audiences()).isEmpty();
						assertThat(props.upstream().issuer()).isNull();
					});
		}

		@Test
		void shouldBindCustomInternalIssuerAndTtl()
		{
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.internal.hmac-secret=" + INTERNAL_SECRET,
							"argus.internal.issuer=my-service",
							"argus.internal.token-ttl=PT30M")
					.withBean(ArgusUserResolver.class,
							() -> (ArgusUserResolver<String>) Optional::of)
					.withBean(ArgusVersionResolver.class, () -> _ -> 1L)
					.run(context ->
					{
						final ArgusProperties props = context.getBean(ArgusProperties.class);
						assertThat(props.internal().issuer()).isEqualTo("my-service");
						assertThat(props.internal().tokenTtl()).isEqualTo(Duration.ofMinutes(30));
					});
		}

		@Test
		void shouldBindCustomClaimNames()
		{
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.internal.hmac-secret=" + INTERNAL_SECRET,
							"argus.internal.role-claim-name=user_roles",
							"argus.internal.version-claim-name=token_ver",
							"argus.internal.upstream-issuer-claim-name=iss_upstream")
					.withBean(ArgusUserResolver.class,
							() -> (ArgusUserResolver<String>) Optional::of)
					.withBean(ArgusVersionResolver.class, () -> _ -> 1L)
					.run(context ->
					{
						final ArgusProperties props = context.getBean(ArgusProperties.class);
						assertThat(props.internal().roleClaimName()).isEqualTo("user_roles");
						assertThat(props.internal().versionClaimName()).isEqualTo("token_ver");
						assertThat(props.internal().upstreamIssuerClaimName()).isEqualTo("iss_upstream");
					});
		}

		@Test
		void shouldBindUpstreamIssuerAudiencesAndClockSkew()
		{
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.upstream.issuer=https://my-idp.example.com",
							"argus.upstream.audiences=service-a,service-b",
							"argus.upstream.clock-skew=PT45S",
							"argus.upstream.require-subject=false",
							"argus.internal.hmac-secret=" + INTERNAL_SECRET)
					.withBean(ArgusUserResolver.class,
							() -> (ArgusUserResolver<String>) Optional::of)
					.withBean(ArgusVersionResolver.class, () -> _ -> 1L)
					.run(context ->
					{
						final ArgusProperties props = context.getBean(ArgusProperties.class);
						assertThat(props.upstream().issuer()).isEqualTo("https://my-idp.example.com");
						assertThat(props.upstream().audiences()).containsExactlyInAnyOrder("service-a", "service-b");
						assertThat(props.upstream().clockSkew()).isEqualTo(Duration.ofSeconds(45));
						assertThat(props.upstream().requireSubject()).isFalse();
					});
		}

		@Test
		void shouldFailEarlyWhenUpstreamSecretIsMissing()
		{
			baseRunner()
					.withPropertyValues("argus.internal.hmac-secret=" + INTERNAL_SECRET)
					.withBean(ArgusUserResolver.class,
							() -> (ArgusUserResolver<String>) Optional::of)
					.withBean(ArgusVersionResolver.class, () -> _ -> 1L)
					.run(context -> assertThat(context).hasFailed()
					                                   .getFailure()
					                                   .rootCause()
					                                   .hasMessageContaining("argus.upstream.hmac-secret"));
		}

		@Test
		void shouldFailEarlyWhenInternalSecretIsMissing()
		{
			baseRunner()
					.withPropertyValues("argus.upstream.hmac-secret=" + UPSTREAM_SECRET)
					.withBean(ArgusUserResolver.class,
							() -> (ArgusUserResolver<String>) Optional::of)
					.withBean(ArgusVersionResolver.class, () -> _ -> 1L)
					.run(context -> assertThat(context).hasFailed()
					                                   .getFailure()
					                                   .rootCause()
					                                   .hasMessageContaining("argus.internal.hmac-secret"));
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// User resolver behaviour
	// ─────────────────────────────────────────────────────────────────────────

	@Nested
	@DisplayName("optional resolver beans")
	final class OptionalResolverBeans
	{
		@Test
		void shouldUseRoleResolverBeanAndReturnRolesInSuccessIdentity()
		{
			runnerWithMinimalProperties()
					.withBean(RoleResolver.class,
							() -> (RoleResolver<String>) _ -> Set.of("ROLE_ADMIN", "ROLE_USER"))
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("external-user"));

						assertThat(result).isInstanceOf(AuthenticationSuccess.class);
						assertThat(((AuthenticationSuccess) result).identity().roles())
								.containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
					});
		}

		@Test
		void shouldReturnEmptyRolesWhenNoRoleResolverBeanIsPresent()
		{
			runnerWithMinimalProperties()
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("external-user"));

						assertThat(result).isInstanceOf(AuthenticationSuccess.class);
						assertThat(((AuthenticationSuccess) result).identity().roles()).isEmpty();
					});
		}

		@Test
		void shouldUseLocalSubjectResolverBeanAndReflectSubjectInIdentity()
		{
			runnerWithMinimalProperties()
					.withBean(LocalSubjectResolver.class,
							() -> (LocalSubjectResolver<String>) user -> "local::" + user)
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("external-user"));

						assertThat(result).isInstanceOf(AuthenticationSuccess.class);
						assertThat(((AuthenticationSuccess) result).identity().subject())
								.isEqualTo("local::external-user");
					});
		}

		@Test
		void shouldUseStringValueOfSubjectWhenNoLocalSubjectResolverBeanIsPresent()
		{
			runnerWithMinimalProperties()
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("external-user"));

						assertThat(result).isInstanceOf(AuthenticationSuccess.class);
						// default LocalSubjectResolver: String.valueOf(user); ArgusUserResolver returns externalId as-is
						assertThat(((AuthenticationSuccess) result).identity().subject()).isEqualTo("external-user");
					});
		}

		@Test
		void shouldUseUserTokenVersionResolverBeanForVersionAtMintTime()
		{
			// ArgusVersionResolver (current) returns 3L.
			// UserTokenVersionResolver (at mint) returns 99L → minted token has ver=99, current=3 → NotCurrent.
			runnerWithMinimalProperties()
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 99L)
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("external-user"));

						assertThat(result).isInstanceOf(AuthenticationNotCurrent.class);
					});
		}

		@Test
		void shouldDefaultMintVersionToOneWhenNoUserTokenVersionResolverBeanIsPresent()
		{
			// Default UserTokenVersionResolver returns 1L.
			// ArgusVersionResolver (current) returns 3L → minted=1, current=3 → NotCurrent.
			runnerWithMinimalProperties()
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("external-user"));

						assertThat(result).isInstanceOf(AuthenticationNotCurrent.class);
					});
		}

		@Test
		void shouldSucceedWhenMintVersionAndCurrentVersionMatch()
		{
			runnerWithMinimalProperties()
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("external-user"));

						assertThat(result).isInstanceOf(AuthenticationSuccess.class);
					});
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Optional infrastructure beans
	// ─────────────────────────────────────────────────────────────────────────

	@Nested
	@DisplayName("user resolver behaviour")
	final class UserResolverBehaviour
	{
		@Test
		void shouldRejectAuthenticationWhenUserResolverReturnsEmpty()
		{
			// "missing-user" → Optional.empty() in the minimal runner's ArgusUserResolver
			runnerWithMinimalProperties()
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("missing-user"));

						assertThat(result).isInstanceOf(IdentityNotResolved.class);
					});
		}

		@Test
		void shouldRejectAuthenticationWhenTokenSignatureIsInvalid()
		{
			runnerWithMinimalProperties()
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.invalidSignatureToken(
																				   "external-user"));

						assertThat(result).isInstanceOf(InvalidCredential.class);
					});
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Test helpers
	// ─────────────────────────────────────────────────────────────────────────

	@Nested
	@DisplayName("optional infrastructure beans")
	final class OptionalInfrastructureBeans
	{
		@Test
		void shouldUseTokenAuthenticationCacheBeanWhenPresent()
		{
			final RecordingCache cache = new RecordingCache();

			runnerWithMinimalProperties()
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.withBean(TokenAuthenticationCache.class, () -> cache)
					.run(context ->
					{
						final Authenticator authenticator = context.getBean(Authenticator.class);
						final String token = TestAuthenticators.token("external-user");
						authenticator.authenticate(token);
						authenticator.authenticate(token);

						// First call: cache miss → delegate runs → put called.
						// Second call: cache hit → delegate not called → get returns value.
						assertThat(cache.putCallCount()).isEqualTo(1);
						assertThat(cache.getCallCount()).isEqualTo(2);
					});
		}

		@Test
		void shouldFunctionWithoutCacheBeanUsingNoOpDefault()
		{
			// No cache bean → no-op → every call hits the delegate → still works
			runnerWithMinimalProperties()
					.withBean(UserTokenVersionResolver.class,
							() -> (UserTokenVersionResolver<String>) _ -> 3L)
					.run(context ->
					{
						final Authenticator authenticator = context.getBean(Authenticator.class);
						final AuthenticationResult first = authenticator.authenticate(
								TestAuthenticators.token("external-user"));
						final AuthenticationResult second = authenticator.authenticate(
								TestAuthenticators.token("external-user"));

						assertThat(first).isInstanceOf(AuthenticationSuccess.class);
						assertThat(second).isInstanceOf(AuthenticationSuccess.class);
					});
		}

		@Test
		void shouldUseClockBeanForTokenValidation()
		{
			// Tokens minted with CLOCK (2026-04-09T12:00:00Z, valid for 30 min).
			// A clock far in the future makes the token appear expired → InvalidCredential.
			final Clock futureClockFarAhead = Clock.fixed(
					Instant.parse("2099-01-01T00:00:00Z"), ZoneOffset.UTC);

			// Build runner without a Clock bean, then provide the future one.
			baseRunner()
					.withPropertyValues(
							"argus.upstream.hmac-secret=" + UPSTREAM_SECRET,
							"argus.upstream.issuer=" + UPSTREAM_ISSUER,
							"argus.upstream.audiences=" + AUDIENCE,
							"argus.upstream.require-subject=true",
							"argus.internal.issuer=" + INTERNAL_ISSUER,
							"argus.internal.audiences=" + AUDIENCE,
							"argus.internal.hmac-secret=" + INTERNAL_SECRET)
					.withBean(ArgusUserResolver.class,
							() -> (ArgusUserResolver<String>) externalId ->
									"missing-user".equals(externalId) ? Optional.empty() : Optional.of(externalId))
					.withBean(ArgusVersionResolver.class, () -> _ -> 3L)
					.withBean(Clock.class, () -> futureClockFarAhead)
					.run(context ->
					{
						final AuthenticationResult result = context.getBean(Authenticator.class)
						                                           .authenticate(
																		   TestAuthenticators.token("external-user"));

						assertThat(result).isInstanceOf(InvalidCredential.class);
					});
		}
	}
}