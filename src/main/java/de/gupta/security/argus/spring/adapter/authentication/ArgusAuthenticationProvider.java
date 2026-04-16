package de.gupta.security.argus.spring.adapter.authentication;

import de.gupta.security.argus.api.authentication.Authenticator;
import de.gupta.security.argus.domain.model.authentication.AuthenticationFailure;
import de.gupta.security.argus.domain.model.authentication.AuthenticationResult;
import de.gupta.security.argus.domain.model.authentication.AuthenticationSuccess;
import de.gupta.security.argus.domain.model.authentication.FailureDetails;
import de.gupta.security.argus.domain.model.authentication.availability.AuthenticationUnavailable;
import de.gupta.security.argus.domain.model.authentication.credential.InvalidCredential;
import de.gupta.security.argus.domain.model.authentication.currentness.AuthenticationNotCurrent;
import de.gupta.security.argus.domain.model.authentication.identity.IdentityNotResolved;
import de.gupta.security.argus.domain.model.identity.AuthenticatedIdentity;
import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public final class ArgusAuthenticationProvider implements AuthenticationProvider
{
	private static final Logger LOG = LoggerFactory.getLogger(ArgusAuthenticationProvider.class);

	private final Authenticator authenticator;

	@Override
	public Authentication authenticate(final Authentication authentication) throws AuthenticationException
	{
		if (!(authentication instanceof ArgusAuthenticationToken tokenRequest) || !(tokenRequest.getCredentials() instanceof String rawToken))
		{
			return null;
		}

		final AuthenticationResult authenticationResult = authenticator.authenticate(rawToken);
		return switch (authenticationResult)
		{
			case AuthenticationSuccess success -> ArgusAuthenticationToken.authenticated(success.identity(),
					authoritiesOf(success.identity()));
			case InvalidCredential failure -> throw logAndWrapBadCredentials(failure);
			case IdentityNotResolved failure -> throw logAndWrapBadCredentials(failure);
			case AuthenticationNotCurrent failure -> throw logAndWrapExpiredCredentials(failure);
			case AuthenticationUnavailable failure -> throw logAndWrapServiceUnavailable(failure);
		};
	}

	@Override
	public boolean supports(final Class<?> authentication)
	{
		return ArgusAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private Set<GrantedAuthority> authoritiesOf(final AuthenticatedIdentity identity)
	{
		return identity.roles().stream()
		               .flatMap(role -> roleAuthorities(role).stream())
		               .map(SimpleGrantedAuthority::new)
		               .collect(Collectors.toCollection(LinkedHashSet::new));
	}

	private Set<String> roleAuthorities(final String role)
	{
		if (role.regionMatches(true, 0, "ROLE_", 0, "ROLE_".length()))
		{
			return Set.of(role);
		}
		return Set.of(role, "ROLE_" + role);
	}

	private String messageOf(final AuthenticationFailure failure)
	{
		return failure.details()
		              .map(FailureDetails::message)
		              .orElseGet(failure::description);
	}

	private BadCredentialsException logAndWrapBadCredentials(final AuthenticationFailure failure)
	{
		final String message = messageOf(failure);
		LOG.debug("Argus authentication rejected the presented bearer token: {}", message);
		return new BadCredentialsException(message);
	}

	private CredentialsExpiredException logAndWrapExpiredCredentials(final AuthenticationFailure failure)
	{
		final String message = messageOf(failure);
		LOG.info("Argus authentication rejected a no-longer-current bearer token: {}", message);
		return new CredentialsExpiredException(message);
	}

	private AuthenticationServiceException logAndWrapServiceUnavailable(final AuthenticationFailure failure)
	{
		final String message = messageOf(failure);
		LOG.warn("Argus authentication could not complete because a required dependency was unavailable: {}",
				message);
		return new AuthenticationServiceException(message);
	}

	public ArgusAuthenticationProvider(final Authenticator authenticator)
	{
		this.authenticator = Objects.requireNonNull(authenticator, "authenticator must not be null");
	}
}
