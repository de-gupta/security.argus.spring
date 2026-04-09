package de.gupta.security.argus.spring.api.authentication;

import de.gupta.security.argus.domain.model.identity.AuthenticatedIdentity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class ArgusAuthenticationToken extends AbstractAuthenticationToken
{
    private final String rawToken;
    private final AuthenticatedIdentity authenticatedIdentity;

    public static ArgusAuthenticationToken unauthenticated(final String rawToken)
    {
        return new ArgusAuthenticationToken(rawToken, null, List.of(), false);
    }

    public static ArgusAuthenticationToken authenticated(final AuthenticatedIdentity authenticatedIdentity,
                                                          final Collection<? extends GrantedAuthority> authorities)
    {
        return new ArgusAuthenticationToken(null, authenticatedIdentity, authorities, true);
    }

    public Optional<AuthenticatedIdentity> authenticatedIdentity()
    {
        return Optional.ofNullable(authenticatedIdentity);
    }

    @Override
    public Object getCredentials()
    {
        // TODO: should it be raw token or token from AuthenticatedIdentity? maybe if authenticated idnetity present, its token else raw token?
        return rawToken;
    }

    @Override
    public Object getPrincipal()
    {
        return authenticatedIdentity;
    }

    @Override
    public String getName()
    {
        return authenticatedIdentity == null ? "" : authenticatedIdentity.subject();
    }

    private ArgusAuthenticationToken(final String rawToken,
                                     final AuthenticatedIdentity authenticatedIdentity,
                                     final Collection<? extends GrantedAuthority> authorities,
                                     final boolean authenticated)
    {
        super(List.copyOf(Objects.requireNonNull(authorities, "authorities must not be null")));
        this.rawToken = rawToken;
        this.authenticatedIdentity = authenticatedIdentity;
        super.setAuthenticated(authenticated);
    }
}