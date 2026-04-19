package de.gupta.security.argus.spring.adapter.context;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.security.argus.domain.model.identity.AuthenticatedIdentity;
import de.gupta.security.argus.spring.api.context.ArgusSecurityContextQueryManager;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public final class DefaultArgusSecurityContextQueryManager implements ArgusSecurityContextQueryManager
{
    @Override
    public Optional<Authentication> authentication()
    {
        return Unfolding.beckon(SecurityContextHolder.getContext().getAuthentication()).optional();
    }

    @Override
    public Optional<AuthenticatedIdentity> authenticatedIdentity()
    {
        return authentication().filter(this::isRealAuthentication)
                               .map(Authentication::getPrincipal)
                               .filter(AuthenticatedIdentity.class::isInstance)
                               .map(AuthenticatedIdentity.class::cast);
    }

    @Override
    public Optional<String> subject()
    {
        return authenticatedIdentity().map(AuthenticatedIdentity::subject);
    }

    @Override
    public Set<String> roles()
    {
        return authenticatedIdentity().map(AuthenticatedIdentity::roles)
                                      .orElseGet(this::authorityRoles);
    }

    @Override
    public boolean hasRole(final String role)
    {
        final String normalizedRole = normalizeRole(role);
        return roles().stream().map(this::normalizeRole).anyMatch(normalizedRole::equalsIgnoreCase);
    }

    @Override
    public boolean isAuthenticated()
    {
        return authentication().filter(this::isRealAuthentication).isPresent();
    }

    private boolean isRealAuthentication(final Authentication authentication)
    {
        return authentication.isAuthenticated() && !(authentication instanceof AnonymousAuthenticationToken);
    }

    private Set<String> authorityRoles()
    {
        return authentication().stream()
                               .flatMap(authentication -> authentication.getAuthorities().stream())
                               .map(GrantedAuthority::getAuthority)
                               .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private String normalizeRole(final String role)
    {
        return role.regionMatches(true, 0, "ROLE_", 0, "ROLE_".length()) ? role.substring(5) : role;
    }
}