package de.gupta.security.argus.spring.adapter.method;

import de.gupta.security.argus.spring.api.context.ArgusSecurityContextQueryManager;
import de.gupta.security.argus.spring.api.method.ArgusMethodAccess;

import java.util.Arrays;
import java.util.Objects;

public final class DefaultArgusMethodAccess implements ArgusMethodAccess
{
    private final ArgusSecurityContextQueryManager securityContextQueryManager;

    @Override
    public boolean isAuthenticated()
    {
        return securityContextQueryManager.isAuthenticated();
    }

    @Override
    public boolean hasRole(final String role)
    {
        return securityContextQueryManager.hasRole(role);
    }

    @Override
    public boolean hasAnyRole(final String... roles)
    {
        return Arrays.stream(roles)
                     .flatMap(role -> Arrays.stream(role.split(",")))
                     .map(String::trim)
                     .filter(role -> !role.isBlank())
                     .anyMatch(securityContextQueryManager::hasRole);
    }

    @Override
    public boolean hasSubject(final String subject)
    {
        return securityContextQueryManager.subject()
                                          .map(subject::equals)
                                          .orElse(false);
    }

    public DefaultArgusMethodAccess(final ArgusSecurityContextQueryManager securityContextQueryManager)
    {
        this.securityContextQueryManager = Objects.requireNonNull(securityContextQueryManager,
                "securityContextQueryManager must not be null");
    }
}