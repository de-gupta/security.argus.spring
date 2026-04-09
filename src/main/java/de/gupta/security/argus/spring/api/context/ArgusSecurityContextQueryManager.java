package de.gupta.security.argus.spring.api.context;

import de.gupta.security.argus.domain.model.identity.AuthenticatedIdentity;
import org.springframework.security.core.Authentication;

import java.util.Optional;
import java.util.Set;

public interface ArgusSecurityContextQueryManager
{
    Optional<Authentication> authentication();

    Optional<AuthenticatedIdentity> authenticatedIdentity();

    Optional<String> subject();

    Set<String> roles();

    boolean hasRole(String role);

    boolean isAuthenticated();
}