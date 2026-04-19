package de.gupta.security.argus.spring.api.method;

public interface ArgusMethodAccess
{
    boolean isAuthenticated();

    boolean hasRole(String role);

    boolean hasAnyRole(String... roles);

    boolean hasSubject(String subject);
}