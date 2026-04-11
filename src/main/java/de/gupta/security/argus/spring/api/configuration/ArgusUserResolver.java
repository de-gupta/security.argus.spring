package de.gupta.security.argus.spring.api.configuration;

import java.util.Optional;

/**
 * Resolves a local application user from an external identity string (typically the
 * {@code sub} claim from the upstream IdP token, or a configured custom claim).
 *
 * <p>Implement this interface and expose it as a Spring bean. Argus will call it during
 * the token exchange pipeline to look up the user in your domain.
 *
 * <pre>{@code
 * @Service
 * class UserLookupService implements ArgusUserResolver<User> {
 *     public Optional<User> resolveUser(String externalId) {
 *         return userRepository.findByExternalId(externalId);
 *     }
 * }
 * }</pre>
 *
 * @param <User> your application's user type
 */
@FunctionalInterface
public interface ArgusUserResolver<User>
{
	Optional<User> resolveUser(String externalIdentity);
}