package de.gupta.security.argus.spring.api.configuration;

/**
 * Resolves the current token version for an authenticated subject.
 *
 * <p>Argus uses token versioning for soft revocation: when a user's version in your
 * store is bumped (e.g., on password change or explicit logout), their existing tokens
 * become stale and are rejected.
 *
 * <p>Implement this interface and expose it as a Spring bean. Argus calls it on every
 * authenticated request to check whether the token's version matches the current version
 * for that subject.
 *
 * <pre>{@code
 * @Service
 * class TokenVersionService implements ArgusVersionResolver {
 *     public long currentVersion(String subject) {
 *         return userRepository.findBySubject(subject)
 *                              .map(User::tokenVersion)
 *                              .orElse(0L);
 *     }
 * }
 * }</pre>
 */
@FunctionalInterface
public interface ArgusVersionResolver
{
	long currentVersion(String subject);
}