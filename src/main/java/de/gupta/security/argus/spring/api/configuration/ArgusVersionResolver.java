package de.gupta.security.argus.spring.api.configuration;

import java.time.Instant;

/**
 * Resolves the timestamp of the last revocation event for a user identity.
 *
 * <p>Argus uses this for token currentness checking: if a token's {@code iat} (issued-at)
 * claim is before the value returned by this resolver, the token is considered superseded
 * and the request is rejected with {@code AuthenticationNotCurrent}.
 *
 * <p>Return {@link Instant#EPOCH} to indicate that no revocation has ever occurred for
 * this user, which means all tokens issued at any time will be accepted.
 *
 * <p>Implement this interface and expose it as a Spring bean. Argus calls it on every
 * authenticated request, before the token exchange step.
 *
 * <pre>{@code
 * @Service
 * class RevocationService implements ArgusVersionResolver {
 *     public Instant lastRevokedAt(String externalIdentity) {
 *         return userRepository.findByExternalId(externalIdentity)
 *                              .map(User::lastRevokedAt)
 *                              .orElse(Instant.EPOCH);  // never revoked
 *     }
 * }
 * }</pre>
 *
 * <p>To revoke all tokens for a user, update their {@code lastRevokedAt} to the current
 * time. Any token with an {@code iat} before that timestamp will be rejected on the next
 * request. If you use caching, also call
 * {@code TokenAuthenticationCache.invalidateBySubject()} to take effect immediately.
 */
@FunctionalInterface
public interface ArgusVersionResolver
{
	Instant lastRevokedAt(String externalIdentity);
}
