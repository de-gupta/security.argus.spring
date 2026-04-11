package de.gupta.security.argus.spring.api.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.Set;

/**
 * Configuration properties for Argus auto-assembly.
 *
 * <pre>{@code
 * argus:
 *   upstream:
 *     hmac-secret: "your-idp-jwt-secret"         # required for HMAC upstream
 *     issuer: "https://your-idp.example.com"      # optional: validate upstream issuer
 *     audiences:                                  # optional: validate upstream audience
 *       - "your-app"
 *     clock-skew: PT30S                           # default: PT0S
 *     require-subject: true                       # default: true
 *   internal:
 *     issuer: "my-app"                            # default: "argus"
 *     audiences:                                  # default: empty
 *       - "my-app"
 *     hmac-secret: "your-internal-signing-secret" # required for HMAC internal tokens
 *     token-ttl: PT15M                            # default: PT15M
 *     role-claim-name: "roles"                    # default: "roles"
 *     version-claim-name: "ver"                   # default: "ver"
 * }</pre>
 */
@ConfigurationProperties(prefix = "argus")
public record ArgusProperties(Upstream upstream, Internal internal)
{
	public ArgusProperties(
			@DefaultValue Upstream upstream,
			@DefaultValue Internal internal)
	{
		this.upstream = upstream != null ? upstream : new Upstream(null, null, Set.of(), Duration.ZERO, true);
		this.internal = internal != null ? internal :
				new Internal("argus", Set.of(), null, Duration.ofMinutes(15), "roles", "ver", "upstream_iss");
	}

	public record Upstream(
			String hmacSecret,
			String issuer,
			@DefaultValue Set<String> audiences,
			@DefaultValue("PT0S") Duration clockSkew,
			@DefaultValue("true") boolean requireSubject)
	{
		public Upstream
		{
			if (audiences == null)
			{
				audiences = Set.of();
			}
			if (clockSkew == null)
			{
				clockSkew = Duration.ZERO;
			}
		}
	}

	public record Internal(
			@DefaultValue("argus") String issuer,
			@DefaultValue Set<String> audiences,
			String hmacSecret,
			@DefaultValue("PT15M") Duration tokenTtl,
			@DefaultValue("roles") String roleClaimName,
			@DefaultValue("ver") String versionClaimName,
			@DefaultValue("upstream_iss") String upstreamIssuerClaimName)
	{
		public Internal
		{
			if (issuer == null || issuer.isBlank())
			{
				issuer = "argus";
			}
			if (audiences == null)
			{
				audiences = Set.of();
			}
			if (tokenTtl == null)
			{
				tokenTtl = Duration.ofMinutes(15);
			}
			if (roleClaimName == null || roleClaimName.isBlank())
			{
				roleClaimName = "roles";
			}
			if (versionClaimName == null || versionClaimName.isBlank())
			{
				versionClaimName = "ver";
			}
			if (upstreamIssuerClaimName == null || upstreamIssuerClaimName.isBlank())
			{
				upstreamIssuerClaimName = "upstream_iss";
			}
		}
	}
}