package de.gupta.security.argus.spring.adapter.authentication;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

public final class BearerTokenAuthenticationConverter implements AuthenticationConverter
{
    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer ";

    @Override
    public Authentication convert(final HttpServletRequest request)
    {
        return Unfolding.beckon(request.getHeader(AUTHORIZATION))
                        .discern(this::isBearerHeader)
                        .metamorphose(this::extractToken)
                        .discern(token -> !token.isBlank())
                        .metamorphose(ArgusAuthenticationToken::unauthenticated)
                        .optional()
                        .orElse(null);
    }

    private boolean isBearerHeader(final String authorizationHeader)
    {
        return authorizationHeader.regionMatches(true, 0, BEARER, 0, BEARER.length());
    }

    private String extractToken(final String authorizationHeader)
    {
        return authorizationHeader.substring(BEARER.length()).trim();
    }
}

