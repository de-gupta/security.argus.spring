package de.gupta.security.argus.spring.api.authentication;

import de.gupta.aletheia.functional.Unfolding;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

public final class ArgusAuthenticationFilter extends OncePerRequestFilter
{
    private final AuthenticationManager authenticationManager;
    private final AuthenticationConverter authenticationConverter;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain)
            throws ServletException, IOException
    {
        if (securityContextPopulated())
        {
            filterChain.doFilter(request, response);
            return;
        }

        final Authentication authenticationRequest = Unfolding.beckon(authenticationConverter.convert(request))
                                                                .ordain((Authentication) null);
        if (authenticationRequest == null)
        {
            filterChain.doFilter(request, response);
            return;
        }

        try
        {
            final Authentication authentication = authenticationManager.authenticate(authenticationRequest);
            final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);
            filterChain.doFilter(request, response);
        }
        catch (final AuthenticationException exception)
        {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response, exception);
        }
    }

    private boolean securityContextPopulated()
    {
        return Unfolding.beckon(SecurityContextHolder.getContext().getAuthentication())
                         .discern(Authentication::isAuthenticated)
                         .supple();
    }

    public ArgusAuthenticationFilter(final AuthenticationManager authenticationManager,
                                     final AuthenticationConverter authenticationConverter,
                                     final AuthenticationEntryPoint authenticationEntryPoint)
    {
        this.authenticationManager = Objects.requireNonNull(authenticationManager,
                "authenticationManager must not be null");
        this.authenticationConverter = Objects.requireNonNull(authenticationConverter,
                "authenticationConverter must not be null");
        this.authenticationEntryPoint = Objects.requireNonNull(authenticationEntryPoint,
                "authenticationEntryPoint must not be null");
    }
}