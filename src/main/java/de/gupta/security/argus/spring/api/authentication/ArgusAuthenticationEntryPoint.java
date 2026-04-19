package de.gupta.security.argus.spring.api.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class ArgusAuthenticationEntryPoint implements AuthenticationEntryPoint
{
    private static final Logger LOG = LoggerFactory.getLogger(ArgusAuthenticationEntryPoint.class);

    @Override
    public void commence(final HttpServletRequest request,
                         final HttpServletResponse response,
                         final AuthenticationException authException)
            throws IOException
    {
        final String message = resolveMessage(authException);
        LOG.debug("Argus returning 401 for {} {}: {}",
                request.getMethod(),
                request.getRequestURI(),
                message);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("WWW-Authenticate", wwwAuthenticateHeaderValue(message));
        response.getWriter()
                .write(unauthorizedResponseBody(message, request.getRequestURI()));
    }

    private static String resolveMessage(final AuthenticationException authException)
    {
        return authException == null || authException.getMessage() == null || authException.getMessage().isBlank()
                ? HttpStatus.UNAUTHORIZED.getReasonPhrase()
                : authException.getMessage();
    }

    private static String unauthorizedResponseBody(final String message,
                                                   final String path)
    {
        return """
                {"status":401,"error":"Unauthorized","message":"%s","path":"%s"}"""
                .formatted(jsonEscape(message), jsonEscape(path));
    }

    private static String wwwAuthenticateHeaderValue(final String message)
    {
        return "Bearer error=\"invalid_token\", error_description=\"%s\""
                .formatted(headerEscape(message));
    }

    private static String jsonEscape(final String value)
    {
        final StringBuilder result = new StringBuilder(value.length() + 8);
        for (final char current : value.toCharArray())
        {
            switch (current)
            {
                case '\\' -> result.append("\\\\");
                case '"' -> result.append("\\\"");
                case '\b' -> result.append("\\b");
                case '\f' -> result.append("\\f");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default ->
                {
                    if (current < 0x20)
                    {
                        result.append("\\u%04x".formatted((int) current));
                    }
                    else
                    {
                        result.append(current);
                    }
                }
            }
        }
        return result.toString();
    }

    private static String headerEscape(final String value)
    {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }
}