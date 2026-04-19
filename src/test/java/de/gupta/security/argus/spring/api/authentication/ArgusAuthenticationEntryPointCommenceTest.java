package de.gupta.security.argus.spring.api.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ArgusAuthenticationEntryPoint.commence")
final class ArgusAuthenticationEntryPointCommenceTest
{
	@Nested
	@DisplayName("when the authentication exception has a message")
	final class WithMessage
	{
		@Test
		@DisplayName("should expose that message in the unauthorized response body and header")
		void shouldExposeTheAuthenticationExceptionMessage() throws Exception
		{
			final ArgusAuthenticationEntryPoint entryPoint = new ArgusAuthenticationEntryPoint();
			final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/secured/resource");
			final MockHttpServletResponse response = new MockHttpServletResponse();

			entryPoint.commence(request, response, new BadCredentialsException(
					"The upstream identity was trusted, but no matching local user could be resolved."));

			assertThat(response.getStatus())
					.as("unauthorized status")
					.isEqualTo(401);
			assertThat(response.getContentType())
					.as("json content type")
					.startsWith(MediaType.APPLICATION_JSON_VALUE);
			assertThat(response.getHeader("WWW-Authenticate"))
					.as("bearer authentication header")
					.isEqualTo(
							"Bearer error=\"invalid_token\", error_description=\"The upstream identity was trusted, but no matching local user could be resolved.\"");
			assertThat(response.getContentAsString())
					.as("public error response payload")
					.isEqualTo("""
							{"status":401,"error":"Unauthorized","message":"The upstream identity was trusted, but no matching local user could be resolved.","path":"/secured/resource"}""");
		}
	}

	@Nested
	@DisplayName("when the authentication exception does not have a message")
	final class WithoutMessage
	{
		@Test
		@DisplayName("should fall back to the standard unauthorized reason phrase in body and header")
		void shouldFallBackToUnauthorized() throws Exception
		{
			final ArgusAuthenticationEntryPoint entryPoint = new ArgusAuthenticationEntryPoint();
			final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/secured/resource");
			final MockHttpServletResponse response = new MockHttpServletResponse();

			entryPoint.commence(request, response, new BadCredentialsException(""));

			assertThat(response.getStatus())
					.as("unauthorized status")
					.isEqualTo(401);
			assertThat(response.getHeader("WWW-Authenticate"))
					.as("fallback authentication header")
					.isEqualTo("Bearer error=\"invalid_token\", error_description=\"Unauthorized\"");
			assertThat(response.getContentAsString())
					.as("fallback error response payload")
					.isEqualTo("""
							{"status":401,"error":"Unauthorized","message":"Unauthorized","path":"/secured/resource"}""");
			assertThat(response.getErrorMessage())
					.as("servlet error message should not be used anymore")
					.isNull();
			assertThat(response.getContentType())
					.as("json content type")
					.startsWith(MediaType.APPLICATION_JSON_VALUE);
			assertThat(response.getCharacterEncoding())
					.as("utf-8 response encoding")
					.isEqualTo("UTF-8");
		}
	}
}