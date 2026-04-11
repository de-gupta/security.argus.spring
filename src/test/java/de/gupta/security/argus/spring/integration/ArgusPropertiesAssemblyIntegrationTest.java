package de.gupta.security.argus.spring.integration;

import de.gupta.security.argus.api.identity.UserTokenVersionResolver;
import de.gupta.security.argus.spring.api.configuration.ArgusSecurityCustomizer;
import de.gupta.security.argus.spring.api.configuration.ArgusUserResolver;
import de.gupta.security.argus.spring.api.configuration.ArgusVersionResolver;
import de.gupta.security.argus.spring.api.method.EnableArgusMethodSecurity;
import de.gupta.security.argus.spring.api.method.RequireAuthenticated;
import de.gupta.security.argus.spring.api.method.RequireRole;
import de.gupta.security.argus.spring.test.TestAuthenticators;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.util.Optional;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Full Spring Boot integration test that uses only application properties
 * and resolver beans — no manually provided {@code Authenticator} bean.
 * Verifies that the auto-assembly path produces a correctly wired filter
 * chain that authenticates real HTTP requests.
 */
@SpringBootTest(classes = ArgusPropertiesAssemblyIntegrationTest.TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
		"argus.upstream.hmac-secret=" + TestAuthenticators.UPSTREAM_SECRET,
		"argus.upstream.issuer=" + TestAuthenticators.UPSTREAM_ISSUER,
		"argus.upstream.audiences=" + TestAuthenticators.AUDIENCE,
		"argus.upstream.require-subject=true",
		"argus.internal.issuer=" + TestAuthenticators.INTERNAL_ISSUER,
		"argus.internal.audiences=" + TestAuthenticators.AUDIENCE,
		"argus.internal.hmac-secret=" + TestAuthenticators.INTERNAL_SECRET
})
@DisplayName("Argus properties-assembly HTTP integration")
final class ArgusPropertiesAssemblyIntegrationTest
{
	@Autowired
	private MockMvc mockMvc;

	private static String token(final String subject)
	{
		return TestAuthenticators.token(subject);
	}

	// ── public endpoint ──

	@SpringBootApplication
	@EnableArgusMethodSecurity
	static class TestApplication
	{
		@Bean
		ArgusUserResolver<String> userResolver()
		{
			return externalId -> switch (externalId)
			{
				case "admin-user" -> Optional.of("admin");
				case "regular-user" -> Optional.of("regular");
				case "missing-user" -> Optional.empty();
				default -> Optional.of(externalId);
			};
		}

		@Bean
		ArgusVersionResolver versionResolver()
		{
			return _ -> 1L;
		}

		@Bean
		Clock clock()
		{
			return TestAuthenticators.CLOCK;
		}

		@Bean
		UserTokenVersionResolver<String> userTokenVersionResolver()
		{
			return _ -> 1L;
		}

		@Bean
		de.gupta.security.argus.api.identity.RoleResolver<String> roleResolver()
		{
			return user -> switch (user)
			{
				case "admin" -> Set.of("ROLE_ADMIN", "ROLE_USER");
				default -> Set.of("ROLE_USER");
			};
		}

		@Bean
		ArgusSecurityCustomizer argusSecurityCustomizer()
		{
			return http -> http.authorizeHttpRequests(
					auth -> auth.requestMatchers("/public/**").permitAll()
			);
		}

		@RestController
		static class TestController
		{
			@GetMapping("/public/ping")
			String ping()
			{
				return "pong";
			}

			@GetMapping("/secured/hello")
			@RequireAuthenticated
			String hello()
			{
				return "hello";
			}

			@GetMapping("/admin/dashboard")
			@RequireRole("ADMIN")
			String dashboard()
			{
				return "dashboard";
			}
		}
	}

	// ── secured endpoint ──

	@Nested
	@DisplayName("public endpoint")
	final class PublicEndpoint
	{
		@Test
		void shouldPermitPublicEndpointWithoutToken() throws Exception
		{
			mockMvc.perform(get("/public/ping").accept(MediaType.TEXT_PLAIN))
			       .andExpect(status().isOk())
			       .andExpect(content().string("pong"));
		}
	}

	// ── role-protected endpoint ──

	@Nested
	@DisplayName("secured endpoint")
	final class SecuredEndpoint
	{
		@Test
		void shouldAuthenticateRequestWithValidToken() throws Exception
		{
			mockMvc.perform(get("/secured/hello")
						   .accept(MediaType.TEXT_PLAIN)
					       .header("Authorization", "Bearer " + token("regular-user")))
			       .andExpect(status().isOk())
			       .andExpect(content().string("hello"));
		}

		@Test
		void shouldRejectRequestWithNoToken() throws Exception
		{
			mockMvc.perform(get("/secured/hello").accept(MediaType.TEXT_PLAIN))
			       .andExpect(status().isUnauthorized());
		}

		@Test
		void shouldRejectRequestWithInvalidSignature() throws Exception
		{
			mockMvc.perform(get("/secured/hello")
						   .accept(MediaType.TEXT_PLAIN)
					       .header("Authorization",
								   "Bearer " + TestAuthenticators.invalidSignatureToken("regular-user")))
			       .andExpect(status().isUnauthorized());
		}

		@Test
		void shouldRejectRequestWhenUserCannotBeResolved() throws Exception
		{
			mockMvc.perform(get("/secured/hello")
						   .accept(MediaType.TEXT_PLAIN)
					       .header("Authorization", "Bearer " + token("missing-user")))
			       .andExpect(status().isUnauthorized());
		}
	}

	@Nested
	@DisplayName("role-protected endpoint")
	final class RoleProtectedEndpoint
	{
		@Test
		void shouldPermitAdminUserOnAdminEndpoint() throws Exception
		{
			mockMvc.perform(get("/admin/dashboard")
						   .accept(MediaType.TEXT_PLAIN)
					       .header("Authorization", "Bearer " + token("admin-user")))
			       .andExpect(status().isOk())
			       .andExpect(content().string("dashboard"));
		}

		@Test
		void shouldRejectRegularUserOnAdminEndpoint() throws Exception
		{
			mockMvc.perform(get("/admin/dashboard")
						   .accept(MediaType.TEXT_PLAIN)
					       .header("Authorization", "Bearer " + token("regular-user")))
			       .andExpect(status().isForbidden());
		}

		@Test
		void shouldRejectUnauthenticatedRequestOnAdminEndpoint() throws Exception
		{
			mockMvc.perform(get("/admin/dashboard").accept(MediaType.TEXT_PLAIN))
			       .andExpect(status().isUnauthorized());
		}
	}
}