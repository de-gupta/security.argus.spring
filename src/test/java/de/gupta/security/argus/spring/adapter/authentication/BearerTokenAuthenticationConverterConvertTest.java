package de.gupta.security.argus.spring.adapter.authentication;

import de.gupta.security.argus.spring.api.authentication.ArgusAuthenticationToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;

import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@DisplayName("BearerTokenAuthenticationConverter.convert")
@TestInstance(PER_CLASS)
final class BearerTokenAuthenticationConverterConvertTest
{
    private record ConversionCase(String description, String authorizationHeader, Optional<String> expectedRawToken)
    {
        @Override
        public String toString()
        {
            return description;
        }
    }

    @Nested
    @DisplayName("as token conversion")
    @TestInstance(PER_CLASS)
    final class TokenConversion
    {
        @ParameterizedTest(name = "{0}")
        @MethodSource("cases")
        void shouldConvertOnlyValidBearerHeaders(final ConversionCase input)
        {
            final var converter = new BearerTokenAuthenticationConverter();
            final var request = new MockHttpServletRequest();
            if (input.authorizationHeader() != null)
            {
                request.addHeader("Authorization", input.authorizationHeader());
            }

            final Authentication authentication = converter.convert(request);

            if (input.expectedRawToken().isEmpty())
            {
                assertThat(authentication)
                        .as(input.description())
                        .isNull();
                return;
            }

            assertThat(authentication)
                    .as(input.description())
                    .isInstanceOf(ArgusAuthenticationToken.class);
            assertThat(authentication.getCredentials())
                    .as(input.description())
                    .isEqualTo(input.expectedRawToken().orElseThrow());
            assertThat(authentication.isAuthenticated())
                    .as(input.description())
                    .isFalse();
        }

        private Stream<Arguments> cases()
        {
            return Stream.of(
                            new ConversionCase("when no authorization header is present", null, Optional.empty()),
                            new ConversionCase("when the authorization header does not use the bearer scheme", "Basic abc123", Optional.empty()),
                            new ConversionCase("when the bearer token is blank after trimming", "Bearer    ", Optional.empty()),
                            new ConversionCase("when the bearer scheme casing varies", "bEaReR token-value", Optional.of("token-value")),
                            new ConversionCase("when the bearer token has leading and trailing spaces", "Bearer   token-value   ", Optional.of("token-value")))
                    .map(Arguments::of);
        }
    }
}
