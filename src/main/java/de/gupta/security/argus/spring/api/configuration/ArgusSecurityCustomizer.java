package de.gupta.security.argus.spring.api.configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Customises the default Argus {@link org.springframework.security.web.SecurityFilterChain}
 * before the catch-all {@code anyRequest().authenticated()} rule is appended.
 *
 * <p>Provide a bean of this type to permit specific paths or add other
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity} configuration
 * without replacing the entire filter chain:
 *
 * <pre>{@code
 * @Bean
 * ArgusSecurityCustomizer argusSecurityCustomizer() {
 *     return http -> http.authorizeHttpRequests(
 *             auth -> auth.requestMatchers("/public/**").permitAll()
 *     );
 * }
 * }</pre>
 *
 * <p><strong>Ordering note:</strong> the customiser runs <em>before</em> Argus appends
 * {@code anyRequest().authenticated()}. Any permit-list matchers registered here therefore
 * take effect before the catch-all, which is the correct order.
 */
@FunctionalInterface
public interface ArgusSecurityCustomizer
{
    void customize(HttpSecurity http) throws Exception;

    static ArgusSecurityCustomizer noOp()
    {
        return _ -> {};
    }
}