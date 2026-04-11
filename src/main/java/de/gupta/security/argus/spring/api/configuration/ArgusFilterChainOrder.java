package de.gupta.security.argus.spring.api.configuration;

public final class ArgusFilterChainOrder
{
    /**
     * Order of the default Argus security filter chain ({@value}).
     * <p>
     * Ordered at {@code -99}: lower priority than Spring Boot's actuator chains
     * (ordered at {@code -100}), and higher priority than the default basic-auth
     * fallback chain (ordered at {@code Integer.MIN_VALUE}).
     * <p>
     * A consumer-defined {@link org.springframework.security.web.SecurityFilterChain}
     * with a lower order value (e.g. {@code DEFAULT - 1 = -100}) takes precedence
     * over this default.
     * <p>
     * Use this constant when declaring your own chain so that ordering relative to the
     * Argus default is explicit:
     * <pre>{@code
     * @Bean
     * @Order(ArgusFilterChainOrder.DEFAULT - 1)
     * SecurityFilterChain myChain(HttpSecurity http) throws Exception { ... }
     * }</pre>
     */
    public static final int DEFAULT = -99;

    private ArgusFilterChainOrder()
    {
    }
}
