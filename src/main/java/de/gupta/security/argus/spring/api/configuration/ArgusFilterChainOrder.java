package de.gupta.security.argus.spring.api.configuration;

public final class ArgusFilterChainOrder
{
    /**
     * Order of the default Argus security filter chain ({@value}).
     * <p>
     * Sits just below Spring Boot's actuator chains ({@code DEFAULT_FILTER_ORDER = -100})
     * and above the basic-auth fallback chain. Consumer-defined {@link
     * org.springframework.security.web.SecurityFilterChain} beans with a lower order value
     * will take precedence over this default.
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
