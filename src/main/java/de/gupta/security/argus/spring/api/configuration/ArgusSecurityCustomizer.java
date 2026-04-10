package de.gupta.security.argus.spring.api.configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@FunctionalInterface
public interface ArgusSecurityCustomizer
{
    void customize(HttpSecurity http) throws Exception;

    static ArgusSecurityCustomizer noOp()
    {
        return _ -> {};
    }
}