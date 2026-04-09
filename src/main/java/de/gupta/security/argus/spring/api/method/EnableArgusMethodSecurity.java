package de.gupta.security.argus.spring.api.method;

import de.gupta.security.argus.spring.api.configuration.ArgusSpringConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@EnableMethodSecurity
@Import(ArgusSpringConfiguration.class)
public @interface EnableArgusMethodSecurity
{
}
