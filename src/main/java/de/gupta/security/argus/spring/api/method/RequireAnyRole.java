package de.gupta.security.argus.spring.api.method;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@argusMethodAccess.hasAnyRole('{value}')")
public @interface RequireAnyRole
{
    String[] value();
}

