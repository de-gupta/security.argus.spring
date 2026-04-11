open module de.gupta.security.argus.spring
{
	exports de.gupta.security.argus.spring.api.authentication;
	exports de.gupta.security.argus.spring.api.configuration;
	exports de.gupta.security.argus.spring.api.context;
	exports de.gupta.security.argus.spring.api.method;

	requires de.gupta.aletheia;

	requires transitive de.gupta.security.argus;
	requires transitive jakarta.servlet;
	requires transitive spring.beans;
	requires transitive spring.boot;
	requires transitive spring.boot.autoconfigure;
	requires transitive spring.context;
	requires spring.core;
	requires transitive spring.security.config;
	requires transitive spring.security.core;
	requires transitive spring.security.web;
	requires transitive spring.web;

}