package com.zosh.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

@Configuration
public class ThymeleafConfig {
	@Bean

	public ClassLoaderTemplateResolver templateResolver() {

	ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();

	templateResolver.setPrefix("templates/");

	templateResolver.setCacheable(false);

	templateResolver.setSuffix(".html");

	templateResolver.setTemplateMode("HTML5");

	return templateResolver;

	}
}
