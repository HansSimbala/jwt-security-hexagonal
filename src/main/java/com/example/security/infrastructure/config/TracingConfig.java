package com.example.security.infrastructure.config;

import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import io.micrometer.tracing.Tracer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
@ConditionalOnProperty(value = "tracing.enabled", havingValue = "true", matchIfMissing = true)
public class TracingConfig {
    private static final Logger log = LoggerFactory.getLogger(TracingConfig.class);

    private final Environment environment;

    public TracingConfig(Environment environment) {
        this.environment = environment;
    }

    @Bean
    public ObservedAspect observedAspect(ObservationRegistry observationRegistry) {
        log.info("Configurando ObservedAspect para instrumentacion automatica");
        return new ObservedAspect(observationRegistry);
    }

    @Bean
    @ConditionalOnBean(Tracer.class)
    public TracingCustomizer tracingCustomizer(Tracer tracer) {
        String serviceName = environment.getProperty("otel.service.name", "jwt-security-hexagonal");
        String otlpEndpoint = environment.getProperty("otel.exporter.otlp.endpoint", "http://localhost:4318");

        log.info("Tracing habilitado para servicio: {}", serviceName);
        log.info("Exportando traces a: {}", otlpEndpoint);
        return new TracingCustomizer(tracer);
    }
}
