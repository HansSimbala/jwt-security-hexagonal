package com.example.security.infrastructure.config;

import com.example.security.infrastructure.adapter.input.filter.JwtAuthenticationEntryPoint;
import com.example.security.infrastructure.adapter.input.filter.JwtAuthenticationFilter;
import com.example.security.infrastructure.metrics.MetricsService;
import com.example.security.domain.port.output.TokenGeneratorPort;
import com.example.security.domain.port.output.TokenRepositoryPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final TokenGeneratorPort tokenGenerator;
    private final TokenRepositoryPort tokenRepository;
    private final MetricsService metricsService;

    public SecurityConfig(
            TokenGeneratorPort tokenGenerator,
            TokenRepositoryPort tokenRepository,
            MetricsService metricsService) {
        this.tokenGenerator = tokenGenerator;
        this.tokenRepository = tokenRepository;
        this.metricsService = metricsService;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(tokenGenerator, tokenRepository, metricsService);
    }

    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint(metricsService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/v1/auth/**", "/h2-console/**", "/error", "/actuator/**").permitAll()
                .anyRequest().authenticated())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(e -> e.authenticationEntryPoint(jwtAuthenticationEntryPoint()))
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            .headers(h -> h.frameOptions(f -> f.sameOrigin()));
        return http.build();
    }
}
