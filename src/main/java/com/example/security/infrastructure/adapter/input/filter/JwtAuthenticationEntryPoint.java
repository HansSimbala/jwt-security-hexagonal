package com.example.security.infrastructure.adapter.input.filter;

import com.example.security.infrastructure.metrics.MetricsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.Instant;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final MetricsService metricsService;

    public JwtAuthenticationEntryPoint(MetricsService metricsService) {
        this.metricsService = metricsService;
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        metricsService.incrementUnauthorizedAccess();
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write(
                "{\"timestamp\":\"" + Instant.now() + "\"," +
                        "\"status\":401," +
                        "\"error\":\"Unauthorized\"," +
                        "\"message\":\"Token JWT inválido, expirado o ausente\"," +
                        "\"path\":\"" + request.getRequestURI() + "\"}");
    }
}
