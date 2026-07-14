package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.domain.exception.RateLimitExceededException;
import com.example.security.domain.port.output.RateLimitPort;
import com.example.security.infrastructure.config.RateLimitProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class RateLimitInterceptor implements HandlerInterceptor {
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String REGISTER_PATH = "/api/v1/auth/register";

    private final RateLimitPort rateLimitPort;
    private final RateLimitProperties properties;

    public RateLimitInterceptor(RateLimitPort rateLimitPort, RateLimitProperties properties) {
        this.rateLimitPort = rateLimitPort;
        this.properties = properties;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!properties.isEnabled()) {
            return true;
        }

        String endpoint = request.getRequestURI();
        RateLimitProperties.EndpointLimit endpointLimit = resolveEndpointLimit(endpoint);
        if (endpointLimit == null) {
            return true;
        }

        String ip = extractClientIp(request);
        String key = endpoint + ":" + ip;
        int maxRequests = endpointLimit.getMaxRequests();
        int windowMinutes = endpointLimit.getWindowMinutes();

        boolean allowed = rateLimitPort.isAllowed(key, maxRequests, windowMinutes);
        int remaining = rateLimitPort.getRemainingRequests(key);
        long reset = rateLimitPort.getResetTime(key);

        addRateLimitHeaders(response, maxRequests, remaining, reset);

        if (!allowed) {
            throw new RateLimitExceededException(
                    "Rate limit exceeded. Try again later.",
                    maxRequests,
                    remaining,
                    reset);
        }

        return true;
    }

    private RateLimitProperties.EndpointLimit resolveEndpointLimit(String endpoint) {
        if (LOGIN_PATH.equals(endpoint)) {
            return properties.getLogin();
        }
        if (REGISTER_PATH.equals(endpoint)) {
            return properties.getRegister();
        }
        return null;
    }

    private void addRateLimitHeaders(HttpServletResponse response, int limit, int remaining, long resetEpochSeconds) {
        // Standard response metadata for clients to implement backoff/retry behavior.
        response.setHeader("X-RateLimit-Limit", String.valueOf(limit));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(Math.max(remaining, 0)));
        response.setHeader("X-RateLimit-Reset", String.valueOf(resetEpochSeconds));
    }

    private String extractClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }

        return request.getRemoteAddr();
    }
}
