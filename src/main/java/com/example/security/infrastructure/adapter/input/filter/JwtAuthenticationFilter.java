package com.example.security.infrastructure.adapter.input.filter;

import com.example.security.domain.port.output.TokenGeneratorPort;
import com.example.security.domain.port.output.TokenRepositoryPort;
import com.example.security.infrastructure.metrics.MetricsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenGeneratorPort tokenGenerator;
    private final TokenRepositoryPort tokenRepository;
    private final MetricsService metricsService;

    public JwtAuthenticationFilter(
            TokenGeneratorPort tokenGenerator,
            TokenRepositoryPort tokenRepository,
            MetricsService metricsService) {
        this.tokenGenerator = tokenGenerator;
        this.tokenRepository = tokenRepository;
        this.metricsService = metricsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        // If Authorization header is present but invalid format
        if (authHeader != null && !authHeader.startsWith("Bearer ")) {
            sendUnauthorizedError(response, "Authorization header must have 'Bearer <token>' format");
            return;
        }

        // If no Authorization header, continue (public endpoints will pass)
        if (authHeader == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = authHeader.substring(7);

            // Validate token
            if (!tokenGenerator.isTokenValid(token)) {
                sendUnauthorizedError(response, "Token is invalid or expired");
                return;
            }

            // Extract userId
            Long userId = tokenGenerator.extractUserId(token);

            // Verify token exists in database and is not revoked
            var tokenEntity = tokenRepository.findByValue(token);
            if (tokenEntity.isEmpty() || tokenEntity.get().isRevoked() || tokenEntity.get().isExpired()) {
                sendUnauthorizedError(response, "Token is revoked or expired");
                return;
            }

            // Extract roles from JWT and convert to authorities
            List<String> roles = extractRoles(token);
            List<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            // Extract scopes from JWT and add them as authorities with SCOPE_ prefix
            List<String> scopes = extractScopes(token);
            scopes.stream()
                    .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                    .forEach(authorities::add);

            // Create authentication token
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);
            authToken.setDetails("user-" + userId);

            SecurityContextHolder.getContext().setAuthentication(authToken);
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            sendUnauthorizedError(response, "Token validation failed: " + e.getMessage());
        }
    }

    private void sendUnauthorizedError(HttpServletResponse response, String message) throws IOException {
        metricsService.incrementUnauthorizedAccess();
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"" + message + "\"}");
    }

    private List<String> extractRoles(String token) {
        List<String> roles = tokenGenerator.extractRoles(token);
        return roles != null ? roles : Collections.emptyList();
    }

    private List<String> extractScopes(String token) {
        List<String> scopes = tokenGenerator.extractScopes(token);
        return scopes != null ? scopes : Collections.emptyList();
    }
}
