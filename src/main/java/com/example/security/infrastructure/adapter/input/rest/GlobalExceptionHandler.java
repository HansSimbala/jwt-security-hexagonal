package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.domain.exception.AccountLockedException;
import com.example.security.domain.exception.InvalidRoleException;
import com.example.security.domain.exception.InvalidCredentialsException;
import com.example.security.domain.exception.InvalidTokenException;
import com.example.security.domain.exception.RateLimitExceededException;
import com.example.security.domain.exception.UserAlreadyExistsException;
import com.example.security.infrastructure.metrics.MetricsService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private final MetricsService metricsService;

    public GlobalExceptionHandler(MetricsService metricsService) {
        this.metricsService = metricsService;
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<Map<String, String>> handleUserAlreadyExists(UserAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(InvalidRoleException.class)
    public ResponseEntity<Map<String, String>> handleInvalidRole(InvalidRoleException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleInvalidCredentials(InvalidCredentialsException ex) {
        metricsService.incrementUnauthorizedAccess();
        metricsService.incrementInvalidCredentials();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<Map<String, String>> handleInvalidToken(InvalidTokenException ex) {
        metricsService.incrementUnauthorizedAccess();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            AccountLockedException ex,
            HttpServletRequest request) {
        metricsService.incrementAccountLockout();
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", java.time.Instant.now().toString());
        response.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
        response.put("error", "Too Many Requests");
        response.put("message", ex.getMessage());
        response.put("path", request.getRequestURI());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleRateLimitExceeded(
            RateLimitExceededException ex,
            HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", java.time.Instant.now().toString());
        response.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
        response.put("error", "Too Many Requests");
        response.put("message", ex.getMessage());
        response.put("path", request.getRequestURI());

        HttpHeaders headers = new HttpHeaders();
        headers.add("X-RateLimit-Limit", String.valueOf(ex.getLimit()));
        headers.add("X-RateLimit-Remaining", String.valueOf(ex.getRemaining()));
        headers.add("X-RateLimit-Reset", String.valueOf(ex.getResetEpochSeconds()));

        return new ResponseEntity<>(response, headers, HttpStatus.TOO_MANY_REQUESTS);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors()
            .forEach(e -> errors.put(e.getField(), e.getDefaultMessage()));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errors);
    }
}
