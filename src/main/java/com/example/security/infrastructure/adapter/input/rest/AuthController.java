package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.application.dto.LoginCommand;
import com.example.security.application.dto.RegisterCommand;
import com.example.security.application.dto.TokenResult;
import com.example.security.domain.exception.InvalidTokenException;
import com.example.security.domain.port.input.LoginUserPort;
import com.example.security.domain.port.input.LogoutUserPort;
import com.example.security.domain.port.input.RefreshTokenPort;
import com.example.security.domain.port.input.RegisterUserPort;
import com.example.security.domain.port.output.TokenGeneratorPort;
import com.example.security.infrastructure.metrics.MetricsService;
import com.example.security.infrastructure.adapter.input.rest.dto.LoginRequestDto;
import com.example.security.infrastructure.adapter.input.rest.dto.LogoutResponseDto;
import com.example.security.infrastructure.adapter.input.rest.dto.RegisterRequestDto;
import com.example.security.infrastructure.adapter.input.rest.dto.TokenResponseDto;
import com.example.security.infrastructure.adapter.input.rest.mapper.AuthMapper;
import io.micrometer.core.instrument.Timer;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.Instant;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final RegisterUserPort registerUserPort;
    private final LoginUserPort loginUserPort;
    private final RefreshTokenPort refreshTokenPort;
    private final LogoutUserPort logoutUserPort;
    private final TokenGeneratorPort tokenGenerator;
    private final MetricsService metricsService;

    public AuthController(
            RegisterUserPort registerUserPort,
            LoginUserPort loginUserPort,
            RefreshTokenPort refreshTokenPort,
            LogoutUserPort logoutUserPort,
            TokenGeneratorPort tokenGenerator,
            MetricsService metricsService) {
        this.registerUserPort = registerUserPort;
        this.loginUserPort = loginUserPort;
        this.refreshTokenPort = refreshTokenPort;
        this.logoutUserPort = logoutUserPort;
        this.tokenGenerator = tokenGenerator;
        this.metricsService = metricsService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(@Valid @RequestBody LoginRequestDto request) {
        Timer.Sample sample = metricsService.startTimer();
        try {
            LoginCommand command = AuthMapper.toCommand(request);
            TokenResult result = loginUserPort.login(command);
            metricsService.incrementLoginSuccess();
            TokenResponseDto response = AuthMapper.toResponseDto(result);
            return metricsService.recordLoginDuration(sample, ResponseEntity.ok(response));
        } catch (RuntimeException ex) {
            metricsService.incrementLoginFailure();
            throw ex;
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponseDto> refresh(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()
                || !authorizationHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Authorization header is required and must start with Bearer");
        }

        String refreshToken = authorizationHeader.substring("Bearer ".length()).trim();
        if (refreshToken.isEmpty()) {
            throw new IllegalArgumentException("Refresh token is required");
        }

        TokenResult result = refreshTokenPort.refresh(refreshToken);
        metricsService.incrementRefreshTokenUsed();
        TokenResponseDto response = AuthMapper.toResponseDto(result);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutResponseDto> logout(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()
                || !authorizationHeader.startsWith("Bearer ")) {
            throw new InvalidTokenException("Token inválido o ausente");
        }

        String accessToken = authorizationHeader.substring("Bearer ".length()).trim();
        if (accessToken.isEmpty() || !tokenGenerator.isTokenValid(accessToken)) {
            throw new InvalidTokenException("Token inválido o ausente");
        }

        logoutUserPort.logout(accessToken);
        metricsService.incrementJwtRevoked();
        return ResponseEntity.ok(new LogoutResponseDto("Logout successful", Instant.now().toString()));
    }

    @PostMapping("/register")
    public ResponseEntity<TokenResponseDto> register(@Valid @RequestBody RegisterRequestDto request) {
        Timer.Sample sample = metricsService.startTimer();
        try {
            RegisterCommand command = AuthMapper.toCommand(request);
            TokenResult result = registerUserPort.register(command);
            metricsService.incrementRegistrationSuccess();
            TokenResponseDto response = AuthMapper.toResponseDto(result);
            return metricsService.recordRegistrationDuration(sample, ResponseEntity.status(HttpStatus.CREATED).body(response));
        } catch (RuntimeException ex) {
            metricsService.incrementRegistrationFailure();
            throw ex;
        }
    }
}
