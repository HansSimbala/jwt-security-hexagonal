package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.application.dto.LoginCommand;
import com.example.security.application.dto.RegisterCommand;
import com.example.security.application.dto.TokenResult;
import com.example.security.domain.port.input.LoginUserPort;
import com.example.security.domain.port.input.RefreshTokenPort;
import com.example.security.domain.port.input.RegisterUserPort;
import com.example.security.infrastructure.adapter.input.rest.dto.LoginRequestDto;
import com.example.security.infrastructure.adapter.input.rest.dto.RegisterRequestDto;
import com.example.security.infrastructure.adapter.input.rest.dto.TokenResponseDto;
import com.example.security.infrastructure.adapter.input.rest.mapper.AuthMapper;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final RegisterUserPort registerUserPort;
    private final LoginUserPort loginUserPort;
    private final RefreshTokenPort refreshTokenPort;

    public AuthController(
            RegisterUserPort registerUserPort,
            LoginUserPort loginUserPort,
            RefreshTokenPort refreshTokenPort) {
        this.registerUserPort = registerUserPort;
        this.loginUserPort = loginUserPort;
        this.refreshTokenPort = refreshTokenPort;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(@Valid @RequestBody LoginRequestDto request) {
        LoginCommand command = AuthMapper.toCommand(request);
        TokenResult result = loginUserPort.login(command);
        TokenResponseDto response = AuthMapper.toResponseDto(result);
        return ResponseEntity.ok(response);
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
        TokenResponseDto response = AuthMapper.toResponseDto(result);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<TokenResponseDto> register(@Valid @RequestBody RegisterRequestDto request) {
        RegisterCommand command = AuthMapper.toCommand(request);
        TokenResult result = registerUserPort.register(command);
        TokenResponseDto response = AuthMapper.toResponseDto(result);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
