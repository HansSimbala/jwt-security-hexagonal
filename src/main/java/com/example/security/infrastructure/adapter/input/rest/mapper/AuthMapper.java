package com.example.security.infrastructure.adapter.input.rest.mapper;

import com.example.security.application.dto.LoginCommand;
import com.example.security.application.dto.RegisterCommand;
import com.example.security.application.dto.TokenResult;
import com.example.security.infrastructure.adapter.input.rest.dto.LoginRequestDto;
import com.example.security.infrastructure.adapter.input.rest.dto.RegisterRequestDto;
import com.example.security.infrastructure.adapter.input.rest.dto.TokenResponseDto;

public class AuthMapper {
    public static LoginCommand toCommand(LoginRequestDto dto) {
        return new LoginCommand(dto.email(), dto.password());
    }

    public static RegisterCommand toCommand(RegisterRequestDto dto) {
        return new RegisterCommand(dto.name(), dto.email(), dto.password(), dto.role());
    }

    public static TokenResponseDto toResponseDto(TokenResult result) {
        return new TokenResponseDto(result.accessToken(), result.refreshToken(),
            result.tokenType(), result.expiresInSeconds());
    }
}
