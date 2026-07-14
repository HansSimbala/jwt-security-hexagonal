package com.example.security.infrastructure.adapter.input.rest.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record TokenResponseDto(
    @JsonProperty("access_token") String accessToken,
    @JsonProperty("refresh_token") String refreshToken,
    @JsonProperty("token_type") String tokenType,
    @JsonProperty("expires_in") long expiresIn
) {}
