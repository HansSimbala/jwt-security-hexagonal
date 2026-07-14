package com.example.security.domain.port.input;

import com.example.security.application.dto.TokenResult;

public interface RefreshTokenPort {
    TokenResult refresh(String refreshToken);
}
