package com.example.security.domain.port.input;

import com.example.security.application.dto.RegisterCommand;
import com.example.security.application.dto.TokenResult;

public interface RegisterUserPort {
    TokenResult register(RegisterCommand command);
}
