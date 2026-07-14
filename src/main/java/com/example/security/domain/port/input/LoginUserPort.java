package com.example.security.domain.port.input;

import com.example.security.application.dto.LoginCommand;
import com.example.security.application.dto.TokenResult;

public interface LoginUserPort {
    TokenResult login(LoginCommand command);
}
