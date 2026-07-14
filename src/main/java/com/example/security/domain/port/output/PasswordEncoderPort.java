package com.example.security.domain.port.output;

import com.example.security.domain.model.Password;

public interface PasswordEncoderPort {
    Password encode(Password plainPassword);
    boolean matches(Password plainPassword, Password hashedPassword);
}
