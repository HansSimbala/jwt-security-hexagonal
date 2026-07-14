package com.example.security.infrastructure.adapter.output.security;

import com.example.security.domain.model.Password;
import com.example.security.domain.port.output.PasswordEncoderPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class BcryptPasswordAdapter implements PasswordEncoderPort {
    private final PasswordEncoder passwordEncoder;

    public BcryptPasswordAdapter(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Password encode(Password plainPassword) {
        if (plainPassword.isHashed()) {
            throw new IllegalArgumentException("Cannot encode an already hashed password");
        }
        return Password.ofHashed(passwordEncoder.encode(plainPassword.getValue()));
    }

    @Override
    public boolean matches(Password plainPassword, Password hashedPassword) {
        return passwordEncoder.matches(plainPassword.getValue(), hashedPassword.getValue());
    }
}
