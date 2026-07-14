package com.example.security.domain.port.input;

public interface LogoutUserPort {
    void logout(String token);
    void logoutAll(Long userId);
}
