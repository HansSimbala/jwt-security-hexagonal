package com.example.security.domain.port.output;

public interface LoginAttemptPort {
    void loginFailed(String email);
    void loginSucceeded(String email);
    boolean isBlocked(String email);
    int getAttempts(String email);
    void resetAttempts(String email);
}
