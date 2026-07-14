package com.example.security.domain.exception;

public class AccountLockedException extends RuntimeException {
    private final String email;
    private final int remainingMinutes;

    public AccountLockedException(String email, int remainingMinutes) {
        super("Account temporarily locked due to multiple failed login attempts. Try again in "
                + remainingMinutes + " minutes.");
        this.email = email;
        this.remainingMinutes = remainingMinutes;
    }

    public String getEmail() {
        return email;
    }

    public int getRemainingMinutes() {
        return remainingMinutes;
    }
}
