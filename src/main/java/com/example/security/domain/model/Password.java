package com.example.security.domain.model;

import java.util.Objects;

public final class Password {
    private static final int MIN_LENGTH = 8;
    private final String value;
    private final boolean isHashed;

    private Password(String value, boolean isHashed) {
        this.value = value;
        this.isHashed = isHashed;
    }

    public static Password ofPlainText(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        if (value.length() < MIN_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_LENGTH + " characters");
        }
        return new Password(value, false);
    }

    public static Password ofHashed(String hashedValue) {
        if (hashedValue == null || hashedValue.isBlank()) {
            throw new IllegalArgumentException("Hashed password cannot be null or empty");
        }
        return new Password(hashedValue, true);
    }

    public String getValue() { return value; }
    public boolean isHashed() { return isHashed; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Password password = (Password) o;
        return isHashed == password.isHashed && Objects.equals(value, password.value);
    }

    @Override
    public int hashCode() { return Objects.hash(value, isHashed); }

    @Override
    public String toString() { return "Password{hashed=" + isHashed + "}"; }
}
