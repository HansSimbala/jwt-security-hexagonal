package com.example.security.domain.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class User {
    private final Long id;
    private final String name;
    private final Email email;
    private final Password password;
    private final Role role;

    private User(Builder builder) {
        this.id = builder.id;
        this.name = builder.name;
        this.email = builder.email;
        this.password = builder.password;
        this.role = builder.role;
    }

    public Long getId() { return id; }
    public String getName() { return name; }
    public Email getEmail() { return email; }
    public Password getPassword() { return password; }
    public Role getRole() { return role; }

    public List<String> getScopes() {
        if (role == null) return List.of();
        List<String> scopes = new ArrayList<>();
        role.getPermissions().forEach(p -> scopes.add(p.getScope()));
        return scopes;
    }

    public User withId(Long id) {
        return User.builder().id(id).name(this.name).email(this.email)
            .password(this.password).role(this.role).build();
    }

    public User withHashedPassword(Password hashedPassword) {
        return User.builder().id(this.id).name(this.name).email(this.email)
            .password(hashedPassword).role(this.role).build();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(id, user.id) && Objects.equals(email, user.email);
    }

    @Override
    public int hashCode() { return Objects.hash(id, email); }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private Long id;
        private String name;
        private Email email;
        private Password password;
        private Role role;

        public Builder id(Long id) { this.id = id; return this; }
        public Builder name(String name) { this.name = name; return this; }
        public Builder email(Email email) { this.email = email; return this; }
        public Builder password(Password password) { this.password = password; return this; }
        public Builder role(Role role) { this.role = role; return this; }

        public User build() {
            Objects.requireNonNull(name, "Name is required");
            Objects.requireNonNull(email, "Email is required");
            Objects.requireNonNull(password, "Password is required");
            Objects.requireNonNull(role, "Role is required");
            return new User(this);
        }
    }
}
