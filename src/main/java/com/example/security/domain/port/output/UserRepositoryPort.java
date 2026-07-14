package com.example.security.domain.port.output;

import com.example.security.domain.model.Email;
import com.example.security.domain.model.User;
import java.util.Optional;

public interface UserRepositoryPort {
    User save(User user);
    Optional<User> findById(Long id);
    Optional<User> findByEmail(Email email);
    boolean existsByEmail(Email email);
}
