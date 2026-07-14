package com.example.security.infrastructure.adapter.output.persistence;

import com.example.security.domain.model.Email;
import com.example.security.domain.model.User;
import com.example.security.domain.port.output.UserRepositoryPort;
import com.example.security.infrastructure.adapter.output.persistence.entity.UserJpaEntity;
import com.example.security.infrastructure.adapter.output.persistence.mapper.UserPersistenceMapper;
import org.springframework.stereotype.Component;
import java.util.Optional;

@Component
public class UserRepositoryAdapter implements UserRepositoryPort {
    private final UserJpaRepository jpaRepository;

    public UserRepositoryAdapter(UserJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public User save(User user) {
        UserJpaEntity entity = UserPersistenceMapper.toJpaEntity(user);
        UserJpaEntity saved = jpaRepository.save(entity);
        return UserPersistenceMapper.toDomain(saved);
    }

    @Override
    public Optional<User> findById(Long id) {
        return jpaRepository.findById(id).map(UserPersistenceMapper::toDomain);
    }

    @Override
    public Optional<User> findByEmail(Email email) {
        return jpaRepository.findByEmail(email.getValue()).map(UserPersistenceMapper::toDomain);
    }

    @Override
    public boolean existsByEmail(Email email) {
        return jpaRepository.existsByEmail(email.getValue());
    }
}
