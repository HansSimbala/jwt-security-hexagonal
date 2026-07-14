package com.example.security.infrastructure.adapter.output.persistence.mapper;

import com.example.security.domain.model.*;
import com.example.security.infrastructure.adapter.output.persistence.entity.UserJpaEntity;

public class UserPersistenceMapper {
    public static UserJpaEntity toJpaEntity(User user) {
        UserJpaEntity entity = new UserJpaEntity();
        entity.setId(user.getId());
        entity.setName(user.getName());
        entity.setEmail(user.getEmail().getValue());
        entity.setPassword(user.getPassword().getValue());
        entity.setRole(user.getRole().name());
        return entity;
    }

    public static User toDomain(UserJpaEntity entity) {
        return User.builder()
            .id(entity.getId())
            .name(entity.getName())
            .email(Email.of(entity.getEmail()))
            .password(Password.ofHashed(entity.getPassword()))
            .role(Role.fromString(entity.getRole()))
            .build();
    }
}
