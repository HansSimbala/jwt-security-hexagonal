package com.example.security.infrastructure.adapter.output.persistence;

import com.example.security.infrastructure.adapter.output.persistence.entity.TokenJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import java.util.List;
import java.util.Optional;

public interface TokenJpaRepository extends JpaRepository<TokenJpaEntity, Long> {
    @Query("SELECT t FROM TokenJpaEntity t WHERE t.userId = :userId AND t.isExpired = false AND t.isRevoked = false")
    List<TokenJpaEntity> findAllValidTokensByUserId(Long userId);

    Optional<TokenJpaEntity> findByToken(String token);

    @Modifying
    @Query("UPDATE TokenJpaEntity t SET t.isRevoked = true WHERE t.userId = :userId")
    void revokeAllByUserId(Long userId);
}
