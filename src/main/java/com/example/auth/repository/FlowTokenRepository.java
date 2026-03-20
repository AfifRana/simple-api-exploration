package com.example.auth.repository;

import com.example.auth.domain.FlowToken;
import com.example.auth.domain.FlowTokenType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface FlowTokenRepository extends JpaRepository<FlowToken, Long> {
    Optional<FlowToken> findByTokenHashAndType(String tokenHash, FlowTokenType type);
}
