package com.github.everolfe.authservice.dao;

import com.github.everolfe.authservice.entity.UserCredential;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserCredentialRepository extends JpaRepository<UserCredential, Long> {

    Optional<UserCredential> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<UserCredential> findBySub(UUID sub);

}
