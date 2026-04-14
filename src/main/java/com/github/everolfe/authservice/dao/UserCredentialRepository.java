package com.github.everolfe.authservice.dao;

import com.github.everolfe.authservice.entity.UserCredential;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserCredentialRepository extends JpaRepository<UserCredential, Long> {

    Optional<UserCredential> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<UserCredential> findBySub(UUID sub);

    @Modifying
    @Query("DELETE FROM UserCredential u WHERE u.sub = :sub")
    void deleteBySub(@Param("sub") UUID sub);

}
