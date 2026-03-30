package com.github.everolfe.authservice.dao;

import com.github.everolfe.authservice.entity.Outbox;
import com.github.everolfe.authservice.entity.OutboxStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.UUID;

public interface OutboxRepository extends JpaRepository<Outbox, UUID> {

    List<Outbox> findByStatus(OutboxStatus status);

    @Modifying
    @Transactional
    @Query("DELETE FROM Outbox o WHERE o.id = :id")
    void deleteById(@Param("id") UUID id);
}