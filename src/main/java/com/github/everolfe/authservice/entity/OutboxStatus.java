package com.github.everolfe.authservice.entity;

public enum OutboxStatus {
    PENDING,
    CREATED,
    FAILED,
    ROLLBACK
}
