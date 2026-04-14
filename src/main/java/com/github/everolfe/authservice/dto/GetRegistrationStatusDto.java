package com.github.everolfe.authservice.dto;

import com.github.everolfe.authservice.entity.OutboxStatus;
import java.util.UUID;

public record GetRegistrationStatusDto(
        UUID registrationId,
        OutboxStatus status
) {
}
